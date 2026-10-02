#!/usr/bin/env bash
# Version-aware passive subdomain enumeration via amass, for recon-ry's
# subdomain_enum stage.
#
# Why this exists:
#   * amass v4 is a one-shot CLI:  amass enum -passive -d <d> ...
#   * amass v5 is a client/engine split. `amass enum` submits work to an engine
#     and `amass subs` reads names back out of the graph DB. With no engine
#     reachable, v5 HANGS INDEFINITELY - it does not even print `-h`.
#   * The previous recon-ry command also passed `-rf <rate>`, but `-rf` is
#     "path to a file providing untrusted DNS resolvers" in every version, and
#     it never redirected stdout to {{OUTPUT}}, so results were discarded.
#
# Usage: amass-enum.sh <roots-file> <output-file> [rate-qps]
set -uo pipefail
ROOTS="${1:?roots file required}"; OUT="${2:?output file required}"; RATE="${3:-5}"
HARD_TIMEOUT="${AMASS_HARD_TIMEOUT:-600}"      # per-root ceiling; never hang forever
ENGINE_WAIT="${AMASS_ENGINE_WAIT:-25}"

command -v amass >/dev/null || { echo "[amass] FATAL: amass not installed" >&2; exit 1; }
RAW_VER="$(amass -version 2>&1 | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
MAJOR="$(printf '%s' "${RAW_VER#v}" | cut -d. -f1)"
: "${MAJOR:=0}"
echo "[amass] version=${RAW_VER:-unknown} major=$MAJOR rate=${RATE}qps" >&2

# Resolver discovery. amass ships its own DNS stack and does NOT use the OS
# resolver, so on hosts where outbound DNS is restricted (e.g. a VPN that
# permits only its own in-tunnel resolver) amass cannot resolve its bootstrap
# hosts and the v5 engine dies at startup. Passing working resolvers via -r
# fixes that. Config is not trusted - every candidate is probed, because this
# host advertises 1.1.1.1/8.8.8.8 via resolvectl while both are firewalled.
discover_resolvers() {
  local cands="" r working=""
  command -v resolvectl >/dev/null 2>&1 &&     cands+=" $(resolvectl status 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | tr '\n' ' ')"
  cands+=" $(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | tr '\n' ' ')"
  for ip in $(ip -o -4 addr show 2>/dev/null | grep -E 'wg|tun' | awk '{print $4}' | cut -d/ -f1); do
    cands+=" ${ip%.*}.1"
  done
  cands+=" 10.64.0.1 1.1.1.1 8.8.8.8"
  for r in $(printf '%s\n' $cands | awk 'NF' | sort -u); do
    if timeout 4 dig +short +time=2 +tries=1 "@$r" A one.one.one.one 2>/dev/null | grep -qE '^[0-9]+\.'; then
      working+="${working:+,}$r"
    fi
  done
  printf '%s' "$working"
}
RESOLVERS="${AMASS_RESOLVERS:-$(discover_resolvers)}"
RFLAG=()
if [ -n "$RESOLVERS" ]; then
  RFLAG=(-r "$RESOLVERS")
  echo "[amass] resolvers (probed): $RESOLVERS" >&2
else
  echo "[amass] WARNING: no working resolver found; amass will use its built-in list" >&2
fi

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
: > "$tmp/all"
roots=0; ok=0

# NOTE: deliberately no standalone-engine pre-start here.
# `amass engine` rejects -r/-rf ("flag provided but not defined"), so a
# standalone engine cannot be given working resolvers and dies at startup on a
# DNS-restricted host. `amass enum -r` spawns its OWN engine and passes the
# resolvers through to it, which is the only path that clears DNS bootstrap.
# Verified: with -r the engine starts 14 plugins and no longer fails on
# BGPTools; it may still exceed enum's fixed ~60s readiness wait, which the
# per-root handler below reports explicitly.

while IFS= read -r root; do
  root="${root%%[[:space:]]*}"; [ -z "$root" ] && continue
  case "$root" in \#*) continue;; esac
  root="${root#\*.}"
  roots=$((roots+1))

  if [ "$MAJOR" -ge 5 ]; then
    timeout "$HARD_TIMEOUT" amass enum -d "$root" "${RFLAG[@]}" -silent -nocolor >/dev/null 2>"$tmp/$root.err"
    rc=$?
    timeout 120 amass subs -d "$root" -names -silent -nocolor 2>/dev/null >"$tmp/$root.out" || true
  else
    timeout "$HARD_TIMEOUT" amass enum -passive -d "$root" "${RFLAG[@]}" -rqps "$RATE" -silent -nocolor \
      >"$tmp/$root.out" 2>"$tmp/$root.err"
    rc=$?
  fi

  # grep -c prints a count AND exits non-zero on no-match; a `|| echo 0`
  # here would append a SECOND zero and break the integer tests below.
  n=$(grep -coE '^[A-Za-z0-9_.-]+\.[A-Za-z]{2,}$' "$tmp/$root.out" 2>/dev/null | head -1)
  n=${n:-0}
  if grep -qi 'engine did not respond' "$tmp/$root.err" 2>/dev/null; then
    echo "[amass] $root: v5 engine never became responsive (enum has a fixed ~60s internal wait)." >&2
  fi
  if [ "$rc" -eq 124 ]; then
    echo "[amass] $root: hit ${HARD_TIMEOUT}s ceiling; keeping $n partial names" >&2
  elif [ "$rc" -ne 0 ]; then
    echo "[amass] $root: exit=$rc ($(tail -1 "$tmp/$root.err" 2>/dev/null | cut -c1-70))" >&2
  else
    echo "[amass] $root: $n names" >&2
  fi
  [ "$n" -gt 0 ] && { cat "$tmp/$root.out" >> "$tmp/all"; ok=$((ok+1)); }
done < "$ROOTS"

grep -hoE '^[A-Za-z0-9_.-]+\.[A-Za-z]{2,}$' "$tmp/all" 2>/dev/null | tr 'A-Z' 'a-z' | sort -u > "$OUT" || : > "$OUT"
echo "[amass] roots=$roots with_results=$ok names=$(wc -l < "$OUT")" >&2
exit 0
