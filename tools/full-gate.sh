#!/usr/bin/env bash
# tools/full-gate.sh — the FULL gate: the static checks plus every suite, both tiers.
#
# Who runs it, and when (`~/fleet/docs/speed.md`):
#   * the MERGER, once per landing, on the merged union of every cleared branch (R1, R11, R13);
#   * never an implementer lane while iterating — that is `tools/fast-gate.sh` / `fleet-check --fast` (R2).
#   `bin/fleet-check` enforces this: a non-merger lane asking for the full gate is refused.
# Budget: <= 300 s median on 8 vCPU (R1). Record the first measurement on this project's bead.
#
# It is also the independent oracle the fast gate cannot be: the fast gate proves that every changed file
# HAD a suite (fleet-1n0z mode (a)). It cannot prove that the suites it selected were ALL of them (mode (b)).
# This run is what can.
set -uo pipefail

HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
CONF="$HERE/gate.conf"
# An explicitly exported value wins over the profile's: capture before sourcing tools/gate.conf.
# (Plain assignment in gate.conf + this capture, rather than `${VAR:-default}` there, because a placeholder
# inside a default form is parsed wrong - see the comment in tools/gate.conf.)
_ENV_FAST=${FAST_GATE_RUNNER-}; _ENV_FULL=${FULL_TIER_CMD-}; _ENV_STATIC=${STATIC_CMD-}
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"
[ -n "$_ENV_FAST" ] && FAST_GATE_RUNNER=$_ENV_FAST
[ -n "$_ENV_FULL" ] && FULL_TIER_CMD=$_ENV_FULL
[ -n "$_ENV_STATIC" ] && STATIC_CMD=$_ENV_STATIC
STATIC_CMD=${STATIC_CMD:-true}
FULL_TIER_CMD=${FULL_TIER_CMD:-deno test tests/unit tests/integration}
: "${FULL_TIER_CMD:?tools/gate.conf did not set FULL_TIER_CMD and no override was given}"

rc=0
step() { printf '\n[gate] %s\n' "$1"; }

step "static: $STATIC_CMD"
( cd "$ROOT" && eval "$STATIC_CMD" ) || rc=1

step "tests: $FULL_TIER_CMD"
( cd "$ROOT" && eval "$FULL_TIER_CMD" ) || rc=1

if [ "$rc" -eq 0 ]; then echo "full gate: PASS"; else echo "full gate: FAIL" >&2; fi
exit $rc
