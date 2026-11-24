#!/usr/bin/env bash
# T1496 Resource Hijacking — simulated miner (NW-006/007/008). Uses an inert
# binary named xmrig and a non-routable pool so nothing actually mines.
set -euo pipefail
NS=${NS:-nightwatch-test}
kubectl -n "$NS" run miner-demo --restart=Never --image=busybox --command -- sh -c '
  cp /bin/sleep /tmp/xmrig && /tmp/xmrig 300'   # process named xmrig -> NW-006
echo "[+] expect NW-006 CRITICAL (miner binary name)"
