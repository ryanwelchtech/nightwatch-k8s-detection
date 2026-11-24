#!/usr/bin/env bash
set -euo pipefail
NS=${NS:-nightwatch-test}
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
for s in escape sa-token-theft cryptomining reverse-shell; do
  echo "=== $s ==="; NS="$NS" bash "$(dirname "$0")/$s.sh" || true; sleep 3
done
echo "cleanup: kubectl delete namespace $NS"
