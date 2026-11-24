# IR Runbook — Service-Account Token Theft (NW-004/005/013/015, T1552.007)

**Severity:** WARNING → CRITICAL when correlated · **Page:** on correlation

## Correlation that escalates to CRITICAL
NW-004 (token read by a shell/tool) **within 60s of** NW-005 (egress to
`kubernetes.default`) **or** NW-013/NW-015 (SA listing secrets / exec'ing pods).
Single signals are notice-worthy; the chain is an active credential-theft.

## Triage
1. Which SA? `ka.user.name` / `apiUser` = `system:serviceaccount:<ns>:<sa>`.
2. What can it do? `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>`.
3. What did it touch? Pull the apiserver audit log for that SA in the window.

## Contain
1. **Invalidate the token:** delete the pod (projected tokens are short-lived) and, if a legacy Secret token, delete the Secret and let it regenerate.
2. If the SA is over-permissioned, **remove the binding now:** `kubectl delete rolebinding/clusterrolebinding <b>`.
3. Rotate every secret the SA could read.

## Root cause
- Least-privilege the SA (most workloads need **zero** cluster-wide secret/exec rights).
- Set `automountServiceAccountToken: false` on workloads that never call the API.

## ATT&CK
T1552.007 Container API/SA Token · T1078 Valid Accounts · T1021 Remote Services
