# IR Runbook — Container Escape (NW-002, T1611)

**Severity:** CRITICAL · **Page:** on-call platform security + node owner

## Trigger
`nsenter`/`unshare` in a container, or a `setns` kprobe hit from the Tetragon
policy. Almost always preceded by NW-003 (privileged/hostPID pod).

## Triage (first 5 minutes)
1. Identify node and pod from the alert fields (`pod`, `ns`, `image`, node from `kubectl get pod -o wide`).
2. Confirm blast radius: `kubectl get pod <pod> -o jsonpath='{.spec.containers[*].securityContext}'` — privileged? hostPID? hostPath mounts?
3. Capture volatile state before anything restarts the pod:
   - `kubectl logs <pod> --previous` and current
   - process tree if Tetragon is in Post (not Sigkill) mode

## Contain
1. **Cordon the node:** `kubectl cordon <node>` (stop new scheduling).
2. **Isolate the pod** with a deny-all NetworkPolicy in its namespace (see `deploy/k8s/`).
3. **Drain** only after evidence capture: `kubectl drain <node> --ignore-daemonsets --delete-emptydir-data`.
4. Treat the **node as compromised** — a successful escape means host-level code execution.

## Eradicate & recover
1. Delete the workload; block its image digest at admission.
2. Rebuild/replace the node from a known-good image (do not reuse).
3. Rotate any secret that was mounted on that node or reachable by its kubelet.

## Root cause
- Why was a privileged/hostPID pod admitted? Fix the admission policy (Pod Security `restricted`, or an OPA/Kyverno rule) so NW-003 is a hard deny, not just an alert.

## ATT&CK
T1611 Escape to Host · T1548 Abuse Elevation Control · (precursor) T1610 Deploy Container
