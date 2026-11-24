# Attack emulation

Each script reproduces one scenario from `core/scenarios.ts` against a **disposable
test namespace** so you can watch the NIGHTWATCH rules fire in a live cluster
(kind/minikube + Falco). They are detection-validation harnesses, not exploits:
every payload is a harmless stand-in (`sleep`, a reachable-but-inert pool address,
a throwaway listener).

```bash
./run-all.sh                 # applies the test workloads and triggers each technique
kubectl logs -n falco ds/falco | grep NW-     # watch alerts
```

> Run only against a cluster you own and have authorization to test. Never against production.
