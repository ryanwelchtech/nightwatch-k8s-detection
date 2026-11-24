import type { Rule } from './types.ts';

// NIGHTWATCH detection rules. Each one has a direct Falco/Tetragon analogue in
// rules/ — this is the executable, testable source of truth for the detection
// logic; the YAML is what actually loads into the cluster sensors.

export const RULES: Rule[] = [
  {
    id: 'NW-001', name: 'Terminal shell spawned in container',
    description: 'An interactive shell (bash/sh/zsh) executed inside a running container. Rare in immutable, single-process workloads; a hallmark of interactive compromise.',
    kind: 'process', severity: 'notice', attack: ['T1059'], confidence: 0.5,
    condition: { op: 'and', of: [
      { op: 'in', field: 'proc', values: ['bash', 'sh', 'zsh', 'ash', 'dash'] },
      { op: 'not', of: { op: 'in', field: 'parent', values: ['containerd-shim', 'runc', 'docker-init', 'tini'] } },
    ] },
    response: 'Correlate with who exec\'d in (kubectl exec vs. in-pod spawn). Treat as IOC if the image is a single-binary service.',
    tags: ['container', 'mitre', 'shell'],
  },
  {
    id: 'NW-002', name: 'Container escape via namespace break-out',
    description: 'nsenter / setns or a write to /proc/*/ns from inside a container — a direct attempt to escape to the host namespace.',
    kind: 'process', severity: 'critical', attack: ['T1611'], confidence: 0.95,
    condition: { op: 'or', of: [
      { op: 'in', field: 'proc', values: ['nsenter', 'unshare'] },
      { op: 'and', of: [{ op: 'eq', field: 'proc', value: 'ctr' }, { op: 'contains', field: 'args', value: 'task exec' }] },
    ] },
    response: 'CRITICAL. Isolate the node, cordon+drain, snapshot the pod, preserve /proc. Likely privileged or hostPID pod abuse.',
    tags: ['container', 'mitre', 'escape'],
  },
  {
    id: 'NW-003', name: 'Privileged container launched',
    description: 'A container started with privileged=true or hostPID — the precondition for most escape techniques.',
    kind: 'process', severity: 'warning', attack: ['T1610', 'T1548'], confidence: 0.4,
    condition: { op: 'or', of: [{ op: 'eq', field: 'privileged', value: true }, { op: 'eq', field: 'hostPid', value: true }] },
    response: 'Verify against the admission policy. Privileged pods should be a short allow-list; alert if the workload is not on it.',
    tags: ['container', 'mitre', 'posture'],
  },
  {
    id: 'NW-004', name: 'Service-account token read by shell or transfer tool',
    description: 'A shell, interpreter or download tool (not the application binary) read the mounted service-account token. The app SDK reading its own token is benign; a shell reading it is step one of in-cluster lateral movement. Tuned on the reading process to keep legitimate SDK use quiet.',
    kind: 'file', severity: 'warning', attack: ['T1552.007', 'T1552'], confidence: 0.6,
    condition: { op: 'and', of: [
      { op: 'contains', field: 'path', value: '/var/run/secrets/kubernetes.io/serviceaccount' },
      { op: 'in', field: 'proc', values: ['sh', 'bash', 'zsh', 'ash', 'dash', 'curl', 'wget', 'python', 'python3', 'perl', 'ruby', 'nc', 'ncat', 'socat', 'cat', 'xxd'] },
    ] },
    response: 'Expected for app SDKs (quiet by design); suspicious for shells, curl, python one-liners. Correlate with NW-005 egress to the API server.',
    tags: ['container', 'mitre', 'credentials'],
  },
  {
    id: 'NW-005', name: 'Outbound connection to Kubernetes API server',
    description: 'A workload process connected to the apiserver directly (not via the SDK sidecar), often right after reading the SA token.',
    kind: 'network', severity: 'warning', attack: ['T1552.007', 'T1071'], confidence: 0.5,
    condition: { op: 'and', of: [
      { op: 'eq', field: 'direction', value: 'outbound' },
      { op: 'eq', field: 'dstName', value: 'kubernetes.default' },
      { op: 'in', field: 'proc', values: ['curl', 'wget', 'python3', 'python', 'sh', 'bash'] },
    ] },
    response: 'Pair with NW-004 within a short window to raise to critical: SA token theft + API recon.',
    tags: ['container', 'mitre', 'lateral'],
  },
  {
    id: 'NW-006', name: 'Crypto-miner execution',
    description: 'A known miner binary or mining pool connection — the most common opportunistic payload on exposed clusters.',
    kind: 'process', severity: 'critical', attack: ['T1496'], confidence: 0.9,
    condition: { op: 'or', of: [
      { op: 'in', field: 'proc', values: ['xmrig', 'minerd', 'cpuminer', 'kdevtmpfsi'] },
      { op: 'contains', field: 'args', value: 'stratum+tcp' },
    ] },
    response: 'CRITICAL. Kill the pod, scan the image and its registry source, check the admission path that let it in.',
    tags: ['container', 'mitre', 'impact'],
  },
  {
    id: 'NW-007', name: 'Mining pool network connection',
    description: 'Outbound connection on a well-known stratum mining port.',
    kind: 'network', severity: 'critical', attack: ['T1496', 'T1071'], confidence: 0.85,
    condition: { op: 'and', of: [{ op: 'eq', field: 'direction', value: 'outbound' }, { op: 'in', field: 'dstPort', values: [3333, 4444, 5555, 7777, 14444, 45700] }] },
    response: 'CRITICAL. Null-route the destination at the egress firewall; treat the node as compromised.',
    tags: ['container', 'mitre', 'c2'],
  },
  {
    id: 'NW-008', name: 'Ingress tool transfer into container',
    description: 'A download utility pulling a payload into a running container — tooling is baked into images, not fetched at runtime.',
    kind: 'process', severity: 'warning', attack: ['T1105'], confidence: 0.55,
    condition: { op: 'and', of: [
      { op: 'in', field: 'proc', values: ['curl', 'wget'] },
      { op: 'or', of: [{ op: 'contains', field: 'args', value: '-o' }, { op: 'contains', field: 'args', value: 'http' }] },
      { op: 'not', of: { op: 'in', field: 'namespace', values: ['kube-system', 'ci'] } },
    ] },
    response: 'Baseline per namespace. In a running app container, runtime downloads are an IOC.',
    tags: ['container', 'mitre', 'c2'],
  },
  {
    id: 'NW-009', name: 'Package manager run in container',
    description: 'apt/apk/yum/pip invoked at runtime — images should be immutable; this is attacker tooling-up or drift.',
    kind: 'process', severity: 'notice', attack: ['T1059', 'T1105'], confidence: 0.4,
    condition: { op: 'in', field: 'proc', values: ['apt', 'apt-get', 'apk', 'yum', 'dnf', 'pip', 'pip3', 'npm'] },
    response: 'Expected in build/CI namespaces; an IOC in production app pods. Enforce read-only root FS to prevent it.',
    tags: ['container', 'mitre', 'drift'],
  },
  {
    id: 'NW-010', name: 'Reverse shell pattern',
    description: 'A shell with stdin/stdout redirected to a socket (bash -i >& /dev/tcp, nc -e, socket-reusing python).',
    kind: 'process', severity: 'critical', attack: ['T1059', 'T1071'], confidence: 0.9,
    condition: { op: 'or', of: [
      { op: 'regex', field: 'args', value: '/dev/tcp/' },
      { op: 'and', of: [{ op: 'eq', field: 'proc', value: 'nc' }, { op: 'contains', field: 'args', value: '-e' }] },
      { op: 'regex', field: 'args', value: 'socket\\(.*SOCK_STREAM' },
    ] },
    response: 'CRITICAL. Capture the destination IP/port, block egress, isolate the node.',
    tags: ['container', 'mitre', 'c2'],
  },
  {
    id: 'NW-011', name: 'Sensitive host path read',
    description: 'A read of a host-mounted sensitive path (/etc/shadow, docker.sock, host /proc) — recon or escape via a dangerous mount.',
    kind: 'file', severity: 'warning', attack: ['T1611', 'T1613'], confidence: 0.6,
    condition: { op: 'in', field: 'path', values: ['/host/etc/shadow', '/var/run/docker.sock', '/host/proc/1/environ', '/host/root/.ssh/id_rsa'] },
    response: 'Review the pod\'s volumeMounts; hostPath mounts of these paths should be blocked at admission.',
    tags: ['container', 'mitre', 'escape'],
  },
  {
    id: 'NW-012', name: 'kubectl exec into pod (audit)',
    description: 'A pods/exec request in the API audit log — legitimate for operators, but the entry point for hands-on-keyboard activity.',
    kind: 'k8s_audit', severity: 'notice', attack: ['T1059', 'T1021'], confidence: 0.3,
    condition: { op: 'and', of: [{ op: 'eq', field: 'resource', value: 'pods' }, { op: 'eq', field: 'subresource', value: 'exec' }] },
    response: 'Baseline against the on-call roster; exec by a service account or outside change windows is suspicious.',
    tags: ['k8s', 'mitre', 'audit'],
  },
  {
    id: 'NW-015', name: 'Pod exec by a service account (not a human)',
    description: 'A pods/exec request authenticated as a service account rather than a named human user. Operators exec as themselves; a service account exec\'ing into a pod means a stolen token is driving hands-on-keyboard activity.',
    kind: 'k8s_audit', severity: 'warning', attack: ['T1078', 'T1021', 'T1059'], confidence: 0.7,
    condition: { op: 'and', of: [
      { op: 'eq', field: 'resource', value: 'pods' },
      { op: 'eq', field: 'subresource', value: 'exec' },
      { op: 'startsWith', field: 'apiUser', value: 'system:serviceaccount:' },
    ] },
    response: 'Page. No workload SA should exec into pods. Revoke the token, review the SA\'s RBAC, hunt for the initial token theft.',
    tags: ['k8s', 'mitre', 'lateral'],
  },
  {
    id: 'NW-013', name: 'Secret enumerated by service account (audit)',
    description: 'A service account listing or reading secrets cluster-wide — over-permissioned SA abuse after a token theft.',
    kind: 'k8s_audit', severity: 'warning', attack: ['T1552.007', 'T1078'], confidence: 0.55,
    condition: { op: 'and', of: [
      { op: 'in', field: 'verb', values: ['list', 'get'] },
      { op: 'eq', field: 'resource', value: 'secrets' },
      { op: 'startsWith', field: 'apiUser', value: 'system:serviceaccount:' },
    ] },
    response: 'Check the SA\'s RBAC; most workloads never need cluster-wide secret reads. Rotate exposed secrets.',
    tags: ['k8s', 'mitre', 'credentials'],
  },
  {
    id: 'NW-014', name: 'Scheduled persistence via cron write',
    description: 'A write into a cron directory inside a container — runtime persistence.',
    kind: 'file', severity: 'warning', attack: ['T1053'], confidence: 0.7,
    condition: { op: 'and', of: [
      { op: 'or', of: [{ op: 'startsWith', field: 'path', value: '/etc/cron' }, { op: 'startsWith', field: 'path', value: '/var/spool/cron' }] },
      { op: 'contains', field: 'flags', value: 'O_WRONLY' },
    ] },
    response: 'Persistence IOC. Read-only root FS blocks this; alert if it still occurs.',
    tags: ['container', 'mitre', 'persistence'],
  },
];
