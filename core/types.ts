// NIGHTWATCH — Kubernetes runtime threat detection engineering.
//
// A detection engine is only as good as the evidence that it fires on real
// attacks and stays quiet on real workloads. These types model a stream of
// runtime events (the kind Falco/Tetragon emit from the kernel), a portable
// rule format, and labeled scenarios so every rule can be scored for detection
// rate, false-positive rate and MITRE ATT&CK coverage.

export type EventKind =
  | 'process' // a program executed (execve)
  | 'file' // a file was opened/written
  | 'network' // an outbound/inbound connection
  | 'k8s_audit' // a Kubernetes API request (apiserver audit log)
  | 'syscall'; // a notable raw syscall (e.g. ptrace, setns)

export interface RuntimeEvent {
  ts: number; // ms since scenario start
  kind: EventKind;
  /** workload identity */
  pod: string;
  namespace: string;
  container: string;
  image: string;
  /** process context */
  proc?: string; // comm / binary basename
  exe?: string; // full path
  args?: string; // joined argv
  parent?: string; // parent comm
  user?: string; // user in container (root = uid 0)
  uid?: number;
  /** file context */
  path?: string;
  flags?: string; // e.g. "O_WRONLY"
  /** network context */
  direction?: 'inbound' | 'outbound';
  dstIp?: string;
  dstPort?: number;
  dstName?: string; // resolved name / well-known endpoint
  /** k8s audit context */
  verb?: string; // get/create/exec/...
  resource?: string; // pods/exec, secrets, ...
  subresource?: string;
  apiUser?: string; // system:serviceaccount:...
  /** container posture flags (from the spec, surfaced on each event) */
  privileged?: boolean;
  hostPid?: boolean;
  hostNetwork?: boolean;
}

export type Severity = 'info' | 'notice' | 'warning' | 'critical';

// A condition is a tree over event fields. Kept deliberately small and
// serialisable so the same rule can be expressed as Falco/Tetragon YAML.
export type Condition =
  | { op: 'eq'; field: EventField; value: string | number | boolean }
  | { op: 'ne'; field: EventField; value: string | number | boolean }
  | { op: 'in'; field: EventField; values: (string | number)[] }
  | { op: 'contains'; field: EventField; value: string }
  | { op: 'startsWith'; field: EventField; value: string }
  | { op: 'regex'; field: EventField; value: string }
  | { op: 'gt'; field: EventField; value: number }
  | { op: 'exists'; field: EventField }
  | { op: 'and'; of: Condition[] }
  | { op: 'or'; of: Condition[] }
  | { op: 'not'; of: Condition };

export type EventField = keyof RuntimeEvent;

export interface Rule {
  id: string;
  name: string;
  description: string;
  kind: EventKind;
  severity: Severity;
  /** MITRE ATT&CK technique id(s), e.g. T1611 (Escape to Host) */
  attack: string[];
  /** 0..1 — how strongly this indicates true malice; used to rank, and as a
   * hint for which rules are prone to false positives in noisy clusters. */
  confidence: number;
  condition: Condition;
  /** operator guidance surfaced with every alert */
  response: string;
  /** structured tags, e.g. ["container","mitre"] */
  tags: string[];
}

export interface Alert {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  attack: string[];
  event: RuntimeEvent;
  at: number;
}

export interface Scenario {
  id: string;
  title: string;
  kind: 'attack' | 'benign';
  /** ATT&CK techniques this trace is meant to exercise (attack scenarios) */
  techniques?: string[];
  blurb: string;
  events: RuntimeEvent[];
}

export interface TechniqueInfo {
  id: string;
  name: string;
  tactic: string;
}
