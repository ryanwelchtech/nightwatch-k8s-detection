import type { Alert, Condition, EventField, RuntimeEvent, Rule, Scenario } from './types.ts';

function fieldValue(e: RuntimeEvent, f: EventField): unknown {
  return e[f];
}

export function evalCondition(c: Condition, e: RuntimeEvent): boolean {
  switch (c.op) {
    case 'and': return c.of.every((x) => evalCondition(x, e));
    case 'or': return c.of.some((x) => evalCondition(x, e));
    case 'not': return !evalCondition(c.of, e);
    case 'exists': return fieldValue(e, c.field) !== undefined;
  }
  const v = fieldValue(e, c.field);
  switch (c.op) {
    case 'eq': return v === c.value;
    case 'ne': return v !== c.value;
    case 'in': return v !== undefined && c.values.includes(v as string | number);
    case 'gt': return typeof v === 'number' && v > c.value;
    case 'contains': return typeof v === 'string' && v.includes(c.value);
    case 'startsWith': return typeof v === 'string' && v.startsWith(c.value);
    case 'regex': return typeof v === 'string' && new RegExp(c.value).test(v);
  }
}

export function matchRule(rule: Rule, e: RuntimeEvent): boolean {
  if (rule.kind !== e.kind) return false;
  return evalCondition(rule.condition, e);
}

export interface DetectionRun {
  alerts: Alert[];
  /** per rule: how many events it fired on */
  byRule: Map<string, number>;
  eventsProcessed: number;
}

export function detect(rules: Rule[], events: RuntimeEvent[]): DetectionRun {
  const alerts: Alert[] = [];
  const byRule = new Map<string, number>();
  for (const e of events) {
    for (const r of rules) {
      if (matchRule(r, e)) {
        alerts.push({ ruleId: r.id, ruleName: r.name, severity: r.severity, attack: r.attack, event: e, at: e.ts });
        byRule.set(r.id, (byRule.get(r.id) ?? 0) + 1);
      }
    }
  }
  return { alerts, byRule, eventsProcessed: events.length };
}

/** A benign scenario "fails" only if it raises a page-worthy alert. Notices on
 * benign traffic are expected baseline telemetry, not false positives — the same
 * distinction a real SOC draws between a notice feed and a pager rule. */
const PAGES = (a: Alert) => a.severity === 'warning' || a.severity === 'critical';

export interface ScenarioResult {
  scenario: Scenario;
  alerts: Alert[];
  detected: boolean; // attack: a page-worthy alert fired; benign: none did
  /** attack only: ms from first event to first alert (mean time to detect) */
  mttdMs: number | null;
  /** attack only: ATT&CK techniques the trace exercised that at least one alert covered */
  coveredTechniques: string[];
  missedTechniques: string[];
  /** benign only: warning/critical alerts that should not have fired */
  falsePositives: Alert[];
  /** benign only: expected notice-level baseline hits */
  baselineNotices: Alert[];
}

export function runScenario(rules: Rule[], s: Scenario): ScenarioResult {
  const { alerts } = detect(rules, s.events);
  if (s.kind === 'attack') {
    const want = new Set(s.techniques ?? []);
    const covered = new Set<string>();
    for (const a of alerts) for (const t of a.attack) if (want.has(t)) covered.add(t);
    const paging = alerts.filter(PAGES);
    const firstAlert = paging.length ? Math.min(...paging.map((a) => a.at)) : null;
    const firstEvent = s.events.length ? Math.min(...s.events.map((e) => e.ts)) : 0;
    return {
      scenario: s, alerts, detected: paging.length > 0,
      mttdMs: firstAlert === null ? null : firstAlert - firstEvent,
      coveredTechniques: [...covered],
      missedTechniques: [...want].filter((t) => !covered.has(t)),
      falsePositives: [], baselineNotices: [],
    };
  }
  const fp = alerts.filter(PAGES);
  return { scenario: s, alerts, detected: fp.length === 0, mttdMs: null, coveredTechniques: [], missedTechniques: [], falsePositives: fp, baselineNotices: alerts.filter((a) => !PAGES(a)) };
}

export interface CoverageReport {
  scenarios: ScenarioResult[];
  attackCount: number;
  benignCount: number;
  detectedAttacks: number;
  detectionRate: number; // detected / attack
  falsePositiveRate: number; // benign scenarios with >=1 alert / benign
  meanMttdMs: number | null;
  /** techniques referenced by any rule */
  techniquesWithRule: string[];
  /** techniques exercised by attack scenarios */
  techniquesExercised: string[];
  /** exercised techniques with at least one detecting alert */
  techniquesCovered: string[];
  techniquesMissed: string[];
}

export function coverage(rules: Rule[], scenarios: Scenario[]): CoverageReport {
  const results = scenarios.map((s) => runScenario(rules, s));
  const attacks = results.filter((r) => r.scenario.kind === 'attack');
  const benign = results.filter((r) => r.scenario.kind === 'benign');
  const detected = attacks.filter((r) => r.detected);
  const mttds = attacks.map((r) => r.mttdMs).filter((x): x is number => x !== null);
  const techWithRule = new Set<string>();
  for (const r of rules) for (const t of r.attack) techWithRule.add(t);
  const exercised = new Set<string>();
  const covered = new Set<string>();
  for (const a of attacks) {
    for (const t of a.scenario.techniques ?? []) exercised.add(t);
    for (const t of a.coveredTechniques) covered.add(t);
  }
  return {
    scenarios: results,
    attackCount: attacks.length,
    benignCount: benign.length,
    detectedAttacks: detected.length,
    detectionRate: attacks.length ? detected.length / attacks.length : 0,
    falsePositiveRate: benign.length ? benign.filter((r) => r.falsePositives.length).length / benign.length : 0,
    meanMttdMs: mttds.length ? Math.round(mttds.reduce((a, b) => a + b, 0) / mttds.length) : null,
    techniquesWithRule: [...techWithRule],
    techniquesExercised: [...exercised],
    techniquesCovered: [...covered],
    techniquesMissed: [...exercised].filter((t) => !covered.has(t)),
  };
}
