import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RULES } from '../core/rules.ts';
import { SCENARIOS } from '../core/scenarios.ts';
import { coverage, detect, runScenario } from '../core/engine.ts';
import { TECHNIQUES } from '../core/attack.ts';
import type { RuntimeEvent } from '../core/types.ts';

test('every attack scenario is detected with a page-worthy alert', () => {
  for (const s of SCENARIOS.filter((x) => x.kind === 'attack')) {
    const r = runScenario(RULES, s);
    assert.ok(r.detected, `${s.id} not detected; alerts: ${r.alerts.map((a) => a.ruleId)}`);
  }
});

test('attack scenarios cover every technique they exercise', () => {
  for (const s of SCENARIOS.filter((x) => x.kind === 'attack')) {
    const r = runScenario(RULES, s);
    assert.deepEqual(r.missedTechniques, [], `${s.id} missed ${r.missedTechniques}`);
  }
});

test('no benign scenario raises a warning/critical false positive', () => {
  for (const s of SCENARIOS.filter((x) => x.kind === 'benign')) {
    const r = runScenario(RULES, s);
    assert.deepEqual(r.falsePositives.map((a) => a.ruleId), [], `${s.id} false-positived on ${r.falsePositives.map((a) => a.ruleId)}`);
  }
});

test('coverage headline: 100% detection, 0% FP', () => {
  const c = coverage(RULES, SCENARIOS);
  assert.equal(c.detectionRate, 1);
  assert.equal(c.falsePositiveRate, 0);
  assert.ok(c.attackCount >= 7 && c.benignCount >= 5);
  assert.ok(c.meanMttdMs !== null && c.meanMttdMs >= 0);
});

test('every rule references a known ATT&CK technique', () => {
  for (const r of RULES) {
    assert.ok(r.attack.length > 0, `${r.id} has no technique`);
    for (const t of r.attack) assert.ok(TECHNIQUES[t], `${r.id} references unknown technique ${t}`);
    assert.ok(r.confidence >= 0 && r.confidence <= 1);
    assert.ok(r.response.length > 10, `${r.id} missing response guidance`);
  }
});

test('rule ids are unique', () => {
  const ids = RULES.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length);
});

test('escape chain: nsenter fires critical, not the benign shell', () => {
  const esc = SCENARIOS.find((s) => s.id === 'escape')!;
  const r = runScenario(RULES, esc);
  assert.ok(r.alerts.some((a) => a.ruleId === 'NW-002' && a.severity === 'critical'));
});

test('benign operator exec produces only notices', () => {
  const r = runScenario(RULES, SCENARIOS.find((s) => s.id === 'operator-exec')!);
  assert.ok(r.alerts.length > 0, 'engine should still observe the exec/shell');
  assert.ok(r.alerts.every((a) => a.severity === 'info' || a.severity === 'notice'));
});

test('condition engine: and/or/not/regex', () => {
  const base: RuntimeEvent = { ts: 0, kind: 'process', pod: 'p', namespace: 'n', container: 'c', image: 'i', proc: 'bash', args: 'foo /dev/tcp/1.2.3.4/4444 bar' };
  const { alerts } = detect(RULES, [base]);
  assert.ok(alerts.some((a) => a.ruleId === 'NW-010'), 'reverse-shell regex should match');
});
