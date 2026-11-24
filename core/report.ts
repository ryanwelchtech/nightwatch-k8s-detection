// CI-gate coverage report. Run `npm run report` (optionally `-- --json` or
// `-- --min-detection 1.0 --max-fp 0`) to fail a pipeline on detection
// regressions — detection engineering treated as code.

import { RULES } from './rules.ts';
import { SCENARIOS } from './scenarios.ts';
import { coverage } from './engine.ts';
import { TECHNIQUES, TACTIC_ORDER, primaryTactic } from './attack.ts';

const args = process.argv.slice(2);
const flag = (n: string, d: number) => { const i = args.indexOf(n); return i >= 0 ? Number(args[i + 1]) : d; };
const minDetection = flag('--min-detection', 1);
const maxFp = flag('--max-fp', 0);

const c = coverage(RULES, SCENARIOS);

if (args.includes('--json')) {
  console.log(JSON.stringify({ detectionRate: c.detectionRate, falsePositiveRate: c.falsePositiveRate, meanMttdMs: c.meanMttdMs, rules: RULES.length, techniquesCovered: c.techniquesCovered.length, techniquesExercised: c.techniquesExercised.length }, null, 2));
} else {
  const pct = (n: number) => `${(n * 100).toFixed(0)}%`;
  console.log('\nNIGHTWATCH detection coverage\n' + '='.repeat(60));
  console.log(`rules loaded          ${RULES.length}`);
  console.log(`attack scenarios      ${c.attackCount}  detected ${c.detectedAttacks}  (${pct(c.detectionRate)})`);
  console.log(`benign scenarios      ${c.benignCount}  false positives ${c.scenarios.filter((s) => s.falsePositives.length).length}  (${pct(c.falsePositiveRate)})`);
  console.log(`mean time to detect   ${c.meanMttdMs} ms (first page-worthy alert)`);
  console.log(`ATT&CK techniques     ${c.techniquesCovered.length}/${c.techniquesExercised.length} exercised covered · ${c.techniquesWithRule.length} referenced by rules`);
  console.log('\nATT&CK coverage by tactic');
  const byTactic = new Map<string, string[]>();
  for (const t of c.techniquesWithRule) {
    const info = TECHNIQUES[t]; if (!info) continue;
    const key = primaryTactic(info);
    byTactic.set(key, [...(byTactic.get(key) ?? []), t]);
  }
  for (const tactic of TACTIC_ORDER) {
    const ts = byTactic.get(tactic);
    if (ts) console.log(`  ${tactic.padEnd(22)} ${ts.sort().join(', ')}`);
  }
  if (c.techniquesMissed.length) console.log('\nGAPS (exercised, not covered): ' + c.techniquesMissed.join(', '));
  console.log('\nper scenario');
  for (const s of c.scenarios) {
    const mark = s.scenario.kind === 'attack' ? (s.detected ? '✓ DETECT' : '✗ MISS  ') : (s.falsePositives.length ? '✗ FP    ' : '✓ CLEAN ');
    const extra = s.scenario.kind === 'attack' ? `mttd ${s.mttdMs}ms` : s.baselineNotices.length ? `${s.baselineNotices.length} notice(s)` : '';
    console.log(`  ${mark} ${s.scenario.title.padEnd(42)} ${extra}`);
  }
}

const ok = c.detectionRate >= minDetection && c.falsePositiveRate <= maxFp;
if (!args.includes('--json')) console.log('\n' + (ok ? 'PASS' : `FAIL (need detection ≥ ${pctf(minDetection)}, fp ≤ ${pctf(maxFp)})`) + '\n');
function pctf(n: number) { return `${(n * 100).toFixed(0)}%`; }
process.exit(ok ? 0 : 1);
