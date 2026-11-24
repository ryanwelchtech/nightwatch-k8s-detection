import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { Alert, RuntimeEvent, Severity } from '../core/types.ts';
import { RULES } from '../core/rules.ts';
import { SCENARIOS } from '../core/scenarios.ts';
import { coverage, matchRule } from '../core/engine.ts';
import { MitreMatrix } from './Matrix.tsx';

const auto = new URLSearchParams(location.search).has('auto');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const SEV_RANK: Record<Severity, number> = { info: 0, notice: 1, warning: 2, critical: 3 };

const EVENT_LINE = (e: RuntimeEvent): string => {
  switch (e.kind) {
    case 'process': return `exec ${e.proc}${e.args ? ' ' + e.args : ''}  (parent ${e.parent ?? '?'})`;
    case 'file': return `${e.flags?.includes('WRONLY') || e.flags?.includes('CREAT') ? 'write' : 'read'} ${e.path}  (${e.proc})`;
    case 'network': return `${e.direction} → ${e.dstName ?? e.dstIp}:${e.dstPort}  (${e.proc})`;
    case 'k8s_audit': return `audit ${e.verb} ${e.resource}${e.subresource ? '/' + e.subresource : ''}  (${e.apiUser})`;
    case 'syscall': return `syscall ${e.proc}`;
  }
};

export function App() {
  const [selected, setSelected] = useState(SCENARIOS[0].id);
  const [cursor, setCursor] = useState(0); // events revealed
  const [playing, setPlaying] = useState(false);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [firedTech, setFiredTech] = useState<Set<string>>(new Set());
  const cancel = useRef(false);
  const feed = useRef<HTMLDivElement>(null);

  const scenario = useMemo(() => SCENARIOS.find((s) => s.id === selected)!, [selected]);
  const report = useMemo(() => coverage(RULES, SCENARIOS), []);
  const criticalCount = alerts.filter((a) => a.severity === 'critical').length;
  const pageCount = alerts.filter((a) => SEV_RANK[a.severity] >= 2).length;

  const play = useCallback(async (id: string) => {
    cancel.current = true;
    await sleep(10);
    cancel.current = false;
    const s = SCENARIOS.find((x) => x.id === id)!;
    setSelected(id); setCursor(0); setAlerts([]); setFiredTech(new Set()); setPlaying(true);
    const sorted = [...s.events].sort((a, b) => a.ts - b.ts);
    const acc: Alert[] = [];
    const tech = new Set<string>();
    for (let i = 0; i < sorted.length; i++) {
      if (cancel.current) return;
      const e = sorted[i];
      for (const r of RULES) if (matchRule(r, e)) { acc.push({ ruleId: r.id, ruleName: r.name, severity: r.severity, attack: r.attack, event: e, at: e.ts }); for (const t of r.attack) tech.add(t); }
      setCursor(i + 1); setAlerts([...acc]); setFiredTech(new Set(tech));
      await sleep(auto ? 520 : 750);
      feed.current?.scrollTo({ top: feed.current.scrollHeight, behavior: 'smooth' });
    }
    setPlaying(false);
  }, []);

  useEffect(() => { play(SCENARIOS[0].id); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!auto) return;
    (async () => {
      await sleep(600);
      for (const id of ['escape', 'sa-theft', 'cryptomining', 'sdk-token']) { await play(id); await sleep(1100); }
      document.getElementById('tab-coverage')?.click();
      (window as unknown as { __done: boolean }).__done = true;
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const [tab, setTab] = useState<'live' | 'coverage'>('live');
  const revealed = [...scenario.events].sort((a, b) => a.ts - b.ts).slice(0, cursor);

  return (
    <div className="app">
      <header>
        <div className="brand">
          <span className="logo">◱</span>
          <div><h1>NIGHTWATCH</h1><p>Kubernetes runtime threat detection · MITRE ATT&CK for Containers</p></div>
        </div>
        <div className="chips">
          <span className="chip">rules <b>{RULES.length}</b></span>
          <span className="chip ok">detection <b>{(report.detectionRate * 100).toFixed(0)}%</b></span>
          <span className="chip ok">false-positive <b>{(report.falsePositiveRate * 100).toFixed(0)}%</b></span>
          <span className="chip">MTTD <b>{report.meanMttdMs} ms</b></span>
          <span className="chip">ATT&CK <b>{report.techniquesCovered.length}/{report.techniquesExercised.length}</b></span>
        </div>
      </header>

      <div className="tabs">
        <button id="tab-live" className={tab === 'live' ? 'on' : ''} onClick={() => setTab('live')}>Live detection</button>
        <button id="tab-coverage" className={tab === 'coverage' ? 'on' : ''} onClick={() => setTab('coverage')}>Coverage report</button>
      </div>

      {tab === 'live' ? (
        <main>
          <aside className="panel scn">
            <h2>Scenarios</h2>
            <div className="group">attack emulation</div>
            {SCENARIOS.filter((s) => s.kind === 'attack').map((s) => (
              <button key={s.id} className={`row ${selected === s.id ? 'active' : ''}`} onClick={() => play(s.id)}>
                <span className="dot attack" /><span>{s.title}</span>
              </button>
            ))}
            <div className="group">benign traffic</div>
            {SCENARIOS.filter((s) => s.kind === 'benign').map((s) => (
              <button key={s.id} className={`row ${selected === s.id ? 'active' : ''}`} onClick={() => play(s.id)}>
                <span className="dot benign" /><span>{s.title}</span>
              </button>
            ))}
          </aside>

          <section className="panel stream">
            <div className="shead">
              <div>
                <h2>{scenario.title} <span className={`tag ${scenario.kind}`}>{scenario.kind}</span></h2>
                <p className="blurb">{scenario.blurb}</p>
              </div>
              <div className={`verdict ${scenario.kind === 'attack' ? (pageCount ? 'detected' : playing ? 'pending' : 'miss') : (pageCount ? 'fp' : 'clean')}`}>
                {scenario.kind === 'attack' ? (pageCount ? 'DETECTED' : playing ? '…' : 'MISS') : (pageCount ? 'FALSE POS' : 'CLEAN')}
              </div>
            </div>
            <div className="feed" ref={feed}>
              {revealed.map((e, i) => {
                const evAlerts = alerts.filter((a) => a.event === e);
                return (
                  <div key={i} className="evt">
                    <span className="ts">+{e.ts}ms</span>
                    <span className={`kind ${e.kind}`}>{e.kind}</span>
                    <span className="eline">{EVENT_LINE(e)}</span>
                    {evAlerts.map((a, k) => (
                      <span key={k} className={`fire ${a.severity}`}>▲ {a.ruleId} {a.severity.toUpperCase()} · {a.attack.join(' ')}</span>
                    ))}
                  </div>
                );
              })}
              {!revealed.length && <div className="hint">▶ streaming kernel events…</div>}
            </div>
          </section>

          <section className="panel alerts">
            <h2>Alert feed {criticalCount > 0 && <span className="crit-badge">{criticalCount} critical</span>}</h2>
            <div className="alist">
              {[...alerts].reverse().map((a, i) => (
                <div key={i} className={`al ${a.severity}`}>
                  <div className="atop"><b>{a.ruleId}</b><span className={`sev ${a.severity}`}>{a.severity}</span></div>
                  <div className="aname">{a.ruleName}</div>
                  <div className="amitre">{a.attack.map((t) => <span key={t} className="tk">{t}</span>)}</div>
                </div>
              ))}
              {!alerts.length && <div className="hint">no detections yet</div>}
            </div>
          </section>
        </main>
      ) : (
        <main className="covmain">
          <section className="panel">
            <h2>MITRE ATT&CK for Containers — rule coverage</h2>
            <div className="legend">
              <span><i className="sw covered" /> rule exists</span>
              <span><i className="sw hit" /> fired in last run</span>
              <span><i className="sw gap" /> gap</span>
            </div>
            <MitreMatrix fired={firedTech} />
          </section>
          <section className="panel covtable">
            <h2>Scenario scoring</h2>
            <table>
              <thead><tr><th>scenario</th><th>type</th><th>result</th><th>mttd</th><th>alerts</th></tr></thead>
              <tbody>
                {report.scenarios.map((r) => (
                  <tr key={r.scenario.id}>
                    <td>{r.scenario.title}</td>
                    <td><span className={`tag ${r.scenario.kind}`}>{r.scenario.kind}</span></td>
                    <td className={r.scenario.kind === 'attack' ? (r.detected ? 'g' : 'r') : (r.falsePositives.length ? 'r' : 'g')}>
                      {r.scenario.kind === 'attack' ? (r.detected ? '✓ detected' : '✗ missed') : (r.falsePositives.length ? '✗ false pos' : '✓ clean')}
                    </td>
                    <td className="mono">{r.mttdMs !== null ? r.mttdMs + 'ms' : r.baselineNotices.length ? `${r.baselineNotices.length} notice` : '—'}</td>
                    <td className="mono">{r.alerts.length}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="headline">
              <div><b>{(report.detectionRate * 100).toFixed(0)}%</b><span>detection rate</span></div>
              <div><b>{(report.falsePositiveRate * 100).toFixed(0)}%</b><span>false-positive rate</span></div>
              <div><b>{report.meanMttdMs}ms</b><span>mean time to detect</span></div>
              <div><b>{report.techniquesCovered.length}/{report.techniquesExercised.length}</b><span>techniques covered</span></div>
            </div>
          </section>
        </main>
      )}
      <footer>Same TypeScript detection engine as <code>core/</code> and the CI gate (<code>npm run report</code>); the Falco/Tetragon rules in <code>rules/</code> are its in-cluster analogue. Fictitious workloads.</footer>
    </div>
  );
}
