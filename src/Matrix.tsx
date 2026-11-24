import { TECHNIQUES, TACTIC_ORDER, primaryTactic } from '../core/attack.ts';
import { RULES } from '../core/rules.ts';

const techByTactic = () => {
  const m = new Map<string, string[]>();
  for (const id of Object.keys(TECHNIQUES)) {
    const t = primaryTactic(TECHNIQUES[id]);
    m.set(t, [...(m.get(t) ?? []), id]);
  }
  return m;
};
const RULE_TECH = new Set(RULES.flatMap((r) => r.attack));

export function MitreMatrix({ fired }: { fired: Set<string> }) {
  const grid = techByTactic();
  return (
    <div className="matrix">
      {TACTIC_ORDER.map((tactic) => {
        const techs = grid.get(tactic) ?? [];
        if (!techs.length) return null;
        return (
          <div key={tactic} className="col">
            <div className="tactic">{tactic}</div>
            {techs.sort().map((id) => {
              const has = RULE_TECH.has(id);
              const hit = fired.has(id);
              return (
                <div key={id} className={`cell ${has ? 'covered' : 'gap'} ${hit ? 'hit' : ''}`} title={`${id} ${TECHNIQUES[id].name}`}>
                  <b>{id}</b>
                  <span>{TECHNIQUES[id].name}</span>
                </div>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}
