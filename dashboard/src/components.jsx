export const pct = (x, digits = 1) => (x == null ? "—" : `${(x * 100).toFixed(digits)}%`);
export const num = (x, digits = 3) => (x == null ? "—" : Number(x).toFixed(digits));
export const ci = (r, digits = 3) => `${num(r.point, digits)} (${num(r.ci_lower, digits)}–${num(r.ci_upper, digits)})`;

export function Meter({ value, max = 1, color = "var(--cox)", label }) {
  const w = Math.max(0, Math.min(1, value / max)) * 100;
  return (
    <div className="meter" title={label}>
      <div className="bar"><span style={{ width: `${w}%`, background: color }} /></div>
      <span className="small mono">{label}</span>
    </div>
  );
}

export function FiredRules({ fuzzy, limit }) {
  const rules = limit ? fuzzy.rules_fired.slice(0, limit) : fuzzy.rules_fired;
  return (
    <ul className="rules">
      {rules.map((r) => (
        <li key={r.id} title={r.text}>
          <span className="mono small"><b>{r.id}</b></span>
          <span>
            {r.text.replace(/^IF /, "").replace(/ THEN priority is /, " → ")}
            {!r.affects_score && <> <span className="badge expl" title="Bounded by another rule with the same consequent; explains but never moves the score">explanation only</span></>}
          </span>
          <Meter value={r.strength} color="var(--fuzzy)" label={r.strength.toFixed(2)} />
        </li>
      ))}
    </ul>
  );
}

export function Loading({ what }) {
  return <p className="muted">Loading {what}…</p>;
}

export function ErrorBox({ error }) {
  return error ? <div className="error">{String(error.message || error)}</div> : null;
}
