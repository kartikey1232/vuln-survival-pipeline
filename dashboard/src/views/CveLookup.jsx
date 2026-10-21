import { useEffect, useMemo, useState } from "react";
import {
  CartesianGrid, ComposedChart, Legend, Line, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from "recharts";
import { api } from "../api.js";
import { ErrorBox, FiredRules, Loading, Meter, num, pct } from "../components.jsx";

const DAY = 86400000;
const LANDMARK_COLORS = { 7: "#2a5bd7", 14: "#1d8a8a", 30: "#6b7280" };
const toTs = (d) => new Date(`${d}T00:00:00Z`).getTime();
const fmtDate = (ts) => new Date(ts).toISOString().slice(0, 10);

// One time axis: EPSS percentile per snapshot (left), and per landmark the
// Cox cumulative P(KEV-listed) = 1 - S(t) at as_of_date + t (right, %).
function chartData(cve) {
  const rows = cve.epss_history.map((p) => ({ x: toTs(p.snapshot_date), epss: Number(p.percentile) }));
  for (const lm of cve.landmarks) {
    const start = toTs(lm.as_of_date);
    rows.push({ x: start, [`p${lm.landmark_day}`]: 0 });
    for (const pt of lm.survival_curve) {
      rows.push({ x: start + pt.day * DAY, [`p${lm.landmark_day}`]: (1 - pt.survival_probability) * 100 });
    }
  }
  return rows.sort((a, b) => a.x - b.x);
}

function TrajectoryChart({ cve }) {
  const data = useMemo(() => chartData(cve), [cve]);
  const kevTs = cve.kev ? toTs(cve.kev.date_added) : null;
  return (
    <div className="card">
      <h2>EPSS trajectory and Cox survival curve</h2>
      <p className="muted">
        Left axis: EPSS percentile over time. Right axis: Cox cumulative probability of KEV listing from each
        landmark, over the following 365 days. Cox probabilities are under-dispersed, so read the curve's shape and its
        rank (below), not its height.
      </p>
      <div style={{ width: "100%", height: 320 }}>
        <ResponsiveContainer>
          <ComposedChart data={data} margin={{ top: 10, right: 16, bottom: 0, left: 0 }}>
            <CartesianGrid stroke="var(--line)" strokeDasharray="3 3" />
            <XAxis dataKey="x" type="number" scale="time" domain={["dataMin", "dataMax"]} tickFormatter={fmtDate}
                   stroke="var(--muted)" fontSize={11} />
            <YAxis yAxisId="epss" domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}`} stroke="var(--epss)"
                   fontSize={11} label={{ value: "EPSS pct", angle: -90, position: "insideLeft", fill: "var(--epss)", fontSize: 11 }} />
            <YAxis yAxisId="cox" orientation="right" tickFormatter={(v) => `${v.toFixed(2)}%`} stroke="var(--cox)" fontSize={11} />
            <Tooltip labelFormatter={fmtDate}
                     formatter={(v, name) => (name === "EPSS percentile" ? [num(v, 3), name] : [`${v.toFixed(3)}%`, name])}
                     contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)" }} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Line yAxisId="epss" dataKey="epss" name="EPSS percentile" stroke="var(--epss)" dot={false} strokeWidth={2} connectNulls isAnimationActive={false} />
            {cve.landmarks.map((lm) => (
              <Line key={lm.landmark_day} yAxisId="cox" dataKey={`p${lm.landmark_day}`} connectNulls
                    name={`Cox P(KEV) from day ${lm.landmark_day}`} stroke={LANDMARK_COLORS[lm.landmark_day]}
                    strokeDasharray={lm.landmark_day === 30 ? "4 3" : undefined} dot={{ r: 2 }} isAnimationActive={false} />
            ))}
            {kevTs && <ReferenceLine yAxisId="epss" x={kevTs} stroke="var(--kev)" label={{ value: "KEV", fill: "var(--kev)", fontSize: 11 }} />}
          </ComposedChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

function Context({ cve }) {
  const cna = cve.cna_source_identifier;
  return (
    <div className="card">
      <h2>CVSS / CWE / CNA context</h2>
      <p className="small">
        <b>CNA:</b> <span className="mono">{cna || "unknown"}</span>
        <span className="muted"> — the model only uses CVSS/CWE whose source is the CVE's own CNA (NVD- and CISA-added
          enrichment is excluded as label leakage).</span>
      </p>
      <h3>CVSS metrics</h3>
      {cve.cvss_metrics.length === 0 ? <p className="muted">No CVSS metrics.</p> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Version</th><th className="num">Score</th><th>Severity</th><th>Source</th><th>Vector</th></tr></thead>
            <tbody>
              {cve.cvss_metrics.map((m) => (
                <tr key={`${m.cvss_version}-${m.source}`}>
                  <td>{m.cvss_version}</td><td className="num">{m.base_score}</td><td>{m.base_severity || "—"}</td>
                  <td className="mono small">{m.source} {m.source === cna && <span className="badge cna">CNA · used</span>}</td>
                  <td className="mono small">{m.vector_string}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <h3>CWEs</h3>
      {cve.cwes.length === 0 ? <p className="muted">No CWE mappings.</p> : (
        <ul className="small">
          {cve.cwes.map((w) => (
            <li key={`${w.cwe_id}-${w.source}`}>
              <span className="mono">{w.cwe_id}</span> {w.name || ""} <span className="muted mono">({w.source}{w.source === cna ? ", CNA" : ""})</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Landmarks({ cve }) {
  const [selected, setSelected] = useState(cve.landmarks[0]?.landmark_day);
  const lm = cve.landmarks.find((l) => l.landmark_day === selected);
  return (
    <div className="card">
      <h2>Cox risk percentile per landmark</h2>
      <p className="muted">
        Percentile of the Cox partial hazard against the training-period distribution for the same landmark.
        This is the ranking signal.
      </p>
      {cve.landmarks.length === 0 && <p className="muted">No scored landmarks.</p>}
      {cve.landmarks.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Landmark</th><th>As of</th><th>Split</th><th>Cox risk percentile</th><th className="num">EPSS pct</th><th className="num">CNA CVSS</th><th className="num">Fuzzy priority</th></tr></thead>
            <tbody>
              {cve.landmarks.map((l) => (
                <tr key={l.landmark_day} className="clickable" onClick={() => setSelected(l.landmark_day)}
                    style={l.landmark_day === selected ? { outline: "2px solid var(--fuzzy)" } : undefined}>
                  <td>day {l.landmark_day}</td><td>{l.as_of_date}</td><td>{l.split}</td>
                  <td style={{ minWidth: 160 }}><Meter value={l.cox_risk_pct} label={pct(l.cox_risk_pct)} /></td>
                  <td className="num">{pct(l.epss_pct_now)}</td>
                  <td className="num">{l.cvss_base_score ?? "missing"}</td>
                  <td className="num">{num(l.fuzzy.priority, 1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {cve.landmarks_not_scored.map((n) => (
        <p key={n.landmark_day} className="muted small">Day {n.landmark_day} ({n.as_of_date}): not scored — {n.reason}.</p>
      ))}
      {lm && (
        <>
          <h3>Why it ranks here — fuzzy explanation, day {lm.landmark_day}</h3>
          <p className="muted small">
            Priority {num(lm.fuzzy.priority, 1)} / 100. Blindspot (Cox pct − EPSS pct) = {num(lm.fuzzy.blindspot, 2)}; zero
            does not mean the two agree, since they're measured against different populations. These rules explain the
            Cox ranking; they don't change it.
          </p>
          <FiredRules fuzzy={lm.fuzzy} />
        </>
      )}
    </div>
  );
}

export default function CveLookup({ cveId, onLookup }) {
  const [input, setInput] = useState(cveId || "");
  const [state, setState] = useState({ loading: false, data: null, error: null });

  useEffect(() => {
    setInput(cveId || "");
    if (!cveId) { setState({ loading: false, data: null, error: null }); return; }
    let live = true;
    setState({ loading: true, data: null, error: null });
    api.cve(cveId).then((data) => live && setState({ loading: false, data, error: null }),
                        (error) => live && setState({ loading: false, data: null, error }));
    return () => { live = false; };
  }, [cveId]);

  const cve = state.data;
  return (
    <>
      <form className="search" onSubmit={(e) => { e.preventDefault(); if (input.trim()) onLookup(input.trim().toUpperCase()); }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="CVE-2025-12345" aria-label="CVE ID" />
        <button className="btn" type="submit">Look up</button>
      </form>
      {!cveId && <p className="muted">Enter a CVE ID, or open one from the watchlist.</p>}
      {state.loading && <Loading what={cveId} />}
      <ErrorBox error={state.error} />
      {cve && (
        <>
          <div className="card">
            <h2>
              <span className="mono">{cve.cve_id}</span>{" "}
              {cve.kev && <span className="badge kev">KEV-listed {cve.kev.date_added}</span>}
            </h2>
            <p className="muted small">Published {cve.published_date} · NVD status {cve.vuln_status || "—"}</p>
            <p style={{ fontSize: 14 }}>{cve.description}</p>
            {cve.kev && <p className="small">KEV: {cve.kev.vulnerability_name} ({cve.kev.vendor_project} {cve.kev.product})</p>}
          </div>
          <TrajectoryChart cve={cve} />
          <Landmarks cve={cve} />
          <Context cve={cve} />
          {cve.notes.map((n) => <p key={n} className="muted small">{n}</p>)}
        </>
      )}
    </>
  );
}
