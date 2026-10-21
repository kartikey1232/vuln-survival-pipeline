import { useEffect, useMemo, useState } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../api.js";
import { ci, ErrorBox, Loading, num, pct } from "../components.jsx";

const SERIES = {
  Cox: { color: "var(--cox)", width: 3 },
  RSF: { color: "#1d8a8a", width: 1.5 },
  "XGBoost-AFT": { color: "#8a8a1d", width: 1.5 },
  "EPSS-alone": { color: "var(--epss)", width: 2 },
  "Fuzzy (explanation layer)": { color: "var(--fuzzy)", width: 1.5, dash: "5 4" },
};

function Diff({ d }) {
  return (
    <span className="small">
      {d.point_diff >= 0 ? "+" : ""}{num(d.point_diff)} ({num(d.ci_lower)}, {num(d.ci_upper)}){" "}
      {d.excludes_zero ? <span className="badge sig">CI excludes 0</span> : <span className="muted">n.s.</span>}
    </span>
  );
}

export default function Backtest() {
  const [state, setState] = useState({ data: null, error: null });
  useEffect(() => { api.backtest().then((data) => setState({ data, error: null }), (error) => setState({ data: null, error })); }, []);
  const d = state.data;
  const curve = useMemo(() => d && d.recall_curve.budgets.map((b, i) => ({
    budget: b * 100,
    ...Object.fromEntries(Object.entries(d.recall_curve.recall).map(([m, r]) => [m, r[i]])),
  })), [d]);

  if (state.error) return <ErrorBox error={state.error} />;
  if (!d) return <Loading what="backtest" />;
  const models = ["Cox", "RSF", "XGBoost-AFT", "EPSS-alone"];
  return (
    <>
      <div className="card">
        <h2>Backtest on the held-out test period (corrected encoding)</h2>
        <p className="muted">
          {d.test_rows.toLocaleString()} landmark rows, {d.test_cves.toLocaleString()} CVEs published from 2025-01-01,
          {" "}{d.test_events} KEV events. Frozen models, nothing refit; {d.bootstrap}. Source: {d.source}.
        </p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Model</th><th className="num">C-index (95% CI)</th><th className="num">Recall@1%</th><th className="num">Recall@5%</th>
                <th className="num">Recall@10%</th><th className="num">Blind-spot @10%</th><th>ΔC-index vs EPSS</th></tr>
            </thead>
            <tbody>
              {models.map((m) => {
                const r = d.models[m];
                const bs = d.blind_spot_catch_rate_10pct[m];
                return (
                  <tr key={m} style={m === "Cox" ? { fontWeight: 600 } : undefined}>
                    <td>{m}{m === "Cox" && <> <span className="badge cna">ranking model</span></>}</td>
                    <td className="num">{ci(r.cindex)}</td>
                    {["1pct", "5pct", "10pct"].map((k) => <td key={k} className="num">{ci(r.recall_at_budget[k])}</td>)}
                    <td className="num">{bs ? ci(bs) : "0 (by definition)"}</td>
                    <td>{d.paired_vs_epss[m] ? <Diff d={d.paired_vs_epss[m].cindex} /> : "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="muted small">
          Time-dependent AUC (30 / 90 / 180 days):{" "}
          {Object.entries(d.time_dependent_auc_pooled).map(([m, a]) => `${m} ${num(a["30"])} / ${num(a["90"])} / ${num(a["180"])}`).join(" · ")}
        </p>
      </div>

      <div className="card">
        <h2>Recall at alert budget</h2>
        <p className="muted">
          Share of all test KEV events caught when patching the top X% of rows by each ranking. Point estimates; the table
          above has CIs at 1/5/10%. The fuzzy layer is drawn dashed: it is the explanation layer, not a ranking candidate.
        </p>
        <div style={{ width: "100%", height: 340 }}>
          <ResponsiveContainer>
            <LineChart data={curve} margin={{ top: 10, right: 16, bottom: 24, left: 0 }}>
              <CartesianGrid stroke="var(--line)" strokeDasharray="3 3" />
              <XAxis dataKey="budget" type="number" domain={[0, 30]} ticks={[0, 5, 10, 15, 20, 25, 30]}
                     tickFormatter={(v) => `${v}%`} stroke="var(--muted)" fontSize={11}
                     label={{ value: "Alert budget (% of rows)", position: "insideBottom", offset: -12, fill: "var(--muted)", fontSize: 11 }} />
              <YAxis domain={[0, 1]} tickFormatter={(v) => `${Math.round(v * 100)}%`} stroke="var(--muted)" fontSize={11} />
              <Tooltip labelFormatter={(v) => `budget ${Number(v).toFixed(1)}%`} formatter={(v, n) => [pct(v), n]}
                       contentStyle={{ background: "var(--surface)", border: "1px solid var(--line)" }} />
              <Legend verticalAlign="top" wrapperStyle={{ fontSize: 12, paddingBottom: 8 }} />
              {Object.entries(SERIES).map(([m, s]) => (
                <Line key={m} dataKey={m} stroke={s.color} strokeWidth={s.width} strokeDasharray={s.dash} dot={false} isAnimationActive={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card">
        <h2>Why the fuzzy layer explains rather than ranks</h2>
        <div className="table-wrap">
          <table>
            <thead><tr><th>Fuzzy minus…</th><th>ΔC-index</th><th>ΔRecall@5%</th><th>ΔRecall@10%</th></tr></thead>
            <tbody>
              {Object.entries(d.fuzzy.paired_fuzzy_minus_reference).map(([ref, p]) => (
                <tr key={ref}><td>{ref}</td><td><Diff d={p.cindex} /></td><td><Diff d={p.recall_5pct} /></td><td><Diff d={p.recall_10pct} /></td></tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="muted small">
          No better than a linear blend of the same inputs, and worse than Cox at recall@10%. Its contribution is the
          per-row rule explanation shown in the other two views.
        </p>
      </div>
    </>
  );
}
