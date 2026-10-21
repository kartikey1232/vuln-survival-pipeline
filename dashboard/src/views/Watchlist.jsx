import { useEffect, useState } from "react";
import { api } from "../api.js";
import { ErrorBox, FiredRules, Loading, Meter, num, pct } from "../components.jsx";

const BUDGETS = [0.01, 0.05, 0.1, 0.2];
const PAGE = 50;

export default function Watchlist({ onOpenCve }) {
  const [budget, setBudget] = useState(0.1);
  const [landmarkDay, setLandmarkDay] = useState("");
  const [offset, setOffset] = useState(0);
  const [onlyBlind, setOnlyBlind] = useState(false);
  const [state, setState] = useState({ loading: true, data: null, error: null });

  useEffect(() => {
    let live = true;
    setState((s) => ({ ...s, loading: true, error: null }));
    api.watchlist({ budget, landmarkDay, limit: PAGE, offset })
      .then((data) => live && setState({ loading: false, data, error: null }),
            (error) => live && setState({ loading: false, data: null, error }));
    return () => { live = false; };
  }, [budget, landmarkDay, offset]);

  const d = state.data;
  const items = d ? (onlyBlind ? d.items.filter((i) => i.epss_ranks_low) : d.items) : [];
  return (
    <>
      <div className="card">
        <h2>Blind-spot watchlist — ranked by Cox</h2>
        <p className="muted">
          The top <b>budget</b> share of test-period landmark rows by Cox partial hazard. Highlighted rows are ones EPSS
          ranks low: outside EPSS's own top budget of the same rows. Those are the blind spots this system exists to
          surface. The fuzzy column explains each row's rank and doesn't reorder anything.
        </p>
        <div className="controls">
          <label>Budget{" "}
            <select value={budget} onChange={(e) => { setBudget(Number(e.target.value)); setOffset(0); }}>
              {BUDGETS.map((b) => <option key={b} value={b}>{pct(b, 0)}</option>)}
            </select>
          </label>
          <label>Landmark{" "}
            <select value={landmarkDay} onChange={(e) => { setLandmarkDay(e.target.value); setOffset(0); }}>
              <option value="">all (pooled)</option>
              {[7, 14, 30].map((l) => <option key={l} value={l}>day {l}</option>)}
            </select>
          </label>
          <label><input type="checkbox" checked={onlyBlind} onChange={(e) => setOnlyBlind(e.target.checked)} /> only EPSS blind spots (this page)</label>
        </div>
        {d && (
          <div className="stats">
            <div className="stat"><b>{d.pool_rows.toLocaleString()}</b><span className="muted">rows in pool</span></div>
            <div className="stat"><b>{d.selected_rows.toLocaleString()}</b><span className="muted">selected by Cox at {pct(d.budget, 0)}</span></div>
            <div className="stat"><b>{d.selected_epss_ranks_low.toLocaleString()}</b><span className="muted">of them EPSS ranks low ({pct(d.selected_epss_ranks_low / d.selected_rows, 0)})</span></div>
          </div>
        )}
        {d && <p className="muted small">{d.pool}. KEV dates are retrospective: they show what later happened.</p>}
      </div>
      <ErrorBox error={state.error} />
      {state.loading && <Loading what="watchlist (the first load scores every test row, a few seconds)" />}
      {d && (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th className="num">Cox rank</th><th>CVE</th><th>Landmark</th><th>Cox risk pct</th>
                  <th className="num">EPSS pct</th><th>EPSS</th><th>Later KEV</th><th>Fuzzy explanation</th>
                </tr>
              </thead>
              <tbody>
                {items.map((i) => (
                  <tr key={`${i.cve_id}-${i.landmark_day}`} className={`clickable ${i.epss_ranks_low ? "blindspot" : ""}`}
                      onClick={() => onOpenCve(i.cve_id)}>
                    <td className="num">{i.rank}</td>
                    <td className="mono">{i.cve_id}</td>
                    <td>day {i.landmark_day}<div className="muted small">{i.as_of_date}</div></td>
                    <td style={{ minWidth: 130 }}><Meter value={i.cox_risk_pct} label={pct(i.cox_risk_pct)} /></td>
                    <td className="num">{pct(i.epss_pct_now)}</td>
                    <td>{i.epss_ranks_low ? <span className="badge blind">ranks low</span> : <span className="muted small">top {pct(d.budget, 0)}</span>}</td>
                    <td>{i.kev_date_added ? <span className="badge kev">{i.kev_date_added}</span> : <span className="muted small">—</span>}</td>
                    <td style={{ minWidth: 300 }}>
                      <div className="small">priority <b>{num(i.fuzzy.priority, 1)}</b></div>
                      <FiredRules fuzzy={i.fuzzy} limit={2} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pager">
            <button className="btn secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
            <span className="muted small">ranks {offset + 1}–{Math.min(offset + PAGE, d.selected_rows)} of {d.selected_rows.toLocaleString()}</span>
            <button className="btn secondary" disabled={offset + PAGE >= d.selected_rows} onClick={() => setOffset(offset + PAGE)}>Next</button>
          </div>
        </div>
      )}
    </>
  );
}
