import { useEffect, useState } from "react";
import CveLookup from "./views/CveLookup.jsx";
import Watchlist from "./views/Watchlist.jsx";
import Backtest from "./views/Backtest.jsx";

// Hash routes: #/cve/CVE-2025-1234, #/watchlist, #/backtest
function parseHash() {
  const [, view = "cve", arg = ""] = window.location.hash.split("/");
  return { view: ["cve", "watchlist", "backtest"].includes(view) ? view : "cve", arg: decodeURIComponent(arg) };
}

export default function App() {
  const [route, setRoute] = useState(parseHash);
  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);
  const go = (view, arg = "") => { window.location.hash = `/${view}${arg ? `/${encodeURIComponent(arg)}` : ""}`; };

  return (
    <div className="app">
      <div className="top">
        <h1>KEV risk dashboard</h1>
        <nav className="tabs">
          {[["cve", "CVE lookup"], ["watchlist", "Blind-spot watchlist"], ["backtest", "Backtesting"]].map(([v, label]) => (
            <button key={v} className={route.view === v ? "active" : ""} onClick={() => go(v)}>{label}</button>
          ))}
        </nav>
      </div>
      <div className="design-banner">
        <span><b style={{ color: "var(--cox)" }}>Ranking: Cox</b> (frozen Cox PH partial hazard)</span>
        <span><b style={{ color: "var(--fuzzy)" }}>Explanation: fuzzy rules</b> (priority + the rules that fired)</span>
        <span className="muted">
          Every ordering here comes from Cox. The fuzzy layer did not out-rank a linear blend and lost to Cox on test,
          so it is shown only to explain why a CVE ranks where it does. Local demo; data is the historical test period.
        </span>
      </div>
      {route.view === "cve" && <CveLookup cveId={route.arg} onLookup={(id) => go("cve", id)} />}
      {route.view === "watchlist" && <Watchlist onOpenCve={(id) => go("cve", id)} />}
      {route.view === "backtest" && <Backtest />}
    </div>
  );
}
