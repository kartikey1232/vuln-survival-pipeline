// Thin client over the local FastAPI service (proxied under /api by Vite).

async function get(path) {
  const res = await fetch(`/api${path}`);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* non-JSON error body */
    }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}

export const api = {
  cve: (id) => get(`/cve/${encodeURIComponent(id)}`),
  watchlist: ({ budget, landmarkDay, limit, offset }) => {
    const q = new URLSearchParams({ budget, limit, offset });
    if (landmarkDay) q.set("landmark_day", landmarkDay);
    return get(`/watchlist?${q}`);
  },
  backtest: () => get("/backtest"),
};
