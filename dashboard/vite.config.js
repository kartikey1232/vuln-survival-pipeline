import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Local demo only: the API runs at 127.0.0.1:8000 (uv run uvicorn api.main:app),
// proxied under /api so the browser never needs CORS.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});
