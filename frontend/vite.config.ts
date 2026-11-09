import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const configuredApiBase =
    env.VITE_API_BASE_URL || "http://127.0.0.1:5000/api/v1";
  const apiUrl = new URL(configuredApiBase, "http://127.0.0.1:5000");
  const apiPath = apiUrl.pathname.replace(/\/+$/, "") || "/api/v1";

  return {
    plugins: [react()],
    server: {
      proxy: {
        [apiPath]: {
          target: apiUrl.origin,
          changeOrigin: true,
        },
      },
    },
  };
});
