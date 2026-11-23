import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: { sourcemap: false, outDir: "dist" },
  server: {
    host: "127.0.0.1",
    port: 19110,
    strictPort: true,
    proxy: { "/v1": "http://127.0.0.1:19100" },
  },
});
