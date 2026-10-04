import { defineConfig } from "@caido-community/dev";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  id: "tls-imposter",
  name: "TLS Imposter",
  description: "Spoof browser TLS and HTTP/2 fingerprints for Caido traffic",
  version: "0.1.0",
  author: { name: "json" },
  plugins: [
    {
      kind: "backend",
      id: "tls-imposter-backend",
      root: "packages/backend",
      assets: ["packages/backend/assets/bin/*"],
    },
    {
      kind: "frontend",
      id: "tls-imposter-frontend",
      root: "packages/frontend",
      backend: { id: "tls-imposter-backend" },
      // Vite needs this to compile .vue single-file components; without it the
      // build fails in rollup with "content contains invalid JS syntax".
      vite: { plugins: [vue()] },
    },
  ],
});
