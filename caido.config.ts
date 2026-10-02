import { defineConfig } from "@caido-community/dev";

export default defineConfig({
  id: "awesome-tls",
  name: "Awesome TLS",
  description: "Spoof browser TLS and HTTP/2 fingerprints for Caido traffic",
  version: "0.1.0",
  author: { name: "json" },
  plugins: [
    {
      kind: "backend",
      id: "awesome-tls-backend",
      root: "packages/backend",
      assets: ["packages/backend/assets/bin/*"],
    },
    {
      kind: "frontend",
      id: "awesome-tls-frontend",
      root: "packages/frontend",
      backend: { id: "awesome-tls-backend" },
    },
  ],
});
