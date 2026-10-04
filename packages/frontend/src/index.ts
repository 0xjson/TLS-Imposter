import { createApp, type App as VueApp } from "vue";
import type { Caido } from "@caido/sdk-frontend";

import AppRoot from "./App.vue";
import type { API, BackendEvents, StateDTO } from "../../backend/src/index";

export type FrontendSDK = Caido<API, BackendEvents>;

const PATH = "/tls-imposter";

export function init(sdk: FrontendSDK) {
  const root = document.createElement("div");
  root.id = "tls-imposter-root";
  root.style.height = "100%";

  const app: VueApp = createApp(AppRoot, { sdk });
  app.mount(root);

  sdk.navigation.addPage(PATH, { body: root });
  sdk.sidebar.registerItem("TLS Imposter", PATH, { icon: "fas fa-lock" });
}

export type { StateDTO };
