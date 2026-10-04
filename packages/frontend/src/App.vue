<script setup lang="ts">
import { onMounted, onUnmounted, ref } from "vue";

import StatusCard from "./components/StatusCard.vue";
import FingerprintCard from "./components/FingerprintCard.vue";
import CaptureCard from "./components/CaptureCard.vue";
import type { FrontendSDK } from "./index";
import type { StateDTO } from "../../backend/src/index";

const props = defineProps<{ sdk: FrontendSDK }>();

const state = ref<StateDTO | null>(null);
const busy = ref(false);
/**
 * Set when the backend cannot be reached at all.
 *
 * Caido lets the backend component be disabled while this page stays enabled,
 * and every RPC then answers 500 ("Internal server error"). Left unhandled
 * that surfaces as a bare error dialog, so it is rendered inline instead.
 */
const unreachable = ref<string | null>(null);
let subscription: { stop: () => void } | null = null;

/** Runs a backend call, keeping the page usable if it throws. */
async function call(fn: () => Promise<StateDTO>, viaToast = true) {
  busy.value = true;
  try {
    state.value = await fn();
    unreachable.value = null;
  } catch (err) {
    const msg = String(err);
    if (state.value === null) {
      // Nothing has ever loaded, so there is no UI to annotate: explain inline.
      unreachable.value = msg;
    } else if (viaToast) {
      props.sdk.window.showToast(`TLS Imposter: ${msg}`, { variant: "error" });
    }
  } finally {
    busy.value = false;
  }
}

async function load() {
  // Subscribing can fail for the same reason a call can, so it is guarded too.
  if (subscription === null) {
    try {
      subscription = props.sdk.backend.onEvent("state", (next: StateDTO) => {
        state.value = next;
        unreachable.value = null;
      });
    } catch (err) {
      // Not fatal: the page still reflects state through its own actions, and
      // the inline panel below covers the case where nothing works at all.
      unreachable.value = String(err);
    }
  }
  await call(() => props.sdk.backend.getState(), false);
}

onMounted(load);
onUnmounted(() => subscription?.stop());
</script>

<template>
  <div class="p-6 flex flex-col gap-4 overflow-auto h-full">
    <header>
      <h1 class="text-xl font-semibold">TLS Imposter</h1>
      <p class="text-sm opacity-70">
        Sends routed requests with a real browser's TLS and HTTP/2 fingerprint.
      </p>
    </header>

    <section
      v-if="unreachable !== null"
      class="rounded border border-amber-600 p-4 flex flex-col gap-2"
    >
      <h2 class="font-semibold text-amber-500">Backend unavailable</h2>
      <p class="text-sm">
        This page cannot reach the plugin's backend. The most common reason is that the
        <strong>TLS Imposter backend component is disabled</strong> — enable it under
        Plugins, then retry.
      </p>
      <p class="text-xs opacity-60 font-mono">{{ unreachable }}</p>
      <button
        class="self-start px-3 py-1 rounded bg-surface-700 text-sm disabled:opacity-50"
        :disabled="busy"
        @click="load()"
      >
        Retry
      </button>
    </section>

    <p v-else-if="state === null" class="text-sm opacity-70">Loading…</p>

    <template v-else>
      <StatusCard
        :state="state"
        :busy="busy"
        @restart="call(() => props.sdk.backend.restartHelper())"
        @enable-routing="call(() => props.sdk.backend.enableRouting())"
      />
      <FingerprintCard
        :state="state"
        :busy="busy"
        @update="(patch) => call(() => props.sdk.backend.updateSettings(patch))"
      />
      <CaptureCard
        :state="state"
        :busy="busy"
        @update="(patch) => call(() => props.sdk.backend.updateSettings(patch))"
        @clear="call(() => props.sdk.backend.clearCapture())"
      />
    </template>
  </div>
</template>
