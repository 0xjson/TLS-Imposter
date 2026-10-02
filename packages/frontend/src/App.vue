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
let subscription: { stop: () => void } | null = null;

/** Runs a backend call, keeping the page usable if it throws. */
async function call(fn: () => Promise<StateDTO>) {
  busy.value = true;
  try {
    state.value = await fn();
  } catch (err) {
    props.sdk.window.showToast(`Awesome TLS: ${String(err)}`, { variant: "error" });
  } finally {
    busy.value = false;
  }
}

onMounted(async () => {
  // onEvent returns a handle with stop(); there is no offEvent.
  subscription = props.sdk.backend.onEvent("state", (next: StateDTO) => {
    state.value = next;
  });
  await call(() => props.sdk.backend.getState());
});

onUnmounted(() => subscription?.stop());
</script>

<template>
  <div class="p-6 flex flex-col gap-4 overflow-auto h-full">
    <header>
      <h1 class="text-xl font-semibold">Awesome TLS</h1>
      <p class="text-sm opacity-70">
        Sends routed requests with a real browser's TLS and HTTP/2 fingerprint.
      </p>
    </header>

    <p v-if="state === null" class="text-sm opacity-70">Loading…</p>

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
