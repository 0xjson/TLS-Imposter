<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { StateDTO } from "../../../backend/src/index";

const props = defineProps<{ state: StateDTO; busy: boolean }>();
const emit = defineEmits<{ update: [patch: Record<string, unknown>]; clear: [] }>();

const listen = ref(props.state.settings.capture.listen);
const forwardTo = ref(props.state.settings.capture.forwardTo);

watch(
  () => props.state.settings.capture.listen,
  (v) => {
    listen.value = v;
  },
);
watch(
  () => props.state.settings.capture.forwardTo,
  (v) => {
    forwardTo.value = v;
  },
);

const captureLabel = computed(() => {
  const c = props.state.capture;
  switch (c.state) {
    case "listening":
      return `Listening on ${c.listen ?? listen.value}`;
    case "error":
      return `Error: ${c.error ?? "unknown"}`;
    case "stopped":
      return "Not listening";
  }
});

const captureTone = computed(() =>
  props.state.capture.state === "listening"
    ? "text-green-500"
    : props.state.capture.state === "error"
      ? "text-red-500"
      : "opacity-70",
);

const last = computed(() => props.state.settings.capture.last);
</script>

<template>
  <section class="rounded border border-surface-700 p-4 flex flex-col gap-3">
    <h2 class="font-semibold">Capture your browser's fingerprint</h2>

    <label class="flex items-center gap-2 text-sm">
      <input
        type="checkbox"
        :checked="state.settings.capture.enabled"
        :disabled="busy"
        @change="
          emit('update', {
            capture: { enabled: ($event.target as HTMLInputElement).checked },
          })
        "
      />
      Enable the capture listener
    </label>

    <p class="text-sm" :class="captureTone">{{ captureLabel }}</p>

    <div class="grid grid-cols-2 gap-3 max-w-xl text-sm">
      <label class="flex flex-col gap-1">
        <span class="opacity-70">Listen on</span>
        <input
          v-model="listen"
          :disabled="busy"
          class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
          @change="emit('update', { capture: { listen } })"
        />
      </label>
      <label class="flex flex-col gap-1">
        <span class="opacity-70">Forward to Caido at</span>
        <input
          v-model="forwardTo"
          :disabled="busy"
          class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
          @change="emit('update', { capture: { forwardTo } })"
        />
      </label>
    </div>

    <p class="text-xs opacity-60">
      Point your browser's proxy at the listen address instead of Caido. Traffic passes
      straight through while the first TLS hello is recorded. Both addresses must be loopback.
    </p>

    <div v-if="last !== null" class="text-xs flex flex-col gap-1 font-mono">
      <span class="opacity-70 font-sans">Last capture — {{ last.capturedAt }}</span>
      <span>JA3 {{ last.ja3 }}</span>
      <span>JA4 {{ last.ja4 }}</span>
      <span class="opacity-70 font-sans">{{ last.clientHello.length / 2 }} bytes</span>
      <button
        class="self-start mt-1 px-3 py-1 rounded bg-surface-700 font-sans disabled:opacity-50"
        :disabled="busy"
        @click="emit('clear')"
      >
        Clear
      </button>
    </div>
    <p v-else class="text-xs opacity-60">Nothing captured yet.</p>
  </section>
</template>
