<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { StateDTO } from "../../../backend/src/index";

const props = defineProps<{ state: StateDTO; busy: boolean }>();
const emit = defineEmits<{ update: [patch: Record<string, unknown>] }>();

const filter = ref("");
const timeout = ref(props.state.settings.timeoutSec);

watch(
  () => props.state.settings.timeoutSec,
  (v) => {
    timeout.value = v;
  },
);

const allProfiles = computed(() =>
  props.state.helper.kind === "running" ? props.state.helper.profiles : [],
);

const profiles = computed(() => {
  const needle = filter.value.trim().toLowerCase();
  const list =
    needle === "" ? allProfiles.value : allProfiles.value.filter((p) => p.toLowerCase().includes(needle));
  // Keep the current selection reachable even when filtered out, so the
  // dropdown never silently shows a different profile than the one in use.
  const current = props.state.settings.profile;
  return list.includes(current) ? list : [current, ...list];
});

const hasCapture = computed(() => props.state.settings.capture.last !== null);
</script>

<template>
  <section class="rounded border border-surface-700 p-4 flex flex-col gap-3">
    <h2 class="font-semibold">Fingerprint</h2>

    <div class="flex gap-4 text-sm">
      <label class="flex items-center gap-2">
        <input
          type="radio"
          value="preset"
          :checked="state.settings.source === 'preset'"
          :disabled="busy"
          @change="emit('update', { source: 'preset' })"
        />
        Preset profile
      </label>
      <label class="flex items-center gap-2" :class="{ 'opacity-50': !hasCapture }">
        <input
          type="radio"
          value="captured"
          :checked="state.settings.source === 'captured'"
          :disabled="busy || !hasCapture"
          @change="emit('update', { source: 'captured' })"
        />
        Captured browser hello
      </label>
    </div>

    <p v-if="state.settings.source === 'captured'" class="text-xs opacity-60">
      The TLS hello comes from your browser; the HTTP/2 layer still comes from the profile
      below, so pick the same browser family.
    </p>

    <label class="flex flex-col gap-1 text-sm">
      <span class="opacity-70">Profile ({{ allProfiles.length }} available)</span>
      <input
        v-model="filter"
        placeholder="Filter, e.g. chrome"
        class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
      />
      <select
        class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
        :value="state.settings.profile"
        :disabled="busy"
        @change="emit('update', { profile: ($event.target as HTMLSelectElement).value })"
      >
        <option v-for="p in profiles" :key="p" :value="p">{{ p }}</option>
      </select>
    </label>

    <label class="flex flex-col gap-1 text-sm max-w-xs">
      <span class="opacity-70">Timeout (seconds)</span>
      <input
        v-model.number="timeout"
        type="number"
        min="1"
        max="600"
        :disabled="busy"
        class="px-2 py-1 rounded bg-surface-800 border border-surface-700"
        @change="emit('update', { timeoutSec: timeout })"
      />
    </label>
  </section>
</template>
