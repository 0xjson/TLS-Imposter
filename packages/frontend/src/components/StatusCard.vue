<script setup lang="ts">
import { computed } from "vue";
import type { StateDTO } from "../../../backend/src/index";

const props = defineProps<{ state: StateDTO; busy: boolean }>();
defineEmits<{ restart: []; "enable-routing": [] }>();

const helperLabel = computed(() => {
  const h = props.state.helper;
  switch (h.kind) {
    case "running":
      return `Running on 127.0.0.1:${h.port} (helper ${h.version})`;
    case "starting":
      return "Starting…";
    case "restarting":
      return `Restarting after failure ${h.attempt}: ${h.error}`;
    case "failed":
      return `Failed: ${h.error}`;
    case "stopped":
      return "Stopped";
  }
});

const helperTone = computed(() => {
  switch (props.state.helper.kind) {
    case "running":
      return "text-green-500";
    case "failed":
      return "text-red-500";
    default:
      return "text-amber-500";
  }
});

const canRestart = computed(
  () => props.state.helper.kind === "failed" || props.state.helper.kind === "stopped",
);

const routingLabel = computed(() => {
  const r = props.state.routing;
  if (r === null) return "No routing rule: no traffic reaches this plugin yet.";
  if (!r.enabled) return "Routing rule exists but is disabled.";
  const allow = r.allowlist.length === 0 ? "(none)" : r.allowlist.join(", ");
  const deny = r.denylist.length === 0 ? "" : ` — excluding ${r.denylist.join(", ")}`;
  return `Routing ${allow}${deny}`;
});

const routingActive = computed(() => props.state.routing?.enabled === true);
</script>

<template>
  <section class="rounded border border-surface-700 p-4 flex flex-col gap-3">
    <h2 class="font-semibold">Status</h2>

    <div class="flex items-center gap-2 text-sm">
      <span class="opacity-70 w-20 shrink-0">Helper</span>
      <span :class="helperTone">{{ helperLabel }}</span>
      <button
        v-if="canRestart"
        class="ml-auto px-3 py-1 rounded bg-surface-700 text-sm disabled:opacity-50"
        :disabled="busy"
        @click="$emit('restart')"
      >
        Restart
      </button>
    </div>

    <div class="flex items-center gap-2 text-sm">
      <span class="opacity-70 w-20 shrink-0">Routing</span>
      <span :class="routingActive ? 'text-green-500' : 'text-amber-500'">{{ routingLabel }}</span>
      <button
        v-if="!routingActive"
        class="ml-auto px-3 py-1 rounded bg-primary-600 text-sm disabled:opacity-50"
        :disabled="busy"
        @click="$emit('enable-routing')"
      >
        Enable for all domains
      </button>
    </div>

    <p class="text-xs opacity-60">
      Per-domain rules live in Settings → Upstream → Upstream Plugins. Caido's own upstream
      proxy does not apply to routed traffic: the helper opens the outbound connection itself.
      If the helper is down, routed requests are answered with a 502 rather than sent with
      Caido's own fingerprint.
    </p>

    <ul v-if="state.warnings.length > 0" class="text-xs text-amber-500 list-disc pl-5">
      <li v-for="w in state.warnings" :key="w">{{ w }}</li>
    </ul>
  </section>
</template>
