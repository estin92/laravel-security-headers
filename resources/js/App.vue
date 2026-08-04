<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import Feed from '@/pages/Feed.vue';
import Detail from '@/pages/Detail.vue';
import Incident from '@/pages/Incident.vue';
import AppShell from '@/components/AppShell.vue';

const hash = ref(window.location.hash || '#/');

function onHashChange(): void {
    hash.value = window.location.hash || '#/';
}

onMounted(() => window.addEventListener('hashchange', onHashChange));
onUnmounted(() => window.removeEventListener('hashchange', onHashChange));

const route = computed(() => {
    const detail = hash.value.match(/^#\/reports\/(\d+)$/);
    if (detail) {
        return { name: 'detail', id: Number(detail[1]) } as const;
    }

    const incident = hash.value.match(/^#\/incidents\/([0-9a-f]{64})$/);
    if (incident) {
        return { name: 'incident', fingerprint: incident[1] } as const;
    }

    return { name: 'feed' } as const;
});
</script>

<template>
    <AppShell>
        <Detail v-if="route.name === 'detail'" :id="route.id" :key="route.id" />
        <Incident v-else-if="route.name === 'incident'" :fingerprint="route.fingerprint" :key="route.fingerprint" />
        <Feed v-else />
    </AppShell>
</template>
