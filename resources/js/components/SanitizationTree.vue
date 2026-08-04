<script setup lang="ts">
import type { PresentationNode } from '@/lib/types';
import TreeNode from './TreeNode.vue';
import Card from '@/components/ui/Card.vue';

defineProps<{ nodes: PresentationNode[] }>();
</script>

<template>
    <Card class="overflow-hidden py-2">
        <TreeNode v-for="(node, index) in nodes" :key="index" :node="node" :depth="0" />
    </Card>
</template>
