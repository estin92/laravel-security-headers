<script setup lang="ts">
import { computed, ref } from 'vue';
import { ChevronRight } from 'lucide-vue-next';
import type { PresentationNode } from '@/lib/types';
import { presentationFor } from '@/lib/state-presentation';
import { cn } from '@/lib/utils';
import Badge from '@/components/ui/Badge.vue';

const props = defineProps<{ node: PresentationNode; depth: number }>();

const open = ref(true);
const hasChildren = computed(() => (props.node.children?.length ?? 0) > 0);
const presentation = computed(() => presentationFor(props.node.state));

function toggle(): void {
    if (hasChildren.value) {
        open.value = !open.value;
    }
}
</script>

<template>
    <div>
        <div
            :class="cn(
                'group relative flex items-baseline gap-3 py-2 pr-4',
                !presentation.quiet && 'bg-muted/30',
                hasChildren && 'cursor-pointer hover:bg-muted/50',
            )"
            :style="{ paddingLeft: `${depth * 22 + 20}px` }"
            @click="toggle"
        >
            <span
                v-if="presentation.stripeClass"
                :class="cn('absolute left-0 top-0 bottom-0 w-[3px]', presentation.stripeClass)"
                aria-hidden="true"
            ></span>

            <button
                v-if="hasChildren"
                type="button"
                class="shrink-0 -ml-6 text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring rounded"
                :aria-expanded="open"
                @click.stop="toggle"
            >
                <ChevronRight :class="cn('size-4 transition-transform', open && 'rotate-90')" />
            </button>

            <span :class="cn('shrink-0 w-44 text-sm truncate', hasChildren ? 'font-semibold' : 'font-medium text-foreground/80')">
                {{ node.key }}
            </span>

            <Badge v-if="!presentation.quiet" :class="cn('shrink-0', presentation.badgeClass)">{{ presentation.label }}</Badge>

            <div class="min-w-0 flex-1 text-sm leading-relaxed">
                <span v-if="presentation.showsValue && node.value !== null" class="font-mono break-all text-foreground">
                    {{ node.value }}<span v-if="node.truncated" class="ml-1 text-xs text-muted-foreground">…truncated</span>
                </span>
                <span v-else-if="presentation.quiet" class="text-muted-foreground/60">—</span>
                <span v-else class="text-muted-foreground">withheld</span>
            </div>

            <code v-if="node.action" class="shrink-0 self-center rounded bg-muted px-1.5 py-0.5 text-xs text-amber-700 dark:text-amber-500">{{ node.action }}</code>
        </div>

        <template v-if="hasChildren && open">
            <TreeNode v-for="(child, index) in node.children" :key="index" :node="child" :depth="depth + 1" />
            <div
                v-if="node.children_omitted > 0"
                class="text-xs text-muted-foreground py-2"
                :style="{ paddingLeft: `${(depth + 1) * 22 + 44}px` }"
            >
                +{{ node.children_omitted }} more (capped for display)
            </div>
        </template>
    </div>
</template>
