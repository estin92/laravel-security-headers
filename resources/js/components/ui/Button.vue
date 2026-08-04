<script setup lang="ts">
import { cn } from '@/lib/utils';

withDefaults(defineProps<{ variant?: 'default' | 'outline' | 'ghost'; class?: string; type?: 'button' | 'submit'; disabled?: boolean }>(), {
    variant: 'default',
    type: 'button',
});

const variants = {
    default: 'bg-primary text-primary-foreground hover:bg-primary/90',
    outline: 'border border-input bg-background hover:bg-accent hover:text-accent-foreground',
    ghost: 'hover:bg-accent hover:text-accent-foreground',
};
</script>

<template>
    <button
        :type="type"
        :disabled="disabled"
        :class="cn(
            'inline-flex items-center justify-center gap-2 rounded-md text-sm font-medium h-9 px-4 transition-colors disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            variants[variant],
            $props.class,
        )"
    >
        <slot />
    </button>
</template>
