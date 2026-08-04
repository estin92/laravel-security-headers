<script setup lang="ts">
import { cn } from '@/lib/utils';

const props = defineProps<{ class?: string; modelValue?: string; placeholder?: string }>();
const emit = defineEmits<{ 'update:modelValue': [value: string] }>();
</script>

<template>
    <input
        :value="modelValue"
        :placeholder="placeholder"
        :class="cn(
            'flex h-9 w-full rounded-md border border-input bg-background px-3 py-1 text-sm shadow-sm transition-colors placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            props.class,
        )"
        @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    />
</template>
