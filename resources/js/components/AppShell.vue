<script setup lang="ts">
import { ShieldAlert } from 'lucide-vue-next';
</script>

<template>
    <div class="min-h-screen bg-background text-foreground">
        <header class="sticky top-0 z-10 border-b border-border bg-background/80 backdrop-blur">
            <div class="mx-auto max-w-5xl flex items-center gap-2 h-14 px-6 lg:px-8">
                <a href="#/" class="flex items-center gap-2">
                    <ShieldAlert class="size-5 text-primary" />
                    <span class="font-semibold text-sm">Security Headers</span>
                </a>
                <div class="ml-auto text-xs text-muted-foreground">
                    <slot name="header-right" />
                </div>
            </div>
        </header>

        <main class="mx-auto max-w-5xl p-6 lg:p-8">
            <slot />
        </main>
    </div>
</template>
