import { defineComponent, h } from 'vue';
import { cn } from '@/lib/utils';

export const TableHeader = defineComponent({
    name: 'TableHeader',
    setup: (_, { slots }) => () => h('thead', { class: '[&_tr]:border-b' }, slots.default?.()),
});

export const TableBody = defineComponent({
    name: 'TableBody',
    setup: (_, { slots }) => () => h('tbody', { class: '[&_tr:last-child]:border-0' }, slots.default?.()),
});

export const TableRow = defineComponent({
    name: 'TableRow',
    props: { class: { type: String, default: '' } },
    setup: (props, { slots }) => () =>
        h('tr', { class: cn('border-b transition-colors hover:bg-muted/50', props.class) }, slots.default?.()),
});

export const TableHead = defineComponent({
    name: 'TableHead',
    props: { class: { type: String, default: '' } },
    setup: (props, { slots }) => () =>
        h(
            'th',
            { class: cn('h-10 px-4 text-left align-middle text-xs font-medium uppercase tracking-wide text-muted-foreground', props.class) },
            slots.default?.(),
        ),
});

export const TableCell = defineComponent({
    name: 'TableCell',
    props: { class: { type: String, default: '' } },
    setup: (props, { slots }) => () =>
        h('td', { class: cn('px-4 py-3 align-middle', props.class) }, slots.default?.()),
});
