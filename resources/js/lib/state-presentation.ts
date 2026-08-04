import type { FieldState } from './types';

export interface StatePresentation {
    label: string;
    /** State colour, deliberately off the neutral UI accent so a changed field reads at a glance. */
    badgeClass: string;
    stripeClass: string | null;
    showsValue: boolean;
    /** Unchanged states render with no badge or stripe, so the ones that altered the data stand out. */
    quiet: boolean;
}

const PRESENTATIONS: Record<FieldState, StatePresentation> = {
    present: {
        label: 'present',
        badgeClass: 'border-border bg-muted text-muted-foreground',
        stripeClass: null,
        showsValue: true,
        quiet: true,
    },
    empty: {
        label: 'empty',
        badgeClass: 'border-border bg-muted text-muted-foreground',
        stripeClass: null,
        showsValue: false,
        quiet: true,
    },
    transformed: {
        label: 'transformed',
        badgeClass: 'border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-400',
        stripeClass: 'bg-amber-500',
        showsValue: true,
        quiet: false,
    },
    removed: {
        label: 'removed',
        badgeClass: 'border-red-200 bg-red-50 text-red-700 dark:border-red-900 dark:bg-red-950 dark:text-red-400',
        stripeClass: 'bg-red-500',
        showsValue: false,
        quiet: false,
    },
    unknown_action: {
        label: 'unrecognized action',
        badgeClass: 'border-violet-200 bg-violet-50 text-violet-700 dark:border-violet-900 dark:bg-violet-950 dark:text-violet-400',
        stripeClass: 'bg-violet-500',
        showsValue: false,
        quiet: false,
    },
    not_submitted: {
        label: 'not submitted',
        badgeClass: 'border-border bg-transparent text-muted-foreground',
        stripeClass: null,
        showsValue: false,
        quiet: true,
    },
};

export function presentationFor(state: FieldState): StatePresentation {
    return PRESENTATIONS[state];
}
