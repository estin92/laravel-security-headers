import { describe, expect, it } from 'vitest';
import { presentationFor } from './state-presentation';
import type { FieldState } from './types';

describe('presentationFor', () => {
    it.each([
        ['present', true],
        ['transformed', true],
        ['removed', false],
        ['unknown_action', false],
        ['not_submitted', false],
        ['empty', false],
    ] as [FieldState, boolean][])('shows the value for %s only when appropriate', (state, showsValue) => {
        expect(presentationFor(state).showsValue).toBe(showsValue);
    });

    it('never guesses a label for an unrecognized action', () => {
        expect(presentationFor('unknown_action').label).toBe('unrecognized action');
        expect(presentationFor('unknown_action').showsValue).toBe(false);
    });

    it('gives every state a non-empty label and badge class', () => {
        const states: FieldState[] = ['present', 'empty', 'transformed', 'removed', 'unknown_action', 'not_submitted'];

        for (const state of states) {
            const presentation = presentationFor(state);
            expect(presentation.label.length).toBeGreaterThan(0);
            expect(presentation.badgeClass.length).toBeGreaterThan(0);
        }
    });
});
