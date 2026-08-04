import { describe, expect, it } from 'vitest';
import { mount } from '@vue/test-utils';
import TreeNode from './TreeNode.vue';
import type { PresentationNode } from '@/lib/types';

function node(overrides: Partial<PresentationNode>): PresentationNode {
    return {
        path: ['body', 'field'],
        key: 'field',
        state: 'present',
        value: null,
        value_type: 'null',
        action: null,
        truncated: false,
        children: null,
        children_omitted: 0,
        ...overrides,
    };
}

describe('TreeNode', () => {
    it('renders an attacker-controlled value as inert text, never as HTML', () => {
        const wrapper = mount(TreeNode, {
            props: { node: node({ value: '<script>alert(1)</script>', value_type: 'string' }), depth: 0 },
        });

        expect(wrapper.html()).not.toContain('<script>alert(1)</script>');
        expect(wrapper.text()).toContain('<script>alert(1)</script>');
        expect(wrapper.find('script').exists()).toBe(false);
    });

    it('escapes an attacker-controlled key and action label', () => {
        const wrapper = mount(TreeNode, {
            props: {
                node: node({ key: '<img src=x onerror=1>', action: '<b>x</b>', state: 'transformed', value: 'v', value_type: 'string' }),
                depth: 0,
            },
        });

        expect(wrapper.find('img').exists()).toBe(false);
        expect(wrapper.text()).toContain('<img src=x onerror=1>');
    });

    it.each([
        ['transformed', 'transformed', true],
        ['removed', 'removed', false],
        ['unknown_action', 'unrecognized action', false],
    ] as const)('badges the changed %s state with its distinct label', (state, label, showsValue) => {
        const wrapper = mount(TreeNode, {
            props: { node: node({ state, value: showsValue ? 'kept-value' : null, value_type: showsValue ? 'string' : 'null', action: 'strip_query' }), depth: 0 },
        });

        expect(wrapper.text()).toContain(label);
        if (showsValue) {
            expect(wrapper.text()).toContain('kept-value');
        } else {
            expect(wrapper.text()).toContain('withheld');
        }
    });

    it('renders a present field quietly, showing its value with no state badge', () => {
        const wrapper = mount(TreeNode, {
            props: { node: node({ state: 'present', value: 'kept-value', value_type: 'string' }), depth: 0 },
        });

        expect(wrapper.text()).toContain('kept-value');
        expect(wrapper.text()).not.toContain('present');
    });

    it('renders a not-submitted field as a quiet dash with no badge', () => {
        const wrapper = mount(TreeNode, {
            props: { node: node({ state: 'not_submitted' }), depth: 0 },
        });

        expect(wrapper.text()).not.toContain('not submitted');
        expect(wrapper.text()).toContain('—');
    });

    it('surfaces the children-omitted cap notice', () => {
        const wrapper = mount(TreeNode, {
            props: {
                node: node({
                    value_type: 'object',
                    children: [node({ key: 'a', value: '1', value_type: 'string' })],
                    children_omitted: 7,
                }),
                depth: 0,
            },
        });

        expect(wrapper.text()).toContain('+7 more');
    });
});
