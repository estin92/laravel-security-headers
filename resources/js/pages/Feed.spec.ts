import { afterEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import Feed from './Feed.vue';
import * as api from '@/lib/api';

afterEach(() => {
    vi.restoreAllMocks();
});

describe('Feed', () => {
    it('lists reports fetched on mount', async () => {
        vi.spyOn(api, 'fetchFeed').mockResolvedValue({
            data: [
                { id: 1, type: 'csp-violation', protocol: 'reporting-api', url_origin: 'https://x', received_at: '2026-08-03T00:00:00Z', incident_fingerprint: 'a'.repeat(64) },
            ],
            next_cursor: null,
        });

        const wrapper = mount(Feed);
        await flushPromises();

        expect(wrapper.text()).toContain('csp-violation');
        expect(wrapper.text()).toContain('https://x');

        await wrapper.find('tbody tr').trigger('click');
        expect(window.location.hash).toBe('#/reports/1');
    });

    it('shows the empty state when no reports match', async () => {
        vi.spyOn(api, 'fetchFeed').mockResolvedValue({ data: [], next_cursor: null });

        const wrapper = mount(Feed);
        await flushPromises();

        expect(wrapper.text()).toContain('No reports match');
    });

    it('discards the cursor and refetches from scratch when filters change', async () => {
        const fetchFeed = vi.spyOn(api, 'fetchFeed')
            .mockResolvedValueOnce({ data: [], next_cursor: 'cursor-1' })
            .mockResolvedValue({ data: [], next_cursor: null });

        const wrapper = mount(Feed);
        await flushPromises();

        await wrapper.find('input').setValue('csp-violation');
        await wrapper.findAll('button').find((b) => b.text() === 'Apply')!.trigger('click');
        await flushPromises();

        const lastCall = fetchFeed.mock.calls.at(-1)![0];
        expect(lastCall.cursor).toBeUndefined();
        expect(lastCall.type).toBe('csp-violation');
    });

    it('shows an error message when the request fails', async () => {
        vi.spyOn(api, 'fetchFeed').mockRejectedValue(new api.ApiRequestError(422, 'invalid_filter', 'Bad filter.'));

        const wrapper = mount(Feed);
        await flushPromises();

        expect(wrapper.text()).toContain('Bad filter.');
    });

    it('appends the next page and keeps the earlier rows on load-more', async () => {
        vi.spyOn(api, 'fetchFeed')
            .mockResolvedValueOnce({
                data: [{ id: 1, type: 'a', protocol: 'p', url_origin: null, received_at: 'r', incident_fingerprint: 'f' }],
                next_cursor: 'cursor-1',
            })
            .mockResolvedValueOnce({
                data: [{ id: 2, type: 'b', protocol: 'p', url_origin: null, received_at: 'r', incident_fingerprint: 'f' }],
                next_cursor: null,
            });

        const wrapper = mount(Feed);
        await flushPromises();

        await wrapper.findAll('button').find((b) => b.text().includes('Load more'))!.trigger('click');
        await flushPromises();

        const rows = wrapper.findAll('tbody tr');
        expect(rows).toHaveLength(2);
        expect(wrapper.text()).toContain('a');
        expect(wrapper.text()).toContain('b');
    });
});
