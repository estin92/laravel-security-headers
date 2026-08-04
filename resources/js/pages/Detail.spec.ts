import { afterEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import Detail from './Detail.vue';
import * as api from '@/lib/api';
import type { ReportDetail } from '@/lib/types';

function detail(overrides: Partial<ReportDetail> = {}): ReportDetail {
    return {
        id: 1,
        tree: [
            { path: ['body', 'blockedURL'], key: 'blockedURL', state: 'present', value: 'https://evil/x', value_type: 'string', action: null, truncated: false, children: null, children_omitted: 0 },
        ],
        context: { type: 'csp-violation', protocol: 'reporting-api', url_origin: 'https://x', age: 1, received_at: '2026-08-03T00:00:00Z', incident_fingerprint: 'f'.repeat(64) },
        raw_mode: false,
        raw_warning: false,
        provenance: { sanitizer_version: 'v1', label: 'Sanitized by security-headers (v1)' },
        ...overrides,
    };
}

afterEach(() => vi.restoreAllMocks());

describe('Detail', () => {
    it('renders the tree, provenance label and incident link', async () => {
        vi.spyOn(api, 'fetchReport').mockResolvedValue({ data: detail() });

        const wrapper = mount(Detail, { props: { id: 1 } });
        await flushPromises();

        expect(wrapper.text()).toContain('blockedURL');
        expect(wrapper.text()).toContain('https://evil/x');
        expect(wrapper.text()).toContain('Sanitized by security-headers (v1)');
        expect(wrapper.find(`a[href="#/incidents/${'f'.repeat(64)}"]`).exists()).toBe(true);
    });

    it('shows the raw-storage warning only when raw_warning is set', async () => {
        vi.spyOn(api, 'fetchReport').mockResolvedValue({ data: detail({ raw_mode: true, raw_warning: true }) });

        const wrapper = mount(Detail, { props: { id: 1 } });
        await flushPromises();

        expect(wrapper.text()).toContain('Raw storage');
    });

    it('hides the raw warning for a sanitized report', async () => {
        vi.spyOn(api, 'fetchReport').mockResolvedValue({ data: detail() });

        const wrapper = mount(Detail, { props: { id: 1 } });
        await flushPromises();

        expect(wrapper.text()).not.toContain('Raw storage');
    });

    it('shows an error message when the report cannot be loaded', async () => {
        vi.spyOn(api, 'fetchReport').mockRejectedValue(new api.ApiRequestError(404, 'not_found', 'The requested report is no longer available.'));

        const wrapper = mount(Detail, { props: { id: 999 } });
        await flushPromises();

        expect(wrapper.text()).toContain('no longer available');
    });
});
