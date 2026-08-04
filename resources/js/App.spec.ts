import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { flushPromises, mount } from '@vue/test-utils';
import App from './App.vue';
import * as api from '@/lib/api';

function setHash(hash: string): void {
    window.location.hash = hash;
    window.dispatchEvent(new HashChangeEvent('hashchange'));
}

beforeEach(() => {
    vi.spyOn(api, 'fetchFeed').mockResolvedValue({ data: [], next_cursor: null });
    vi.spyOn(api, 'fetchReport').mockResolvedValue({
        data: {
            id: 7,
            tree: [],
            context: { type: 'csp-violation', protocol: 'p', url_origin: null, age: null, received_at: 'r', incident_fingerprint: 'f' },
            raw_mode: false,
            raw_warning: false,
            provenance: { sanitizer_version: 'v', label: 'Sanitized by v' },
        },
    });
    vi.spyOn(api, 'fetchIncident').mockResolvedValue({ data: [], next_cursor: null });
});

afterEach(() => {
    setHash('#/');
    vi.restoreAllMocks();
});

describe('App router', () => {
    it('shows the feed for the root hash', async () => {
        setHash('#/');
        const wrapper = mount(App);
        await flushPromises();

        expect(wrapper.text()).toContain('Browser security violations');
    });

    it('routes a numeric report hash to the detail view', async () => {
        setHash('#/reports/7');
        const wrapper = mount(App);
        await flushPromises();

        expect(api.fetchReport).toHaveBeenCalledWith(7);
        expect(wrapper.text()).toContain('All reports');
    });

    it('routes a 64-hex fingerprint hash to the incident view', async () => {
        const fingerprint = 'a'.repeat(64);
        setHash(`#/incidents/${fingerprint}`);
        const wrapper = mount(App);
        await flushPromises();

        expect(api.fetchIncident).toHaveBeenCalledWith(fingerprint, undefined);
        expect(wrapper.text()).toContain('Incident');
    });

    it('falls back to the feed for an unrecognized hash', async () => {
        setHash('#/nonsense/../../etc');
        const wrapper = mount(App);
        await flushPromises();

        expect(wrapper.text()).toContain('Browser security violations');
        expect(api.fetchReport).not.toHaveBeenCalled();
    });

    it('falls back to the feed for a non-hex fingerprint', async () => {
        setHash('#/incidents/NOThex');
        const wrapper = mount(App);
        await flushPromises();

        expect(api.fetchIncident).not.toHaveBeenCalled();
        expect(wrapper.text()).toContain('Browser security violations');
    });
});
