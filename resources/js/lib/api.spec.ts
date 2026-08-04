import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError, fetchFeed, fetchIncident, fetchReport } from './api';

function mockFetch(response: Partial<Response> & { jsonBody?: unknown; jsonThrows?: boolean }): typeof fetch {
    return vi.fn(async () =>
        ({
            ok: response.ok ?? true,
            status: response.status ?? 200,
            json: async () => {
                if (response.jsonThrows) {
                    throw new Error('not json');
                }
                return response.jsonBody ?? {};
            },
        }) as Response,
    );
}

beforeEach(() => {
    document.body.innerHTML = '<div id="security-headers-viewer" data-base-path="/base"></div>';
});

afterEach(() => {
    vi.restoreAllMocks();
});

describe('api client', () => {
    it('builds the feed URL from the shell base path and omits empty filters', async () => {
        const fetchSpy = mockFetch({ jsonBody: { data: [], next_cursor: null } });
        vi.stubGlobal('fetch', fetchSpy);

        await fetchFeed({ type: 'csp-violation', protocol: '', limit: 50 });

        expect(fetchSpy).toHaveBeenCalledWith(
            '/base/api/reports?type=csp-violation&limit=50',
            expect.objectContaining({ credentials: 'same-origin' }),
        );
    });

    it('falls back to the default base path when the mount element is absent', async () => {
        document.body.innerHTML = '';
        const fetchSpy = mockFetch({ jsonBody: { data: [], next_cursor: null } });
        vi.stubGlobal('fetch', fetchSpy);

        await fetchFeed({});

        expect(fetchSpy).toHaveBeenCalledWith(
            '/security-headers/reports/api/reports',
            expect.anything(),
        );
    });

    it('throws an ApiRequestError carrying the server error code and message', async () => {
        vi.stubGlobal('fetch', mockFetch({ ok: false, status: 422, jsonBody: { error: 'invalid_filter', message: 'Bad filter.' } }));

        await expect(fetchFeed({})).rejects.toMatchObject({
            status: 422,
            code: 'invalid_filter',
            message: 'Bad filter.',
        });
        await expect(fetchFeed({})).rejects.toBeInstanceOf(ApiRequestError);
    });

    it('does not crash on a non-JSON error body, falling back to a generic error', async () => {
        vi.stubGlobal('fetch', mockFetch({ ok: false, status: 500, jsonThrows: true }));

        await expect(fetchFeed({})).rejects.toMatchObject({ status: 500, code: 'request_failed' });
    });

    it('fetches a report detail by id', async () => {
        const fetchSpy = mockFetch({ jsonBody: { data: {} } });
        vi.stubGlobal('fetch', fetchSpy);

        await fetchReport(42);

        expect(fetchSpy).toHaveBeenCalledWith('/base/api/reports/42', expect.anything());
    });

    it('fetches an incident by fingerprint and passes a cursor', async () => {
        const fetchSpy = mockFetch({ jsonBody: { data: [], next_cursor: null } });
        vi.stubGlobal('fetch', fetchSpy);

        await fetchIncident('abc', 'cursor-token');

        expect(fetchSpy).toHaveBeenCalledWith('/base/api/incidents/abc?cursor=cursor-token', expect.anything());
    });
});
