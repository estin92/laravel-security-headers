import type { Feed, ReportDetail } from './types';

function basePath(): string {
    const el = document.getElementById('security-headers-viewer');
    return el?.dataset.basePath ?? '/security-headers/reports';
}

async function getJson<T>(url: string): Promise<T> {
    const response = await fetch(url, {
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
    });

    if (!response.ok) {
        const body = await response.json().catch(() => ({ error: 'request_failed', message: 'Request failed.' }));
        throw new ApiRequestError(response.status, body.error ?? 'request_failed', body.message ?? 'Request failed.');
    }

    return response.json() as Promise<T>;
}

export class ApiRequestError extends Error {
    constructor(
        public readonly status: number,
        public readonly code: string,
        message: string,
    ) {
        super(message);
    }
}

export interface FeedQuery {
    type?: string;
    protocol?: string;
    url_origin?: string;
    received_from?: string;
    received_to?: string;
    limit?: number;
    cursor?: string;
}

function query(params: FeedQuery): string {
    const search = new URLSearchParams();

    for (const [key, value] of Object.entries(params)) {
        if (value !== undefined && value !== null && value !== '') {
            search.set(key, String(value));
        }
    }

    const string = search.toString();
    return string === '' ? '' : `?${string}`;
}

export function fetchFeed(params: FeedQuery): Promise<Feed> {
    return getJson<Feed>(`${basePath()}/api/reports${query(params)}`);
}

export function fetchReport(id: number): Promise<{ data: ReportDetail }> {
    return getJson<{ data: ReportDetail }>(`${basePath()}/api/reports/${id}`);
}

export function fetchIncident(fingerprint: string, cursor?: string): Promise<Feed> {
    return getJson<Feed>(`${basePath()}/api/incidents/${fingerprint}${query({ cursor })}`);
}
