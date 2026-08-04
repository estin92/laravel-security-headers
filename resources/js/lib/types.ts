export type FieldState =
    | 'present'
    | 'empty'
    | 'transformed'
    | 'removed'
    | 'unknown_action'
    | 'not_submitted';

export type ValueType = 'object' | 'list' | 'string' | 'number' | 'boolean' | 'null';

export interface PresentationNode {
    path: (string | number)[];
    key: string;
    state: FieldState;
    value: string | number | boolean | null;
    value_type: ValueType;
    action: string | null;
    truncated: boolean;
    children: PresentationNode[] | null;
    children_omitted: number;
}

export interface ReportSummary {
    id: number;
    type: string;
    protocol: string;
    url_origin: string | null;
    received_at: string;
    incident_fingerprint: string;
}

export interface ReportDetail {
    id: number;
    tree: PresentationNode[];
    context: {
        type: string;
        protocol: string;
        url_origin: string | null;
        age: number | null;
        received_at: string;
        incident_fingerprint: string;
    };
    raw_mode: boolean;
    raw_warning: boolean;
    provenance: {
        sanitizer_version: string;
        label: string;
    };
}

export interface Feed {
    data: ReportSummary[];
    next_cursor: string | null;
}

export interface ApiError {
    error: string;
    message: string;
}
