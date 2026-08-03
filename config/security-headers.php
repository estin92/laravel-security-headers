<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\StrictPolicy;
use Estin92\SecurityHeaders\PermissionsPolicy\Keyword;
use Estin92\SecurityHeaders\Reporting\Ingestion\ReportType;
use Estin92\SecurityHeaders\Support\IntegerConfig;

return [

    'auto_register' => env('SECURITY_HEADERS_AUTO_REGISTER', true),

    'headers' => [
        'x_frame_options' => [
            'enabled' => env('SECURITY_HEADERS_X_FRAME_OPTIONS_ENABLED', true),
            'value' => env('SECURITY_HEADERS_X_FRAME_OPTIONS', 'DENY'),
        ],

        'x_content_type_options' => [
            'enabled' => env('SECURITY_HEADERS_X_CONTENT_TYPE_OPTIONS_ENABLED', true),
            'value' => env('SECURITY_HEADERS_X_CONTENT_TYPE_OPTIONS', 'nosniff'),
        ],

        'referrer_policy' => [
            'enabled' => env('SECURITY_HEADERS_REFERRER_POLICY_ENABLED', true),
            'value' => env('SECURITY_HEADERS_REFERRER_POLICY', 'strict-origin-when-cross-origin'),
        ],

        'x_xss_protection' => [
            'enabled' => env('SECURITY_HEADERS_X_XSS_PROTECTION_ENABLED', true),
            'value' => env('SECURITY_HEADERS_X_XSS_PROTECTION', '0'),
        ],

        'cross_origin_resource_policy' => [
            'enabled' => env('SECURITY_HEADERS_CROSS_ORIGIN_RESOURCE_POLICY_ENABLED', true),
            'value' => env('SECURITY_HEADERS_CROSS_ORIGIN_RESOURCE_POLICY', 'same-origin'),
        ],
    ],

    'hsts' => [
        'enabled' => env('SECURITY_HEADERS_HSTS_ENABLED', false),
        'max_age' => env('SECURITY_HEADERS_HSTS_MAX_AGE', 31536000),
        'include_subdomains' => env('SECURITY_HEADERS_HSTS_INCLUDE_SUBDOMAINS', true),
        'preload' => env('SECURITY_HEADERS_HSTS_PRELOAD', false),
    ],

    'permissions_policy' => [
        'enabled' => env('SECURITY_HEADERS_PERMISSIONS_POLICY_ENABLED', true),
        'features' => [
            'accelerometer' => [],
            'autoplay' => [],
            'camera' => [],
            'display-capture' => [],
            'encrypted-media' => [],
            'fullscreen' => [Keyword::Self],
            'geolocation' => [],
            'gyroscope' => [],
            'magnetometer' => [],
            'microphone' => [],
            'midi' => [],
            'payment' => [],
            'picture-in-picture' => [],
            'publickey-credentials-create' => [Keyword::Self],
            'publickey-credentials-get' => [Keyword::Self],
            'screen-wake-lock' => [],
            'serial' => [],
            'usb' => [],
            'xr-spatial-tracking' => [],
        ],
    ],

    'coep' => [
        'enforce' => [
            'enabled' => env('SECURITY_HEADERS_CROSS_ORIGIN_EMBEDDER_POLICY_ENABLED', false),
            'value' => env('SECURITY_HEADERS_CROSS_ORIGIN_EMBEDDER_POLICY', 'require-corp'),
            // Optional: the name of a reporting.endpoints entry, e.g. 'coep'.
            'reporting_endpoint' => null,
            // Optional: the name of a reporting.report_to_groups entry (legacy Report-To).
            'report_to_group' => null,
        ],
        'report_only' => [
            'enabled' => env('SECURITY_HEADERS_CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY_ENABLED', false),
            'value' => env('SECURITY_HEADERS_CROSS_ORIGIN_EMBEDDER_POLICY_REPORT_ONLY', 'require-corp'),
            // The name of a reporting.endpoints entry, e.g. 'coep'. Required when this
            // channel is enabled — a report-only header without an endpoint reports nothing.
            'reporting_endpoint' => null,
            // Optional: the name of a reporting.report_to_groups entry (legacy Report-To).
            'report_to_group' => null,
        ],
    ],

    'coop' => [
        'enforce' => [
            'enabled' => env('SECURITY_HEADERS_CROSS_ORIGIN_OPENER_POLICY_ENABLED', true),
            'value' => env('SECURITY_HEADERS_CROSS_ORIGIN_OPENER_POLICY', 'same-origin'),
            // Optional: a reporting.endpoints entry name (modern Reporting-Endpoints).
            'reporting_endpoint' => null,
            // Optional: a reporting.report_to_groups entry key (legacy Report-To).
            'report_to_group' => null,
        ],
        'report_only' => [
            'enabled' => env('SECURITY_HEADERS_CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY_ENABLED', false),
            'value' => env('SECURITY_HEADERS_CROSS_ORIGIN_OPENER_POLICY_REPORT_ONLY', 'same-origin'),
            // Required when enabled — a report-only header with no destination reports
            // nothing. noopener-allow-popups is not a valid report-only value.
            'reporting_endpoint' => null,
            'report_to_group' => null,
        ],
    ],

    'csp' => [
        'skip_when_vite_hot' => env('SECURITY_HEADERS_CSP_SKIP_WHEN_VITE_HOT', true),
        'enforce' => [
            'enabled' => env('SECURITY_HEADERS_CSP_ENABLED', false),
            'policy' => StrictPolicy::class,
            // Optional: the name of a reporting.report_to_groups entry (legacy Report-To).
            'report_to_group' => null,
        ],
        'report_only' => [
            'enabled' => env('SECURITY_HEADERS_CSP_REPORT_ONLY_ENABLED', false),
            'policy' => StrictPolicy::class,
            // Optional: the name of a reporting.report_to_groups entry (legacy Report-To).
            'report_to_group' => null,
        ],
    ],

    'reporting' => [
        'endpoints' => [
            // 'csp' => [
            //     'url' => 'https://example.com/csp',
            //     'legacy_url' => 'https://example.com/csp-legacy',   // optional
            // ],
        ],

        'report_to_groups' => [
            // Each key identifies a Report-To group definition. The emitted group
            // name defaults to that key and may be overridden with `group`.
            // Group endpoints are reporting.endpoints keys; the legacy_url (or url) is emitted.
            // 'security' => [
            //     'max_age' => 10_886_400,
            //     'include_subdomains' => true,
            //     'endpoints' => ['security'],
            // ],
        ],

        'ingestion' => [
            'enabled' => env('SECURITY_HEADERS_INGESTION_ENABLED', false),

            // Swap in your own string-backed enum (implementing ReportTypeContract) to accept
            // report types beyond the four this package emits.
            'report_type_enum' => ReportType::class,

            // Validate the body of a report type the package does not know how to check itself.
            // Keyed by the report's `type` value. Only for types your enum adds not the built-in
            // four (csp-violation, coep, coop, network-error), which validate themselves.
            'body_validators' => [
                // 'document-policy-violation' => App\Reporting\DocumentPolicyReportValidator::class,
            ],

            'route' => [
                'path' => env('SECURITY_HEADERS_INGESTION_PATH', '/security/reports'),
                'domain' => env('SECURITY_HEADERS_INGESTION_DOMAIN'),
            ],

            'database' => [
                'connection' => env('SECURITY_HEADERS_INGESTION_CONNECTION'),
                'table' => env('SECURITY_HEADERS_INGESTION_TABLE', 'security_reports'),
            ],

            'storage' => [
                // 'sanitized' or 'raw'.
                'mode' => env('SECURITY_HEADERS_INGESTION_STORAGE_MODE', 'sanitized'),
                // Silences the audit warning that raw mode stores report data without sanitization.
                'raw_acknowledged' => env('SECURITY_HEADERS_INGESTION_RAW_ACKNOWLEDGED', false),
                // Scrubbing applied in 'sanitized' mode. remove_client_ip and mask_client_ip are exclusive.
                'sanitizers' => [
                    'remove_client_ip' => true,             // the reporter's IP address
                    'mask_client_ip' => false,              // mask the IP's final octets so it identifies a network
                    'strip_query' => true,                  // the ?query string on reported URLs
                    'remove_sample' => false,               // the markup snippet that triggered a CSP report
                    'remove_nel_headers' => true,           // request/response headers in network-error reports
                    'remove_request_user_agent' => false,   // the User-Agent from the report request
                    'remove_reported_user_agent' => false,  // the User-Agent inside the report body
                ],
            ],

            'limits' => [
                'max_bytes' => IntegerConfig::parse(env('SECURITY_HEADERS_INGESTION_MAX_BYTES', 65536)),
                'max_reports_per_batch' => IntegerConfig::parse(env('SECURITY_HEADERS_INGESTION_MAX_BATCH', 100)),
                'json_depth' => IntegerConfig::parse(env('SECURITY_HEADERS_INGESTION_JSON_DEPTH', 32)),
                'url_length' => IntegerConfig::parse(env('SECURITY_HEADERS_INGESTION_URL_LENGTH', 8192)),
                'user_agent_length' => IntegerConfig::parse(env('SECURITY_HEADERS_INGESTION_UA_LENGTH', 1024)),
                'relaxed_acknowledged' => false,
            ],

            'rate_limiting' => [
                'enabled' => env('SECURITY_HEADERS_INGESTION_RATE_LIMITING', true),
                'limiter' => 'security-headers-ingestion',
                'reporting_api_per_minute' => 120,
                'legacy_csp_per_minute' => 600,
                'external_limiting_acknowledged' => false,
            ],

            'cors' => [
                // Leave empty if the reports come from your own site. Only list an origin here if a
                // different site needs to send reports to this endpoint from the browser.
                'allowed_origins' => [
                    // 'https://app.example.com',
                ],
            ],

            'retention' => [
                'days' => IntegerConfig::parse(env('SECURITY_HEADERS_INGESTION_RETENTION_DAYS', 30)),
                'max_rows' => IntegerConfig::parse(env('SECURITY_HEADERS_INGESTION_MAX_ROWS', 100000)),
            ],
        ],
    ],

    'nel' => [
        'enabled' => env('SECURITY_HEADERS_NEL_ENABLED', false),
        // Required unless max_age is 0.
        'report_to_group' => null,
        'max_age' => env('SECURITY_HEADERS_NEL_MAX_AGE', 2592000),
        'include_subdomains' => env('SECURITY_HEADERS_NEL_INCLUDE_SUBDOMAINS', false),
        // Percentage of requests to report, as a fraction 0.0-1.0. null applies the
        // NEL defaults: 0.0 for successes, 1.0 for failures.
        'success_fraction' => null,
        'failure_fraction' => null,
    ],

];
