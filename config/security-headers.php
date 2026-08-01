<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\StrictPolicy;
use Estin92\SecurityHeaders\PermissionsPolicy\Keyword;

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

        'cross_origin_opener_policy' => [
            'enabled' => env('SECURITY_HEADERS_CROSS_ORIGIN_OPENER_POLICY_ENABLED', true),
            'value' => env('SECURITY_HEADERS_CROSS_ORIGIN_OPENER_POLICY', 'same-origin'),
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
