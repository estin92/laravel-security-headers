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

        'cross_origin_embedder_policy' => [
            'enabled' => env('SECURITY_HEADERS_CROSS_ORIGIN_EMBEDDER_POLICY_ENABLED', false),
            'value' => env('SECURITY_HEADERS_CROSS_ORIGIN_EMBEDDER_POLICY', 'require-corp'),
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

    'csp' => [
        'enabled' => env('SECURITY_HEADERS_CSP_ENABLED', false),
        'policy' => StrictPolicy::class,
    ],

];
