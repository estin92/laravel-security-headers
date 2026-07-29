<?php

declare(strict_types=1);

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
    ],

    'hsts' => [
        'enabled' => env('SECURITY_HEADERS_HSTS_ENABLED', false),
        'max_age' => env('SECURITY_HEADERS_HSTS_MAX_AGE', 31536000),
        'include_subdomains' => env('SECURITY_HEADERS_HSTS_INCLUDE_SUBDOMAINS', true),
        'preload' => env('SECURITY_HEADERS_HSTS_PRELOAD', false),
    ],

];
