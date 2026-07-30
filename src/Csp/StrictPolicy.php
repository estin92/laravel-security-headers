<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Csp;

class StrictPolicy extends CspPolicy
{
    protected function define(): void
    {
        $this->directive('default-src', "'self'");
        $this->directiveWithNonce('script-src', "'self'");
        $this->directive('style-src', "'self'");
        $this->directive('img-src', "'self'", 'data:');
        $this->directive('font-src', "'self'");
        $this->directive('connect-src', "'self'");
        $this->directive('form-action', "'self'");
        $this->directive('frame-ancestors', "'none'");
        $this->directive('base-uri', "'self'");
        $this->directive('object-src', "'none'");
        $this->directive('upgrade-insecure-requests');
    }
}
