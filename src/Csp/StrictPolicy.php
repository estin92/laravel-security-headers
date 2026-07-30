<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Csp;

class StrictPolicy extends CspPolicy
{
    protected function define(): void
    {
        $this->directive('default-src', Keyword::Self);
        $this->directiveWithNonce('script-src', Keyword::Self);
        $this->directive('style-src', Keyword::Self);
        $this->directive('img-src', Keyword::Self, 'data:');
        $this->directive('font-src', Keyword::Self);
        $this->directive('connect-src', Keyword::Self);
        $this->directive('form-action', Keyword::Self);
        $this->directive('frame-ancestors', Keyword::None);
        $this->directive('base-uri', Keyword::Self);
        $this->directive('object-src', Keyword::None);
        $this->directive('upgrade-insecure-requests');
    }
}
