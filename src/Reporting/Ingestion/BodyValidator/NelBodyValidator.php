<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

use Estin92\SecurityHeaders\Support\JsonObject;

class NelBodyValidator extends AbstractBodyValidator
{
    protected function type(): string
    {
        return 'network-error';
    }

    protected function validateFields(JsonObject $body): void
    {
        foreach (['type', 'server_ip', 'protocol', 'referrer', 'method'] as $field) {
            $this->assertString($body, $field);
        }

        $this->assertInSet($body, 'phase', ['dns', 'connection', 'application']);
        $this->assertFraction($body, 'sampling_fraction');

        foreach (['elapsed_time', 'status_code'] as $field) {
            $this->assertNonNegativeInt($body, $field);
        }

        foreach (['request_headers', 'response_headers'] as $field) {
            $this->assertHeaderMap($body, $field);
        }
    }
}
