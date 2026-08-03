<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Exceptions;

use Estin92\SecurityHeaders\Reporting\Ingestion\RejectionReason;
use RuntimeException;

// The message can be logged, so it uses the reason only, never report content.
class InvalidReportSubmission extends RuntimeException
{
    public function __construct(
        public readonly RejectionReason $reason,
        public readonly ?string $offendingType = null,
    ) {
        parent::__construct('Report submission rejected: '.$reason->value);
    }

    public static function because(RejectionReason $reason): self
    {
        return new self($reason);
    }

    public static function unacceptedType(string $type): self
    {
        return new self(RejectionReason::UnacceptedReportType, $type);
    }
}
