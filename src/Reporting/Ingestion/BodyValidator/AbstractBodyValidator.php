<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator;

use Estin92\SecurityHeaders\Exceptions\InvalidReportBody;
use Estin92\SecurityHeaders\Reporting\Fields\FieldKind;
use Estin92\SecurityHeaders\Reporting\Fields\KnownFieldCatalogue;
use Estin92\SecurityHeaders\Support\JsonObject;

abstract class AbstractBodyValidator implements ReportBodyValidator
{
    public function validate(?JsonObject $body): void
    {
        if ($body === null) {
            return;
        }

        foreach ((new KnownFieldCatalogue)->for($this->type()) ?? [] as $spec) {
            match ($spec->kind) {
                FieldKind::StringValue => $this->assertString($body, $spec->name),
                FieldKind::NonNegativeInt => $this->assertNonNegativeInt($body, $spec->name),
                FieldKind::Fraction => $this->assertFraction($body, $spec->name),
                FieldKind::EnumSet => $this->assertInSet($body, $spec->name, $spec->allowed),
                FieldKind::HeaderMap => $this->assertHeaderMap($body, $spec->name),
            };
        }
    }

    protected function assertString(JsonObject $body, string $field): void
    {
        if ($body->has([$field]) && ! is_string($body->get([$field]))) {
            throw InvalidReportBody::forType($this->type());
        }
    }

    protected function assertNonNegativeInt(JsonObject $body, string $field): void
    {
        if (! $body->has([$field])) {
            return;
        }

        $value = $body->get([$field]);

        if (! is_int($value) || $value < 0) {
            throw InvalidReportBody::forType($this->type());
        }
    }

    protected function assertFraction(JsonObject $body, string $field): void
    {
        if (! $body->has([$field])) {
            return;
        }

        $value = $body->get([$field]);

        if ((! is_int($value) && ! is_float($value)) || $value < 0 || $value > 1) {
            throw InvalidReportBody::forType($this->type());
        }
    }

    /**
     * @param  list<string>  $allowed
     */
    protected function assertInSet(JsonObject $body, string $field, array $allowed): void
    {
        if (! $body->has([$field])) {
            return;
        }

        $value = $body->get([$field]);

        if (! is_string($value) || ! in_array($value, $allowed, true)) {
            throw InvalidReportBody::forType($this->type());
        }
    }

    protected function assertHeaderMap(JsonObject $body, string $field): void
    {
        if (! $body->has([$field])) {
            return;
        }

        $value = $body->get([$field]);

        if (! $value instanceof JsonObject) {
            throw InvalidReportBody::forType($this->type());
        }

        foreach (get_object_vars($value->toNative()) as $header) {
            if (! $this->isHeaderValue($header)) {
                throw InvalidReportBody::forType($this->type());
            }
        }
    }

    private function isHeaderValue(mixed $value): bool
    {
        if (is_string($value)) {
            return true;
        }

        if (! is_array($value)) {
            return false;
        }

        foreach ($value as $item) {
            if (! is_string($item)) {
                return false;
            }
        }

        return true;
    }

    abstract protected function type(): string;
}
