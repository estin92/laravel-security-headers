<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Fields;

final class KnownFieldCatalogue
{
    /**
     * @return list<FieldSpec>|null
     */
    public function for(string $type): ?array
    {
        return match ($type) {
            'csp-violation' => $this->csp(),
            'coep' => $this->coep(),
            'coop' => $this->coop(),
            'network-error' => $this->nel(),
            default => null,
        };
    }

    /**
     * @return list<string>
     */
    public function knownTypes(): array
    {
        return ['csp-violation', 'coep', 'coop', 'network-error'];
    }

    /**
     * @return list<FieldSpec>
     */
    private function csp(): array
    {
        return [
            new FieldSpec('documentURL', FieldKind::StringValue),
            new FieldSpec('referrer', FieldKind::StringValue),
            new FieldSpec('blockedURL', FieldKind::StringValue),
            new FieldSpec('effectiveDirective', FieldKind::StringValue),
            new FieldSpec('originalPolicy', FieldKind::StringValue),
            new FieldSpec('sourceFile', FieldKind::StringValue),
            new FieldSpec('sample', FieldKind::StringValue),
            new FieldSpec('statusCode', FieldKind::NonNegativeInt),
            new FieldSpec('lineNumber', FieldKind::NonNegativeInt),
            new FieldSpec('columnNumber', FieldKind::NonNegativeInt),
            new FieldSpec('disposition', FieldKind::EnumSet, ['enforce', 'report']),
        ];
    }

    /**
     * @return list<FieldSpec>
     */
    private function coep(): array
    {
        return [
            new FieldSpec('type', FieldKind::StringValue),
            new FieldSpec('blockedURL', FieldKind::StringValue),
            new FieldSpec('destination', FieldKind::StringValue),
            new FieldSpec('disposition', FieldKind::EnumSet, ['enforce', 'reporting']),
        ];
    }

    /**
     * @return list<FieldSpec>
     */
    private function coop(): array
    {
        return [
            new FieldSpec('type', FieldKind::StringValue),
            new FieldSpec('disposition', FieldKind::StringValue),
            new FieldSpec('effectivePolicy', FieldKind::StringValue),
            new FieldSpec('referrer', FieldKind::StringValue),
        ];
    }

    /**
     * @return list<FieldSpec>
     */
    private function nel(): array
    {
        return [
            new FieldSpec('type', FieldKind::StringValue),
            new FieldSpec('server_ip', FieldKind::StringValue),
            new FieldSpec('protocol', FieldKind::StringValue),
            new FieldSpec('referrer', FieldKind::StringValue),
            new FieldSpec('method', FieldKind::StringValue),
            new FieldSpec('phase', FieldKind::EnumSet, ['dns', 'connection', 'application']),
            new FieldSpec('sampling_fraction', FieldKind::Fraction),
            new FieldSpec('elapsed_time', FieldKind::NonNegativeInt),
            new FieldSpec('status_code', FieldKind::NonNegativeInt),
            new FieldSpec('request_headers', FieldKind::HeaderMap),
            new FieldSpec('response_headers', FieldKind::HeaderMap),
        ];
    }
}
