<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Reporting\Ingestion;

use Estin92\SecurityHeaders\Exceptions\InvalidIngestionConfig;
use Estin92\SecurityHeaders\Reporting\Ingestion\BodyValidator\BodyValidatorRegistry;
use Estin92\SecurityHeaders\Support\Origin;
use Illuminate\Container\Container;
use Throwable;

final class IngestionConfigValidator
{
    /**
     * @var array<string, array{int, int}>
     */
    private const LIMIT_BOUNDS = [
        'max_bytes' => [1, 1048576],
        'max_reports_per_batch' => [1, 10000],
        'json_depth' => [1, 128],
        'url_length' => [1, 65536],
        'user_agent_length' => [1, 8192],
    ];

    private const SANITIZER_TOGGLES = [
        'remove_client_ip',
        'mask_client_ip',
        'strip_query',
        'remove_sample',
        'remove_nel_headers',
        'remove_request_user_agent',
        'remove_reported_user_agent',
    ];

    /**
     * @param  array<mixed>  $config
     *
     * @throws InvalidIngestionConfig
     */
    public function validate(array $config): void
    {
        $this->validateLimits(self::section($config, 'limits'));
        $this->validateStorage(self::section($config, 'storage'));
        $this->validateRateLimiting(self::section($config, 'rate_limiting'));
        $this->validateRetention(self::section($config, 'retention'));
        $this->validateCors(self::section($config, 'cors'));
        $this->validateReportTypeEnum($config['report_type_enum'] ?? null);
        $this->validateBodyValidators($config['body_validators'] ?? []);
    }

    /**
     * @param  array<mixed>  $limits
     */
    private function validateLimits(array $limits): void
    {
        foreach (self::LIMIT_BOUNDS as $key => [$min, $max]) {
            $value = $limits[$key] ?? null;

            if (! is_int($value) || $value < $min || $value > $max) {
                throw InvalidIngestionConfig::limitOutOfRange($key, $min, $max);
            }
        }

        $this->assertBoolean($limits, 'relaxed_acknowledged', 'limits.relaxed_acknowledged');
    }

    /**
     * @param  array<mixed>  $storage
     */
    private function validateStorage(array $storage): void
    {
        $mode = $storage['mode'] ?? null;

        if ($mode !== 'sanitized' && $mode !== 'raw') {
            throw InvalidIngestionConfig::notInSet('storage.mode', is_string($mode) ? $mode : gettype($mode));
        }

        $this->assertBoolean($storage, 'raw_acknowledged', 'storage.raw_acknowledged');

        $sanitizers = is_array($storage['sanitizers'] ?? null) ? $storage['sanitizers'] : [];

        foreach (self::SANITIZER_TOGGLES as $toggle) {
            if (array_key_exists($toggle, $sanitizers) && ! is_bool($sanitizers[$toggle])) {
                throw InvalidIngestionConfig::notABoolean('storage.sanitizers.'.$toggle);
            }
        }

        if ($mode === 'sanitized') {
            $this->delegate(fn () => new Sanitizer(SanitizerConfig::fromArray($sanitizers), StorageMode::Sanitized));
        }
    }

    /**
     * @param  array<mixed>  $rate
     */
    private function validateRateLimiting(array $rate): void
    {
        foreach (['reporting_api_per_minute', 'legacy_csp_per_minute'] as $key) {
            if (! array_key_exists($key, $rate)) {
                continue;
            }

            if (! is_int($rate[$key]) || $rate[$key] < 1) {
                throw InvalidIngestionConfig::notAPositiveInt('rate_limiting.'.$key);
            }
        }

        $this->assertBoolean($rate, 'external_limiting_acknowledged', 'rate_limiting.external_limiting_acknowledged');
    }

    /**
     * @param  array<mixed>  $retention
     */
    private function validateRetention(array $retention): void
    {
        $days = $retention['days'] ?? null;

        if (! is_int($days) || $days < 1) {
            throw InvalidIngestionConfig::notAPositiveInt('retention.days');
        }

        $maxRows = $retention['max_rows'] ?? null;

        if (! is_int($maxRows) || $maxRows < 1 || $maxRows > 5000000) {
            throw InvalidIngestionConfig::notAPositiveInt('retention.max_rows');
        }
    }

    /**
     * @param  array<mixed>  $cors
     */
    private function validateCors(array $cors): void
    {
        $origins = is_array($cors['allowed_origins'] ?? null) ? $cors['allowed_origins'] : [];

        foreach ($origins as $origin) {
            if (! is_string($origin) || Origin::normalize($origin) === null) {
                throw InvalidIngestionConfig::badCorsOrigin(is_string($origin) ? $origin : gettype($origin));
            }
        }
    }

    private function validateReportTypeEnum(mixed $enum): void
    {
        if (! is_string($enum)) {
            throw InvalidIngestionConfig::notInSet('report_type_enum', gettype($enum));
        }

        $this->delegate(fn () => ReportTypeResolver::forEnum($enum));
    }

    private function validateBodyValidators(mixed $validators): void
    {
        if (! is_array($validators)) {
            throw InvalidIngestionConfig::notInSet('body_validators', gettype($validators));
        }

        $this->delegate(fn () => new BodyValidatorRegistry($validators, Container::getInstance()));
    }

    /**
     * @param  array<mixed>  $section
     */
    private function assertBoolean(array $section, string $key, string $path): void
    {
        if (! array_key_exists($key, $section) || ! is_bool($section[$key])) {
            throw InvalidIngestionConfig::notABoolean($path);
        }
    }

    /**
     * @param  array<mixed>  $config
     * @return array<mixed>
     */
    public static function section(array $config, string $key): array
    {
        return is_array($config[$key] ?? null) ? $config[$key] : [];
    }

    private function delegate(callable $check): void
    {
        try {
            $check();
        } catch (Throwable $e) {
            throw InvalidIngestionConfig::delegated($e);
        }
    }
}
