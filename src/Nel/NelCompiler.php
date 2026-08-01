<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Nel;

use Estin92\SecurityHeaders\Exceptions\InvalidNel;
use Estin92\SecurityHeaders\Reporting\ReportToGroup;

final class NelCompiler
{
    public function compile(NelPolicy $policy, ?ReportToGroup $group): string
    {
        if ($policy->isRemoval()) {
            if ($group !== null) {
                throw InvalidNel::compileRemovalWithGroup();
            }

            return json_encode(['max_age' => 0], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        }

        if ($group === null) {
            throw InvalidNel::compileWithoutGroup();
        }

        $object = ['report_to' => $group->group, 'max_age' => $policy->maxAge];

        if ($policy->includeSubdomains === true) {
            $object['include_subdomains'] = true;
        }

        if (($policy->successFraction ?? 0.0) !== 0.0) {
            $object['success_fraction'] = $policy->successFraction;
        }

        if (($policy->failureFraction ?? 1.0) !== 1.0) {
            $object['failure_fraction'] = $policy->failureFraction;
        }

        return json_encode($object, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
