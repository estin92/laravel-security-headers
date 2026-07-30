<?php

declare(strict_types=1);

namespace Estin92\SecurityHeaders\Csp;

enum Keyword: string
{
    case Self = "'self'";
    case None = "'none'";
    case UnsafeInline = "'unsafe-inline'";
    case UnsafeEval = "'unsafe-eval'";
    case StrictDynamic = "'strict-dynamic'";
    case UnsafeHashes = "'unsafe-hashes'";
    case WasmUnsafeEval = "'wasm-unsafe-eval'";
    case ReportSample = "'report-sample'";
    case InlineSpeculationRules = "'inline-speculation-rules'";
}
