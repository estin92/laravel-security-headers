<?php

declare(strict_types=1);

use Estin92\SecurityHeaders\Csp\CspCompiler;
use Estin92\SecurityHeaders\Csp\Keyword;
use Estin92\SecurityHeaders\Exceptions\InvalidCspDirective;
use Estin92\SecurityHeaders\Tests\Csp\FakeCspPolicy;

test('it serialises directives into a policy string', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directive('default-src', Keyword::Self);
        $this->directive('img-src', Keyword::Self, 'data:');
    });

    expect((new CspCompiler)->compile($policy, null))
        ->toBe("default-src 'self'; img-src 'self' data:");
});

test('it substitutes the nonce on a nonced directive', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directiveWithNonce('script-src', Keyword::Self);
    });

    expect((new CspCompiler)->compile($policy, 'abc123'))
        ->toBe("script-src 'self' 'nonce-abc123'");
});

test('it serialises a valueless directive', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directive('upgrade-insecure-requests');
    });

    expect((new CspCompiler)->compile($policy, null))
        ->toBe('upgrade-insecure-requests');
});

test('it merges and de-duplicates repeated declarations of one directive', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directive('script-src', Keyword::Self);
        $this->directive('script-src', 'https://example.com', Keyword::Self);
    });

    expect((new CspCompiler)->compile($policy, null))
        ->toBe("script-src 'self' https://example.com");
});

test('it throws when a required nonce is not supplied', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directiveWithNonce('script-src', Keyword::Self);
    });

    expect(fn () => (new CspCompiler)->compile($policy, null))
        ->toThrow(InvalidCspDirective::class);
});

test('it ignores a nonce on a policy that does not request one', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directive('script-src', Keyword::Self);
    });

    expect((new CspCompiler)->compile($policy, 'abc123'))
        ->toBe("script-src 'self'");
});

test('it rejects a source that would break out of the header', function (string $source) {
    $policy = new FakeCspPolicy(function () use ($source) {
        $this->directive('default-src', $source);
    });

    expect(fn () => (new CspCompiler)->compile($policy, null))
        ->toThrow(InvalidCspDirective::class);
})->with([
    'carriage return' => ["'self'\r"],
    'newline' => ["'self'\n"],
    'trailing newline' => ["'self'\n"],
    'tab' => ["'self'\t"],
    'semicolon' => ["'self'; script-src evil"],
    'comma' => ["'self','nonce-x"],
    'header split' => ["'self'\r\nSet-Cookie: x=1"],
    'empty string' => [''],
]);

test('it rejects a directive name that is not a valid token', function (string $name) {
    $policy = new FakeCspPolicy(function () use ($name) {
        $this->directive($name, Keyword::Self);
    });

    expect(fn () => (new CspCompiler)->compile($policy, null))
        ->toThrow(InvalidCspDirective::class);
})->with([
    'space' => ['script src'],
    'newline' => ["script-src\n"],
    'semicolon' => ['script-src;'],
    'uppercase' => ['Script-Src'],
]);

test('it rejects a nonce that is not a valid token', function (string $nonce) {
    $policy = new FakeCspPolicy(function () {
        $this->directiveWithNonce('script-src', Keyword::Self);
    });

    expect(fn () => (new CspCompiler)->compile($policy, $nonce))
        ->toThrow(InvalidCspDirective::class);
})->with([
    'trailing newline' => ["abc123\n"],
    'space' => ['abc 123'],
    'padding not terminal' => ['ab=c'],
    'leading padding' => ['===abc'],
    'header split' => ["abc\r\nSet-Cookie: x=1"],
]);

test('it accepts a base64 nonce with terminal padding', function () {
    $policy = new FakeCspPolicy(function () {
        $this->directiveWithNonce('script-src', Keyword::Self);
    });

    expect((new CspCompiler)->compile($policy, 'YWJjMTIz=='))
        ->toBe("script-src 'self' 'nonce-YWJjMTIz=='");
});
