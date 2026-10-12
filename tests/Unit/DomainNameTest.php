<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\RequiresPhpExtension;
use PHPUnit\Framework\TestCase;
use Whois\Support\DomainName;

final class DomainNameTest extends TestCase
{
    /** @return iterable<string,array{string,string}> */
    public static function normalizable(): iterable
    {
        yield 'plain' => ['google.com', 'google.com'];
        yield 'upper case and spaces' => ['  Google.COM ', 'google.com'];
        yield 'full URL' => ['https://www.Example.com/some/page?x=1#top', 'www.example.com'];
        yield 'URL with port' => ['http://example.com:8080/', 'example.com'];
        yield 'host with port' => ['example.com:8443', 'example.com'];
        yield 'path without scheme' => ['example.com/about', 'example.com'];
        yield 'trailing dot' => ['example.com.', 'example.com'];
        yield 'wildcard prefix' => ['*.example.com', 'example.com'];
        yield 'email address' => ['someone@example.com', 'example.com'];
        yield 'underscore labels' => ['_dmarc.example.com', '_dmarc.example.com'];
        yield 'two-level ccTLD' => ['caatest.co.uk', 'caatest.co.uk'];
        yield 'punycode TLD' => ['example.xn--p1ai', 'example.xn--p1ai'];
    }

    #[DataProvider('normalizable')]
    public function testNormalize(string $input, string $expected): void
    {
        self::assertSame($expected, DomainName::normalize($input));
    }

    #[RequiresPhpExtension('intl')]
    public function testInternationalizedNamesBecomePunycode(): void
    {
        self::assertSame('xn--mnchen-3ya.de', DomainName::normalize('München.de'));
    }

    /** @return iterable<string,array{string,string}> */
    public static function rejected(): iterable
    {
        yield 'empty' => ['', 'Enter a domain'];
        yield 'IPv4' => ['192.0.2.1', 'IP address'];
        yield 'IPv6' => ['2606:4700::1111', 'IP address'];
        yield 'bracketed IPv6 URL' => ['http://[2606:4700::1111]/', 'IP address'];
        yield 'no dot' => ['localhost', 'valid domain'];
        yield 'spaces' => ['not a domain', 'valid domain'];
        yield 'bad characters' => ['exa!mple.com', 'valid domain'];
        yield 'numeric TLD' => ['example.123', 'valid domain'];
        yield 'label too long' => [str_repeat('a', 64) . '.com', 'valid domain'];
        yield 'leading hyphen' => ['-example.com', 'valid domain'];
    }

    #[DataProvider('rejected')]
    public function testRejects(string $input, string $messageFragment): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage($messageFragment);
        DomainName::normalize($input);
    }

    public function testHelpers(): void
    {
        self::assertSame('com', DomainName::tld('www.example.com'));
        self::assertSame('example.com', DomainName::parent('www.example.com'));
        self::assertNull(DomainName::parent('com'));
        self::assertTrue(DomainName::isSubdomainOf('www.example.com', 'example.com'));
        self::assertTrue(DomainName::isSubdomainOf('example.com', 'example.com'));
        self::assertFalse(DomainName::isSubdomainOf('badexample.com', 'example.com'));
        self::assertFalse(DomainName::isSubdomainOf('example.com', 'www.example.com'));
    }
}
