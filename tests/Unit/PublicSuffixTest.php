<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Whois\Support\Cache;
use Whois\Support\HttpClient;
use Whois\Support\PublicSuffix;

final class PublicSuffixTest extends TestCase
{
    // A small slice of the real list, covering normal, wildcard and exception rules.
    private const LIST = <<<'PSL'
        // ===BEGIN ICANN DOMAINS===
        com
        org
        uk
        co.uk
        org.uk
        jp
        // Wildcard with an exception, as in the real list
        *.kawasaki.jp
        !city.kawasaki.jp
        // ===BEGIN PRIVATE DOMAINS===
        github.io
        PSL;

    private static string $cacheDir;

    public static function setUpBeforeClass(): void
    {
        self::$cacheDir = sys_get_temp_dir() . '/whois-psl-test-' . getmypid();
        (new Cache(self::$cacheDir))->set('psl:v1', PublicSuffix::parse(self::LIST), 3600);
    }

    private function psl(): PublicSuffix
    {
        return new PublicSuffix(new HttpClient('test'), new Cache(self::$cacheDir));
    }

    /** @return iterable<string,array{string,string}> */
    public static function domains(): iterable
    {
        yield 'apex' => ['example.com', 'example.com'];
        yield 'subdomain' => ['www.example.com', 'example.com'];
        yield 'deep subdomain' => ['a.b.c.example.com', 'example.com'];
        yield 'two-level ccTLD (old regex never matched this)' => ['blog.caatest.co.uk', 'caatest.co.uk'];
        yield 'two-level ccTLD apex' => ['caatest.co.uk', 'caatest.co.uk'];
        yield 'plain ccTLD' => ['www.example.uk', 'example.uk'];
        yield 'wildcard rule' => ['www.shop.foo.kawasaki.jp', 'shop.foo.kawasaki.jp'];
        yield 'exception rule' => ['www.city.kawasaki.jp', 'city.kawasaki.jp'];
        yield 'private suffix' => ['someone.github.io', 'someone.github.io'];
        yield 'unknown TLD falls back to default rule' => ['www.example.zzz', 'example.zzz'];
        yield 'a public suffix itself' => ['co.uk', 'co.uk'];
    }

    #[DataProvider('domains')]
    public function testRegistrableDomain(string $domain, string $expected): void
    {
        self::assertSame($expected, $this->psl()->registrableDomain($domain));
    }

    public function testParseIgnoresCommentsAndBlankLines(): void
    {
        $parsed = PublicSuffix::parse(self::LIST);
        self::assertArrayHasKey('co.uk', $parsed['rules']);
        self::assertArrayHasKey('kawasaki.jp', $parsed['wildcards']);
        self::assertArrayHasKey('city.kawasaki.jp', $parsed['exceptions']);
        self::assertArrayNotHasKey('// ===BEGIN ICANN DOMAINS===', $parsed['rules']);
    }
}
