<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Whois\Support\Ip;

final class IpTest extends TestCase
{
    /** @return iterable<string,array{string,bool}> */
    public static function addresses(): iterable
    {
        // The SSRF guard depends on these: the server must never fetch internal addresses.
        yield 'loopback' => ['127.0.0.1', false];
        yield 'private 10/8' => ['10.1.2.3', false];
        yield 'private 192.168/16' => ['192.168.0.10', false];
        yield 'cloud metadata' => ['169.254.169.254', false];
        yield 'carrier-grade NAT' => ['100.64.1.1', false];
        yield 'unspecified' => ['0.0.0.0', false];
        yield 'IPv6 loopback' => ['::1', false];
        yield 'IPv6 unique local' => ['fd00::1', false];
        yield 'IPv6 link local' => ['fe80::1', false];
        yield 'IPv4-mapped IPv6 loopback' => ['::ffff:127.0.0.1', false];
        yield 'public IPv4' => ['8.8.8.8', true];
        yield 'public IPv6' => ['2606:4700:4700::1111', true];
    }

    #[DataProvider('addresses')]
    public function testIsPublic(string $ip, bool $public): void
    {
        self::assertSame($public, Ip::isPublic($ip));
    }

    public function testInCidr(): void
    {
        self::assertTrue(Ip::inCidr('140.82.114.3', '140.82.112.0/20'));
        self::assertFalse(Ip::inCidr('140.82.128.1', '140.82.112.0/20'));
        self::assertTrue(Ip::inCidr('10.0.0.1', '10.0.0.0/8'));
        self::assertTrue(Ip::inCidr('2606:4700::1', '2606:4700::/32'));
        self::assertFalse(Ip::inCidr('2606:4701::1', '2606:4700::/32'));
        self::assertFalse(Ip::inCidr('10.0.0.1', '2606:4700::/32'), 'mixed families never match');
        self::assertTrue(Ip::inCidr('1.2.3.4', '1.2.3.4'), 'no prefix means exact match');
    }

    public function testArpa(): void
    {
        // Examples from the old index.php comments.
        self::assertSame('139.149.87.209.in-addr.arpa', Ip::arpa('209.87.149.139'));
        self::assertSame(
            '3.f.c.a.3.4.c.a.0.0.0.0.0.0.0.0.0.0.0.0.4.3.0.3.0.0.7.4.6.0.6.2.ip6.arpa',
            Ip::arpa('2606:4700:3034:0:0:0:ac43:acf3'),
        );
        self::assertNull(Ip::arpa('not-an-ip'));
    }
}
