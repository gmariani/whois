<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Whois\Http\LookupUrl;

final class LookupUrlTest extends TestCase
{
    private array $server;
    private array $get;

    protected function setUp(): void
    {
        $this->server = $_SERVER;
        $this->get = $_GET;
        $_GET = [];
        $_SERVER['SCRIPT_NAME'] = '/projects/dns/index.php';
    }

    protected function tearDown(): void
    {
        $_SERVER = $this->server;
        $_GET = $this->get;
    }

    public function testBase(): void
    {
        self::assertSame('/projects/dns/', LookupUrl::base());
        $_SERVER['SCRIPT_NAME'] = '/index.php';
        self::assertSame('/', LookupUrl::base());
    }

    /** @return iterable<string,array{string,string,bool}> [REQUEST_URI, query, ignored] */
    public static function paths(): iterable
    {
        yield 'home' => ['/projects/dns/', '', false];
        yield 'home without slash' => ['/projects/dns', '', false];
        yield 'index.php' => ['/projects/dns/index.php', '', false];
        yield 'domain' => ['/projects/dns/google.com/', 'google.com', false];
        yield 'domain, no trailing slash' => ['/projects/dns/google.com', 'google.com', false];
        yield 'full URL' => ['/projects/dns/https://example.com/some/page', 'https://example.com/some/page', false];
        yield 'URL with slashes merged by the server' => ['/projects/dns/https:/example.com/', 'https://example.com', false];
        yield 'percent-encoded' => ['/projects/dns/m%C3%BCnchen.de/', 'münchen.de', false];
        yield 'query string is not part of the domain' => ['/projects/dns/google.com/?utm=x', 'google.com', false];
        yield 'favicon' => ['/projects/dns/favicon.ico', 'favicon.ico', true];
        yield 'favicon at the site root' => ['/favicon.ico', 'favicon.ico', true];
        yield 'robots' => ['/projects/dns/robots.txt', 'robots.txt', true];
    }

    #[DataProvider('paths')]
    public function testRequested(string $uri, string $query, bool $ignored): void
    {
        $_SERVER['REQUEST_URI'] = $uri;
        $request = LookupUrl::requested('/projects/dns/');
        self::assertSame($query, $request['query']);
        self::assertSame($ignored, $request['ignored']);
        self::assertFalse($request['legacy']);
    }

    public function testLegacyQueryString(): void
    {
        $_SERVER['REQUEST_URI'] = '/projects/dns/?q=github.com';
        $_GET['q'] = ' github.com ';
        self::assertSame(['query' => 'github.com', 'legacy' => true, 'ignored' => false], LookupUrl::requested('/projects/dns/'));
    }

    public function testTo(): void
    {
        self::assertSame('/projects/dns/google.com/', LookupUrl::to('/projects/dns/', 'google.com'));
    }
}
