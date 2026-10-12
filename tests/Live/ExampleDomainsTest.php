<?php

declare(strict_types=1);

namespace Whois\Tests\Live;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Whois\Config;
use Whois\Lookup\Context;
use Whois\Lookup\SectionRunner;
use Whois\Support\Cache;

/**
 * The example domains from the original index.php, looked up for real.
 *
 * These hit live DNS, RDAP and websites, so they're slow and depend on how
 * those domains are configured today. A failure means either a regression or
 * that the domain changed; check which before "fixing" anything.
 *
 *   composer test:live
 */
final class ExampleDomainsTest extends TestCase
{
    private static Config $config;
    private static Cache $cache;
    /** @var array<string,array<string,array<string,mixed>>> domain => section => data */
    private static array $results = [];

    public static function setUpBeforeClass(): void
    {
        self::$config = require __DIR__ . '/../../app/bootstrap.php';
        // A throwaway cache so results are fresh, but shared within the run.
        self::$cache = new Cache(sys_get_temp_dir() . '/whois-live-' . getmypid());
    }

    /** @return array<string,mixed> */
    private static function section(string $domain, string $section): array
    {
        if (!isset(self::$results[$domain][$section])) {
            $runner = new SectionRunner();
            self::$results[$domain][$section] = $runner->run($section, new Context($domain, self::$config, self::$cache, $runner))['data'];
        }
        return self::$results[$domain][$section];
    }

    /** @return iterable<string,array{string}> */
    public static function exampleDomains(): iterable
    {
        foreach (['7trees.com', 'coursevector.com', 'pipershores.org', 'jplcreative.com', 'kutchy.com', 'caatest.co.uk', 'cloudflare.com', 'accuaudits.com', 'mariani.life', 'github.com'] as $domain) {
            yield $domain => [$domain];
        }
    }

    #[DataProvider('exampleDomains')]
    public function testEverySectionRuns(string $domain): void
    {
        foreach (array_keys(SectionRunner::SECTIONS) as $section) {
            self::assertIsArray(self::section($domain, $section), "{$section} for {$domain}");
        }
        $registration = self::section($domain, 'registration');
        self::assertTrue($registration['registered']);
        self::assertSame('rdap', $registration['source'], 'all of these TLDs have RDAP');
        self::assertNotEmpty($registration['record']['registrar']['name']);
        self::assertTrue(self::section($domain, 'dns')['delegated']);
        self::assertNotEmpty(self::section($domain, 'dns')['records']['soa']);
    }

    // ---- What each example in the old index.php comments was there to test

    public function testTxtThroughCname(): void
    {
        // pipershores.org: DKIM selectors are CNAMEs to Microsoft; the TXT lives at the target.
        $dkim = self::section('pipershores.org', 'email')['dkim'];
        $selector1 = array_values(array_filter($dkim, fn ($k) => $k['selector'] === 'selector1'))[0] ?? null;
        self::assertNotNull($selector1, 'selector1 DKIM key found');
        self::assertStringContainsString('onmicrosoft.com', (string) $selector1['cname']);
        self::assertGreaterThanOrEqual(1024, $selector1['keyBits']);
    }

    public function testAaaa(): void
    {
        self::assertNotEmpty(self::section('jplcreative.com', 'dns')['records']['aaaa']);
    }

    public function testNaptr(): void
    {
        $naptr = self::section('kutchy.com', 'dns')['records']['naptr'];
        self::assertNotEmpty($naptr);
        self::assertSame('U', $naptr[0]['flags']);
    }

    public function testCaaOnCoUk(): void
    {
        self::assertSame('caatest.co.uk', self::section('caatest.co.uk', 'registration')['domain'], 'registrable domain under co.uk');
        $tags = array_column(self::section('caatest.co.uk', 'dns')['records']['caa'], 'tag');
        self::assertContains('issue', $tags);
    }

    public function testDnskeyAndDsFromParentZone(): void
    {
        $dns = self::section('cloudflare.com', 'dns');
        self::assertNotEmpty($dns['records']['dnskey']);
        self::assertNotEmpty($dns['records']['ds']);
        self::assertStringEndsWith('gtld-servers.net', (string) $dns['dsServer'], 'DS comes from the .com servers');
    }

    public function testWildcardIsDetectedAndFiltered(): void
    {
        $subdomains = self::section('accuaudits.com', 'subdomains');
        self::assertTrue($subdomains['wildcard']);
        $hosts = array_column(array_merge(...array_values($subdomains['records'])), 'host');
        self::assertContains('*.accuaudits.com', $hosts);
        self::assertNotContains('ftp.accuaudits.com', $hosts, 'names that only match the wildcard are filtered out');
    }

    public function testHostingDetection(): void
    {
        self::assertSame('Liquid Web, L.L.C', self::section('coursevector.com', 'network')['webHost']);
        self::assertContains('Comcast Business', self::section('7trees.com', 'dns')['dnsHosts']);
    }

    public function testReverseDns(): void
    {
        $ptr = self::section('coursevector.com', 'dns')['records']['ptr'];
        self::assertNotEmpty($ptr);
        self::assertStringEndsWith('.in-addr.arpa', $ptr[0]['host']);
    }

    public function testThinRegistryFollowsRegistrar(): void
    {
        $record = self::section('github.com', 'registration')['record'];
        self::assertSame('MarkMonitor', $record['registrar']['label']);
        self::assertSame('GitHub, Inc.', $record['registrant']['organization'] ?? null, 'only the registrar RDAP server has this');
    }

    public function testNetworkFromRir(): void
    {
        $network = self::section('github.com', 'network');
        self::assertSame('ARIN', $network['network']['registry']);
        self::assertNotEmpty($network['network']['cidrs']);
    }

    // ---- Newer record types

    public function testHttpsRecordAndChildDnssec(): void
    {
        $dns = self::section('cloudflare.com', 'dns');
        self::assertNotEmpty($dns['records']['https'], 'Cloudflare publishes HTTPS records');
        self::assertStringContainsString('h3', $dns['records']['https'][0]['params']['alpn'] ?? '');
        self::assertNotEmpty($dns['records']['cds'], 'cloudflare.com publishes CDS');
        self::assertNotEmpty($dns['records']['cdnskey']);
    }

    public function testSubdomainIpv6AndHttps(): void
    {
        $records = self::section('cloudflare.com', 'subdomains')['records'];
        self::assertContains('www.cloudflare.com', array_column($records['aaaa'], 'host'));
        self::assertContains('www.cloudflare.com', array_column($records['https'], 'host'));
    }

    public function testMxOnSendingSubdomain(): void
    {
        // Resend's bounce handling: send.<domain> MX -> Amazon SES
        $mx = self::section('resend.dev', 'subdomains')['records']['mx'];
        $send = array_values(array_filter($mx, fn ($r) => $r['host'] === 'send.resend.dev'));
        self::assertNotEmpty($send);
        self::assertStringContainsString('amazonses.com', $send[0]['target']);
    }

    public function testMailServerDane(): void
    {
        $dane = self::section('protonmail.com', 'email')['dane'];
        self::assertNotEmpty($dane);
        $withTlsa = array_filter($dane, fn ($d) => $d['records']);
        self::assertNotEmpty($withTlsa, 'Proton publishes TLSA for its MX hosts');
        self::assertSame(3, array_values($withTlsa)[0]['records'][0]['usage']);
    }

    // ---- Edge cases

    public function testUnregisteredDomain(): void
    {
        $domain = 'no-such-domain-' . bin2hex(random_bytes(6)) . '.com';
        self::assertFalse(self::section($domain, 'registration')['registered']);
        self::assertFalse(self::section($domain, 'dns')['delegated']);
    }

    public function testWhoisFallbackForTldWithoutRdap(): void
    {
        // .io has no RDAP server in IANA's bootstrap file (at the time of writing).
        $registration = self::section('nic.io', 'registration');
        self::assertSame('whois', $registration['source']);
        self::assertNotEmpty($registration['record']['expires']);
    }

    public function testSubdomainQueryUsesRegistrableDomain(): void
    {
        self::assertSame('github.com', self::section('www.github.com', 'registration')['domain']);
        self::assertSame('github.com', self::section('www.github.com', 'dns')['zone']);
    }
}
