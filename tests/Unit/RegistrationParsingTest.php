<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Whois\Rdap\RdapParser;
use Whois\Whois\WhoisParser;

/**
 * Parsers run against real responses saved in tests/fixtures/. If a registry
 * changes its format, refresh the fixture and see what breaks.
 */
final class RegistrationParsingTest extends TestCase
{
    private static function fixture(string $name): string
    {
        return (string) file_get_contents(__DIR__ . '/../fixtures/' . $name);
    }

    private static function json(string $name): array
    {
        return json_decode(self::fixture($name), true, flags: JSON_THROW_ON_ERROR);
    }

    // ---------------------------------------------------------------- RDAP

    public function testRdapThinRegistryPlusRegistrar(): void
    {
        // .com is "thin": Verisign has dates and name servers, the registrar has the registrant.
        $parsed = RdapParser::domain(self::json('rdap-github-registry.json'), self::json('rdap-github-registrar.json'));

        self::assertSame('MarkMonitor Inc.', $parsed['registrar']['name']);
        self::assertSame('292', $parsed['registrar']['ianaId']);
        self::assertSame('abusecomplaints@markmonitor.com', $parsed['registrar']['abuseEmail']);
        self::assertStringStartsWith('2007-10-09', (string) $parsed['created']);
        self::assertNotNull($parsed['expires']);
        self::assertContains('dns1.p08.nsone.net', $parsed['nameservers']);
        self::assertContains('client transfer prohibited', $parsed['status']);
        self::assertFalse($parsed['dnssec']);
        self::assertSame('GitHub, Inc.', $parsed['registrant']['organization'], 'registrant comes from the registrar record');
    }

    public function testRdapRegistryOnly(): void
    {
        $parsed = RdapParser::domain(self::json('rdap-github-registry.json'), null);

        self::assertSame('MarkMonitor Inc.', $parsed['registrar']['name']);
        self::assertNull($parsed['registrant'], 'thin registries publish no registrant');
    }

    public function testRdapIpNetworkFromArin(): void
    {
        $network = RdapParser::network(self::json('rdap-arin-github-ip.json'), 'https://rdap.arin.net/registry/ip/140.82.114.3');

        self::assertSame('ARIN', $network['registry']);
        self::assertSame('NET-140-82-112-0-1', $network['handle']);
        self::assertSame('140.82.112.0', $network['startAddress']);
        self::assertSame('140.82.127.255', $network['endAddress']);
        self::assertSame(['140.82.112.0/20'], $network['cidrs']);
        self::assertSame('GitHub, Inc.', $network['organization']['name']);
        self::assertSame('GITHU', $network['organization']['handle']);
        self::assertStringContainsString('San Francisco', (string) $network['organization']['address']);
        self::assertNotEmpty($network['abuseEmail']);
    }

    public function testVcardParsing(): void
    {
        $card = RdapParser::vcard(['vcardArray' => ['vcard', [
            ['version', [], 'text', '4.0'],
            ['fn', [], 'text', 'Jane Doe'],
            ['org', [], 'text', 'Example Ltd'],
            ['email', [], 'text', 'jane@example.com'],
            ['tel', ['type' => 'voice'], 'uri', 'tel:+1.5555550100'],
            ['adr', ['cc' => 'GB'], 'text', ['', '', '1 High St', 'London', '', 'SW1A 1AA', '']],
        ]]]);

        self::assertSame('Jane Doe', $card['name']);
        self::assertSame('Example Ltd', $card['org']);
        self::assertSame('+1.5555550100', $card['phone']);
        self::assertSame('GB', $card['country']);
        self::assertSame('1 High St, London, SW1A 1AA', $card['address']);
    }

    // --------------------------------------------------------------- WHOIS

    public function testWhoisThickRegistry(): void
    {
        $parsed = WhoisParser::domain(self::fixture('whois-nic-io.txt'), null);

        self::assertSame('Registry Operator acts as Registrar (9999)', $parsed['registrar']['name']);
        self::assertSame('https://identity.digital', $parsed['registrar']['url']);
        self::assertSame('9999', $parsed['registrar']['ianaId']);
        self::assertSame('2003-09-15T11:13:53Z', $parsed['created']);
        self::assertSame('2027-05-01T00:00:02Z', $parsed['expires']);
        self::assertContains('serverTransferProhibited', $parsed['status']);
        self::assertNotEmpty($parsed['nameservers']);
        self::assertSame('Internet Computer Bureau Ltd', $parsed['registrant']['organization']);
    }

    public function testWhoisNominetLayout(): void
    {
        // The multi-line .uk format the old regexes were written for.
        $parsed = WhoisParser::domain(self::fixture('whois-nominet-uk.txt'), null);

        self::assertSame('123-Reg Limited t/a 123-reg [Tag = 123-REG]', $parsed['registrar']['name']);
        self::assertSame('http://www.123-reg.co.uk', $parsed['registrar']['url']);
        self::assertSame(['ns1.onetouchdns.co.uk', 'ns2.onetouchdns.co.uk'], $parsed['nameservers']);
        self::assertStringStartsWith('2027-10-25', (string) $parsed['expires']);
        self::assertStringStartsWith('2005-10-25', (string) $parsed['created']);
    }

    public function testWhoisRegistrarRecordWinsOverRegistry(): void
    {
        $registry = "Registrar: Registry Says Ltd\nRegistry Expiry Date: 2030-01-01T00:00:00Z\n";
        $registrar = "Registrar: Real Registrar Inc.\nRegistrant Name: Jane Doe\nRegistrant Email: jane@example.com\n";
        $parsed = WhoisParser::domain($registry, $registrar);

        self::assertSame('Real Registrar Inc.', $parsed['registrar']['name']);
        self::assertSame('Jane Doe', $parsed['registrant']['name']);
        self::assertSame('jane@example.com', $parsed['registrant']['email']);
        self::assertSame('2030-01-01T00:00:00Z', $parsed['expires']);
    }
}
