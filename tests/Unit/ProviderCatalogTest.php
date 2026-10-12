<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Whois\Providers\ProviderCatalog;

final class ProviderCatalogTest extends TestCase
{
    public function testRegistrarNames(): void
    {
        self::assertSame('GoDaddy', ProviderCatalog::registrar('GoDaddy.com, LLC'));
        self::assertSame('Wild West Domains (GoDaddy)', ProviderCatalog::registrar('Wild West Domains, LLC'));
        self::assertSame('MarkMonitor', ProviderCatalog::registrar('MarkMonitor Inc.'));
        self::assertSame('Some Small Registrar', ProviderCatalog::registrar('Some Small Registrar'), 'unknown names pass through');
        self::assertNull(ProviderCatalog::registrar(null));
    }

    public function testDnsHosts(): void
    {
        // github.com's real mix of two providers
        self::assertSame(['NS1', 'AWS Route 53'], ProviderCatalog::dnsHosts([
            'dns1.p08.nsone.net', 'dns2.p08.nsone.net', 'ns-1283.awsdns-32.org', 'ns-421.awsdns-52.com',
        ]));
        self::assertSame(['Comcast Business'], ProviderCatalog::dnsHosts(['ns3.comcastbusiness.net', 'ns4.comcastbusiness.net']));
        self::assertSame(['Unknown (ns1.mystery.example)'], ProviderCatalog::dnsHosts(['ns1.mystery.example']));
        self::assertSame(['Cloudflare'], ProviderCatalog::dnsHosts(['ns1.mystery.example', 'ada.ns.cloudflare.com']), 'known providers hide unknown ones');
    }

    public function testEmailHosts(): void
    {
        self::assertSame(['Microsoft 365', false], ProviderCatalog::emailHost('github-com.mail.protection.outlook.com'));
        self::assertSame(['Google Gmail', false], ProviderCatalog::emailHost('aspmx.l.google.com'));
        self::assertSame(['Proofpoint Essentials', true], ProviderCatalog::emailHost('mx1-us1.ppe-hosted.com'), 'filtering gateway');
        self::assertNull(ProviderCatalog::emailHost('mail.example.com'));
    }

    public function testOrganizationUsesFirstRecognizedHint(): void
    {
        self::assertSame('BlueHost', ProviderCatalog::organization(['Unified Layer', null]));
        self::assertSame('Liquid Web, L.L.C', ProviderCatalog::organization([null, 'host.sourcedns.com']));
        self::assertSame('Network Solutions', ProviderCatalog::organization(['Network Solutions, LLC']));
        self::assertNull(ProviderCatalog::organization(['Tiny ISP', 'host.tiny.example']));
    }
}
