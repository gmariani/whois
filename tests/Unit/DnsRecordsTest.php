<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use NetDNS2\RR;
use PHPUnit\Framework\TestCase;
use Whois\Dns\RecordFormatter;
use Whois\Sections\DnsSection;

final class DnsRecordsTest extends TestCase
{
    private static function format(string $zoneLine): array
    {
        $record = RecordFormatter::format(RR::fromString($zoneLine));
        self::assertNotNull($record, "could not format: {$zoneLine}");
        return $record;
    }

    public function testCommonFields(): void
    {
        $a = self::format('WWW.Example.com. 300 IN A 192.0.2.1');
        self::assertSame(['host' => 'www.example.com', 'ttl' => 300, 'class' => 'IN', 'type' => 'A', 'ip' => '192.0.2.1'], $a);
    }

    public function testRecordTypes(): void
    {
        self::assertSame('2001:db8::1', self::format('example.com. 300 IN AAAA 2001:db8::1')['ipv6']);
        self::assertSame('example.com', self::format('www.example.com. 300 IN CNAME example.com.')['target']);

        $mx = self::format('example.com. 300 IN MX 10 Mail.Example.com.');
        self::assertSame([10, 'mail.example.com'], [$mx['pri'], $mx['target']]);

        $srv = self::format('_sip._tls.example.com. 300 IN SRV 100 1 443 sipdir.online.lync.com.');
        self::assertSame([100, 1, 443, 'sipdir.online.lync.com'], [$srv['pri'], $srv['weight'], $srv['port'], $srv['target']]);

        $caa = self::format('example.com. 300 IN CAA 0 issue "letsencrypt.org"');
        self::assertSame([0, 'issue', 'letsencrypt.org'], [$caa['flags'], $caa['tag'], $caa['value']]);

        // kutchy.com's real NAPTR record (from the old index.php examples)
        $naptr = self::format('kutchy.com. 300 IN NAPTR 100 10 "U" "Meta:SMP" "!^.*$!https://qwac.kutchy.com:443!" .');
        self::assertSame([100, 10, 'U', 'Meta:SMP', '!^.*$!https://qwac.kutchy.com:443!', ''], [
            $naptr['order'], $naptr['pref'], $naptr['flags'], $naptr['services'], $naptr['regex'], $naptr['replacement'],
        ]);

        $ds = self::format('cloudflare.com. 86400 IN DS 2371 13 2 32996839a6d808afe3eb4a795a0e6a7a39a76fc52ff228b22b76f6d63826f2b9');
        self::assertSame([2371, 13, 2], [$ds['keytag'], $ds['algorithm'], $ds['digesttype']]);
        self::assertSame('32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9', $ds['digest']);
    }

    public function testHttpsRecord(): void
    {
        // What Cloudflare publishes for proxied sites.
        $https = self::format('cloudflare.com. 300 IN HTTPS 1 . alpn="h3,h2" ipv4hint=104.16.132.229,104.16.133.229');
        self::assertSame(1, $https['priority']);
        self::assertSame('', $https['target'], '"." means the record\'s own name');
        self::assertSame(['alpn' => 'h3,h2', 'ipv4hint' => '104.16.132.229,104.16.133.229'], $https['params']);
    }

    public function testTlsaRecord(): void
    {
        // Proton Mail's real DANE record for its MX host.
        $tlsa = self::format('_25._tcp.mail.protonmail.ch. 1200 IN TLSA 3 1 1 6111a5698d23c89e09c36ff833c1487edc1b0c841f87c49dae8f7a09e11e979e');
        self::assertSame([3, 1, 1], [$tlsa['usage'], $tlsa['selector'], $tlsa['matchingType']]);
        self::assertSame('6111A5698D23C89E09C36FF833C1487EDC1B0C841F87C49DAE8F7A09E11E979E', $tlsa['data']);
    }

    public function testChildDnssecRecords(): void
    {
        $cds = self::format('cloudflare.com. 3600 IN CDS 2371 13 2 32996839a6d808afe3eb4a795a0e6a7a39a76fc52ff228b22b76f6d63826f2b9');
        self::assertSame(['CDS', 2371, 13, 2], [$cds['type'], $cds['keytag'], $cds['algorithm'], $cds['digesttype']]);

        // RFC 8078 "please remove DNSSEC" signal
        $delete = self::format('example.com. 3600 IN CDS 0 0 0 00');
        self::assertSame(0, $delete['algorithm']);

        $cdnskey = self::format('cloudflare.com. 3600 IN CDNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==');
        self::assertSame(['CDNSKEY', 257, 13], [$cdnskey['type'], $cdnskey['flags'], $cdnskey['algorithm']]);
    }

    public function testTxtKeepsStringsAndJoinsThem(): void
    {
        // Long TXT records (DKIM keys) are split into 255-byte strings.
        $txt = self::format('example.com. 300 IN TXT "v=DKIM1; k=rsa; p=AAAA" "BBBB"');
        self::assertSame(['v=DKIM1; k=rsa; p=AAAA', 'BBBB'], $txt['entries']);
        self::assertSame('v=DKIM1; k=rsa; p=AAAABBBB', $txt['txt']);
    }

    public function testSoaMailboxIsInZoneFileForm(): void
    {
        $soa = self::format('github.com. 3600 IN SOA dns1.p08.nsone.net. hostmaster.nsone.net. 1656468023 43200 7200 1209600 3600');
        self::assertSame('dns1.p08.nsone.net', $soa['mname']);
        self::assertSame('hostmaster.nsone.net', $soa['rname'], 'not "hostmaster@nsone.net"');
        self::assertSame(3600, $soa['minimum-ttl']);
    }

    // ------------------------------------------------- DnsSection helpers

    private static function lookupResult(string $name, string $type, array $records, array $chain = []): array
    {
        return ['name' => $name, 'type' => $type, 'status' => 'NOERROR', 'records' => $records, 'chain' => $chain, 'server' => null];
    }

    public function testOnlyOwnKeepsJustTheCnameForAnAlias(): void
    {
        // www.github.com is a CNAME; the A records that come back belong to github.com.
        $cname = self::format('www.github.com. 3600 IN CNAME github.com.');
        $a = self::format('github.com. 60 IN A 140.82.114.3');

        $aliases = [];
        $own = DnsSection::onlyOwn(self::lookupResult('www.github.com', 'A', [$a], [$cname]), $aliases);

        self::assertSame([], $own);
        self::assertSame([$cname], $aliases);
    }

    public function testOnlyOwnDropsRecordsOwnedByOtherNames(): void
    {
        $mine = self::format('example.com. 300 IN TXT "v=spf1 -all"');
        $other = self::format('other.example.com. 300 IN TXT "x"');
        $aliases = [];

        self::assertSame([$mine], DnsSection::onlyOwn(self::lookupResult('example.com', 'TXT', [$mine, $other]), $aliases));
        self::assertSame([], $aliases);
    }

    public function testUniqueIgnoresTtlDifferences(): void
    {
        $a1 = self::format('example.com. 300 IN A 192.0.2.1');
        $a2 = self::format('example.com. 299 IN A 192.0.2.1');
        $b = self::format('example.com. 300 IN A 192.0.2.2');

        self::assertSame([$a1, $b], DnsSection::unique([$a1, $a2, $b]));
    }
}
