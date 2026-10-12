<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Whois\Sections\EmailSection;

final class EmailParsingTest extends TestCase
{
    // ------------------------------------------------------------------ SPF

    public function testSpfQualifiers(): void
    {
        $terms = EmailSection::parseSpf('v=spf1 +a -mx ~ip4:192.0.2.1 ?include:example.net all')['terms'];

        self::assertSame(['pass', 'fail', 'softfail', 'neutral', 'pass'], array_column($terms, 'qualifier'));
        self::assertSame(['a', 'mx', 'ip4', 'include', 'all'], array_column($terms, 'mechanism'));
    }

    public function testSpfMissingQualifierMeansPass(): void
    {
        // RFC 7208 §4.6.2. The old page listed these under "neutral".
        $terms = EmailSection::parseSpf('v=spf1 include:_spf.google.com ~all')['terms'];
        self::assertSame('pass', $terms[0]['qualifier']);
        self::assertSame('_spf.google.com', $terms[0]['value']);
    }

    public function testSpfMechanismValuesAndPrefixes(): void
    {
        $terms = EmailSection::parseSpf('v=spf1 ip4:192.30.252.0/22 ip6:2001:db8::/32 a:mail.example.com/24 a/24 mx exists:%{i}.spf.example.com -all')['terms'];

        self::assertSame(['ip4', '192.30.252.0', '/22'], [$terms[0]['mechanism'], $terms[0]['value'], $terms[0]['cidr']]);
        self::assertSame(['ip6', '2001:db8::', '/32'], [$terms[1]['mechanism'], $terms[1]['value'], $terms[1]['cidr']]);
        self::assertSame(['a', 'mail.example.com', '/24'], [$terms[2]['mechanism'], $terms[2]['value'], $terms[2]['cidr']]);
        self::assertSame(['a', null, '/24'], [$terms[3]['mechanism'], $terms[3]['value'], $terms[3]['cidr']]);
        self::assertSame(['mx', null], [$terms[4]['mechanism'], $terms[4]['value']]);
        self::assertSame(['exists', '%{i}.spf.example.com'], [$terms[5]['mechanism'], $terms[5]['value']]);
        self::assertSame('fail', $terms[6]['qualifier']);
    }

    public function testSpfModifiers(): void
    {
        $terms = EmailSection::parseSpf('v=spf1 redirect=_spf.example.com exp=explain.example.com')['terms'];

        self::assertSame(['modifier', 'modifier'], array_column($terms, 'kind'));
        self::assertSame(['redirect', 'exp'], array_column($terms, 'mechanism'));
        self::assertSame('_spf.example.com', $terms[0]['value']);
        self::assertNull($terms[0]['qualifier']);
    }

    public function testSpfToleratesExtraWhitespace(): void
    {
        $terms = EmailSection::parseSpf("v=spf1  mx\t -all ")['terms'];
        self::assertCount(2, $terms);
    }

    // ----------------------------------------------------------------- DKIM

    private static function rsaPublicKey(int $bits): string
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
        $pem = openssl_pkey_get_details($key)['key'];
        return preg_replace('/-----[^-]+-----|\s+/', '', $pem);
    }

    public function testDkimRsaKey(): void
    {
        $dkim = EmailSection::parseDkim('google', 'google._domainkey.example.com', 'v=DKIM1; k=rsa; p=' . self::rsaPublicKey(2048));

        self::assertSame(2048, $dkim['keyBits']);
        self::assertSame('rsa', $dkim['keyType']);
        self::assertFalse($dkim['weak']);
        self::assertFalse($dkim['revoked']);
        self::assertStringStartsWith('-----BEGIN PUBLIC KEY-----', $dkim['publicKey']);
        self::assertSame('DKIM1', $dkim['tags']['v']);
    }

    public function testDkimWeakKeyIsFlagged(): void
    {
        $dkim = EmailSection::parseDkim('k1', 'k1._domainkey.example.com', 'k=rsa; p=' . self::rsaPublicKey(512));
        self::assertSame(512, $dkim['keyBits']);
        self::assertTrue($dkim['weak']);
    }

    public function testDkimWithoutVersionTag(): void
    {
        // Some providers publish only k= and p= (the old code accepted these too).
        $dkim = EmailSection::parseDkim('s1', 's1._domainkey.example.com', 'k=rsa; t=s; p=' . self::rsaPublicKey(1024));
        self::assertSame(1024, $dkim['keyBits']);
        self::assertSame('s', $dkim['tags']['t']);
        self::assertFalse($dkim['testing']);
    }

    public function testDkimRevokedAndTestingAndEd25519(): void
    {
        $revoked = EmailSection::parseDkim('old', 'old._domainkey.example.com', 'v=DKIM1; p=');
        self::assertTrue($revoked['revoked']);
        self::assertNull($revoked['keyBits']);

        $testing = EmailSection::parseDkim('t', 't._domainkey.example.com', 'v=DKIM1; t=y:s; p=' . self::rsaPublicKey(1024));
        self::assertTrue($testing['testing']);

        $ed = EmailSection::parseDkim('ed', 'ed._domainkey.example.com', 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=');
        self::assertSame('ed25519', $ed['keyType']);
        self::assertSame(256, $ed['keyBits']);
    }

    // ---------------------------------------------------------------- DMARC

    private static function txt(string $host, string $txt): array
    {
        return ['host' => $host, 'ttl' => 300, 'class' => 'IN', 'type' => 'TXT', 'txt' => $txt, 'entries' => [$txt]];
    }

    public function testDmarc(): void
    {
        $dmarc = EmailSection::dmarc([self::txt(
            '_dmarc.example.com',
            'v=DMARC1; p=quarantine; sp=reject; pct=100; rua=mailto:a@example.com,mailto:b@example.net; ruf=mailto:f@example.com; adkim=s; fo=1',
        )]);

        self::assertNotNull($dmarc);
        self::assertSame('quarantine', $dmarc['tags']['p']);
        self::assertSame('reject', $dmarc['tags']['sp']);
        self::assertSame('a@example.com, b@example.net', $dmarc['tags']['rua'], 'mailto: is stripped from every address');
        self::assertSame('f@example.com', $dmarc['tags']['ruf']);
        self::assertSame('s', $dmarc['tags']['adkim']);
    }

    public function testDmarcIgnoresOtherTxtAndMalformedParts(): void
    {
        self::assertNull(EmailSection::dmarc([self::txt('_dmarc.example.com', 'google-site-verification=abc')]));

        // The old code warned ("Undefined offset") on parts without "=".
        $dmarc = EmailSection::dmarc([self::txt('_dmarc.example.com', 'v=DMARC1;p=none;;garbage;')]);
        self::assertSame(['v' => 'DMARC1', 'p' => 'none'], $dmarc['tags']);
    }
}
