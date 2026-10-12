<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Whois\Sections\TlsSection;

final class TlsCertificateTest extends TestCase
{
    /**
     * Self-signed certificate made on the fly, so no network is needed.
     *
     * @param list<string> $altNames
     */
    private static function certificate(string $commonName, array $altNames): \OpenSSLCertificate
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        $config = tempnam(sys_get_temp_dir(), 'ssl');
        file_put_contents($config, "[req]\ndistinguished_name=dn\n[dn]\n[ext]\nsubjectAltName=" . implode(',', array_map(fn ($n) => "DNS:{$n}", $altNames)) . "\n");
        $csr = openssl_csr_new(['commonName' => $commonName, 'organizationName' => 'Example Ltd'], $key, ['config' => $config, 'digest_alg' => 'sha256']);
        $cert = openssl_csr_sign($csr, null, $key, 30, ['config' => $config, 'x509_extensions' => 'ext', 'digest_alg' => 'sha256'], 0x1234);
        unlink($config);
        return $cert;
    }

    public function testDescribesCertificate(): void
    {
        $info = TlsSection::describe(self::certificate('example.com', ['example.com', 'www.example.com']), 'example.com');

        self::assertSame('example.com', $info['subject']['CN']);
        self::assertSame('Example Ltd', $info['subject']['O']);
        self::assertSame(['example.com', 'www.example.com'], $info['altNames']);
        self::assertTrue($info['selfSigned']);
        self::assertFalse($info['expired']);
        self::assertTrue($info['hostnameMatches']);
        self::assertSame(3, $info['version'], 'X.509 v3 (the old code reported this wrong)');
        self::assertSame('1234', $info['serial']);
        self::assertStringStartsWith('Elliptic Curve', $info['publicKey']['type']);
        self::assertSame(256, $info['publicKey']['bits']);
        self::assertMatchesRegularExpression('/^[0-9A-F]{64}$/', $info['fingerprints']['sha256']);
        self::assertStringStartsWith('-----BEGIN CERTIFICATE-----', $info['pem']);
    }

    public function testWildcardCoversExactlyOneLabel(): void
    {
        $cert = self::certificate('*.example.com', ['*.example.com']);

        self::assertTrue(TlsSection::describe($cert, 'www.example.com')['hostnameMatches']);
        self::assertFalse(TlsSection::describe($cert, 'example.com')['hostnameMatches']);
        self::assertFalse(TlsSection::describe($cert, 'a.b.example.com')['hostnameMatches']);
        self::assertFalse(TlsSection::describe($cert, 'www.badexample.com')['hostnameMatches']);
    }
}
