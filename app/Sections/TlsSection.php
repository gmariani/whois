<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;
use Whois\Support\Ip;

/**
 * The certificate presented on port 443.
 */
final class TlsSection implements Section
{
    public function build(Context $context): array
    {
        $domain = $context->domain;

        $ip = null;
        foreach (@gethostbynamel($domain) ?: [] as $candidate) {
            if (!Ip::isPublic($candidate)) {
                return ['present' => false, 'error' => 'Domain resolves to a non-public address'];
            }
            $ip ??= $candidate;
        }
        if ($ip === null) {
            return ['present' => false, 'error' => 'Domain has no IPv4 address'];
        }

        // Connect to the address we vetted, but send the domain as SNI.
        // Verification is off so expired/self-signed certificates can still be inspected.
        $context_ = stream_context_create(['ssl' => [
            'capture_peer_cert' => true,
            'capture_peer_cert_chain' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'SNI_enabled' => true,
            'peer_name' => $domain,
        ]]);
        $socket = @stream_socket_client("ssl://{$ip}:443", $errno, $error, 4, STREAM_CLIENT_CONNECT, $context_);
        if ($socket === false) {
            return ['present' => false, 'error' => $error ?: 'Could not connect on port 443'];
        }
        $params = stream_context_get_params($socket);
        $meta = stream_get_meta_data($socket);
        fclose($socket);

        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        if (!$cert) {
            return ['present' => false, 'error' => 'No certificate presented'];
        }

        $chain = [];
        foreach (array_slice($params['options']['ssl']['peer_certificate_chain'] ?? [], 1) as $link) {
            $parsed = openssl_x509_parse($link);
            $chain[] = [
                'subject' => $parsed['subject']['CN'] ?? $parsed['name'] ?? null,
                'issuer' => $parsed['issuer']['CN'] ?? null,
                'validTo' => isset($parsed['validTo_time_t']) ? gmdate('c', $parsed['validTo_time_t']) : null,
            ];
        }

        return ['present' => true, 'protocol' => $meta['crypto']['protocol'] ?? null, 'cipher' => $meta['crypto']['cipher_name'] ?? null]
            + self::describe($cert, $domain)
            + ['chain' => $chain];
    }

    /**
     * @param \OpenSSLCertificate $cert
     * @return array<string,mixed>
     */
    public static function describe($cert, string $domain): array
    {
        $info = openssl_x509_parse($cert);
        $publicKey = openssl_pkey_get_details(openssl_pkey_get_public($cert)) ?: [];
        openssl_x509_export($cert, $pem);
        $der = base64_decode((string) preg_replace('/-----[^-]+-----|\s+/', '', $pem));

        $altNames = [];
        foreach (explode(',', $info['extensions']['subjectAltName'] ?? '') as $name) {
            $name = trim($name);
            if (str_starts_with($name, 'DNS:')) {
                $altNames[] = strtolower(substr($name, 4));
            } elseif ($name !== '') {
                $altNames[] = $name;
            }
        }

        $validTo = (int) ($info['validTo_time_t'] ?? 0);

        return [
            'subject' => self::names($info['subject'] ?? []),
            'issuer' => self::names($info['issuer'] ?? []),
            'validFrom' => gmdate('c', (int) ($info['validFrom_time_t'] ?? 0)),
            'validTo' => gmdate('c', $validTo),
            'expired' => $validTo < time(),
            'selfSigned' => ($info['subject'] ?? null) == ($info['issuer'] ?? null),
            'hostnameMatches' => self::matchesHost($domain, $altNames, $info['subject']['CN'] ?? null),
            'altNames' => $altNames,
            'publicKey' => [
                'type' => match ($publicKey['type'] ?? -1) {
                    OPENSSL_KEYTYPE_RSA => 'RSA',
                    OPENSSL_KEYTYPE_DSA => 'DSA',
                    OPENSSL_KEYTYPE_DH => 'Diffie-Hellman',
                    OPENSSL_KEYTYPE_EC => 'Elliptic Curve' . (isset($publicKey['ec']['curve_name']) ? " ({$publicKey['ec']['curve_name']})" : ''),
                    default => 'Unknown',
                },
                'bits' => $publicKey['bits'] ?? null,
                'pem' => $publicKey['key'] ?? null,
            ],
            'serial' => strtoupper($info['serialNumberHex'] ?? dechex((int) ($info['serialNumber'] ?? 0))),
            'signatureAlgorithm' => $info['signatureTypeSN'] ?? null,
            'version' => ($info['version'] ?? 0) + 1, // stored zero-based: 2 means X.509 v3
            'fingerprints' => [
                'sha256' => strtoupper(hash('sha256', $der)),
                'sha1' => strtoupper(hash('sha1', $der)),
                'md5' => strtoupper(hash('md5', $der)),
            ],
            'keyUsage' => $info['extensions']['keyUsage'] ?? null,
            'extendedKeyUsage' => $info['extensions']['extendedKeyUsage'] ?? null,
            'subjectKeyId' => $info['extensions']['subjectKeyIdentifier'] ?? null,
            'authorityKeyId' => isset($info['extensions']['authorityKeyIdentifier'])
                ? trim(str_replace('keyid:', '', $info['extensions']['authorityKeyIdentifier']))
                : null,
            'pem' => $pem,
        ];
    }

    /**
     * @param array<string,string|list<string>> $dn
     * @return array<string,string>
     */
    private static function names(array $dn): array
    {
        return array_map(fn ($v) => is_array($v) ? implode(', ', $v) : (string) $v, $dn);
    }

    /**
     * @param list<string> $altNames
     */
    private static function matchesHost(string $domain, array $altNames, ?string $commonName): bool
    {
        foreach ($altNames ?: [strtolower((string) $commonName)] as $name) {
            if ($name === $domain) {
                return true;
            }
            // *.example.com covers exactly one extra label.
            if (str_starts_with($name, '*.') && substr_count($domain, '.') === substr_count($name, '.')
                && str_ends_with($domain, substr($name, 1))) {
                return true;
            }
        }
        return false;
    }
}
