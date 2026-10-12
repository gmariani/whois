<?php

declare(strict_types=1);

namespace Whois\Rdap;

use Whois\Support\Cache;
use Whois\Support\HttpClient;
use Whois\Support\Ip;

/**
 * IANA's RDAP bootstrap registry (RFC 9224): which server is authoritative
 * for a TLD or IP block. Refreshed daily.
 */
final class RdapBootstrap
{
    private const SOURCES = [
        'dns' => 'https://data.iana.org/rdap/dns.json',
        'ipv4' => 'https://data.iana.org/rdap/ipv4.json',
        'ipv6' => 'https://data.iana.org/rdap/ipv6.json',
    ];

    /** @var array<string,array<int,array{0:list<string>,1:list<string>}>> */
    private array $loaded = [];

    public function __construct(
        private readonly HttpClient $http,
        private readonly Cache $cache,
    ) {
    }

    public function forTld(string $tld): ?string
    {
        foreach ($this->services('dns') as [$tlds, $urls]) {
            if (in_array($tld, $tlds, true)) {
                return self::pickUrl($urls);
            }
        }
        return null;
    }

    public function forIp(string $ip): ?string
    {
        $best = null;
        $bestLength = -1;
        foreach ($this->services(Ip::isV6($ip) ? 'ipv6' : 'ipv4') as [$prefixes, $urls]) {
            foreach ($prefixes as $prefix) {
                $length = (int) (explode('/', $prefix)[1] ?? 0);
                if ($length > $bestLength && Ip::inCidr($ip, $prefix)) {
                    $best = self::pickUrl($urls);
                    $bestLength = $length;
                }
            }
        }
        return $best;
    }

    /**
     * @return array<int,array{0:list<string>,1:list<string>}>
     */
    private function services(string $kind): array
    {
        if (!isset($this->loaded[$kind])) {
            $this->loaded[$kind] = $this->cache->remember("rdap-bootstrap:{$kind}", 86400, function () use ($kind): ?array {
                $response = $this->http->get(self::SOURCES[$kind], ['Accept: application/json'], 8.0);
                return $response->json()['services'] ?? null;
            }) ?? [];
        }
        return $this->loaded[$kind];
    }

    /**
     * @param list<string> $urls
     */
    private static function pickUrl(array $urls): ?string
    {
        foreach ($urls as $url) {
            if (str_starts_with($url, 'https://')) {
                return rtrim($url, '/') . '/';
            }
        }
        return isset($urls[0]) ? rtrim($urls[0], '/') . '/' : null;
    }
}
