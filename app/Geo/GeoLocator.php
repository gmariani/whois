<?php

declare(strict_types=1);

namespace Whois\Geo;

use MaxMind\Db\Reader;
use Whois\Support\Cache;
use Whois\Support\Ip;

/**
 * IP => approximate location + network operator. Sources, in order:
 *
 * 1. ipinfo.io (when IP_INFO holds a token): best city-level data, but the
 *    free plan has a monthly quota. When it answers 429 we stop asking for an
 *    hour and let the next source take over.
 * 2. A local MaxMind-format database (DB-IP "lite" or GeoLite2; see
 *    app/bin/update-geoip.php): no API calls or limits.
 * 3. ip-api.com's batch endpoint, only if the local database isn't installed.
 *
 * API answers are cached per IP for a week, so repeat lookups cost no quota.
 */
final class GeoLocator
{
    private ?Reader $city = null;
    private ?Reader $asn = null;
    public int $apiCalls = 0;

    private const IPINFO_PAUSE_KEY = 'geo:ipinfo:paused';
    private const IPINFO_PAUSE_SECONDS = 3600;
    private const CACHE_TTL = 86400 * 7;

    /** @var array<string,string> source used per IP during this request */
    private array $sources = [];

    public function __construct(
        string $cityDb,
        string $asnDb,
        private readonly Cache $cache,
        private readonly bool $fallbackToIpApi,
        private readonly ?string $ipinfoToken = null,
    ) {
        try {
            $this->city = is_file($cityDb) ? new Reader($cityDb) : null;
            $this->asn = is_file($asnDb) ? new Reader($asnDb) : null;
        } catch (\Throwable $e) {
            error_log('GeoIP database unreadable: ' . $e->getMessage());
        }
    }

    /** Which source(s) answered during this request, e.g. "ipinfo" or "ipinfo+local". */
    public function source(): string
    {
        $used = array_values(array_unique($this->sources));
        if ($used) {
            return implode('+', $used);
        }
        return $this->city ? 'local' : ($this->fallbackToIpApi ? 'ip-api' : 'none');
    }

    /**
     * @param list<string> $ips
     * @return array<string,array{city:?string,region:?string,country:?string,countryCode:?string,lat:?float,lon:?float,asn:?int,org:?string,anycast:?bool}|null>
     */
    public function locateMany(array $ips): array
    {
        $ips = array_values(array_unique(array_filter($ips, fn ($ip) => Ip::isIp($ip))));
        $out = [];
        $missing = [];
        foreach ($ips as $ip) {
            if (Ip::isPublic($ip)) {
                $missing[] = $ip;
            } else {
                $out[$ip] = null;
            }
        }

        if ($missing && $this->ipinfoToken) {
            foreach ($this->fromIpinfo($missing) as $ip => $location) {
                $out[$ip] = $location;
                $this->sources[$ip] = 'ipinfo';
            }
            $missing = array_values(array_diff($missing, array_keys($out)));
        }

        if ($missing && $this->city) {
            foreach ($missing as $ip) {
                $out[$ip] = $this->fromDatabase($ip);
                $this->sources[$ip] = 'local';
            }
            $missing = [];
        }

        if ($missing && $this->fallbackToIpApi) {
            foreach ($this->fromIpApi($missing) as $ip => $location) {
                $out[$ip] = $location;
                $this->sources[$ip] = 'ip-api';
            }
        }
        return $out;
    }

    public function locate(string $ip): ?array
    {
        return $this->locateMany([$ip])[$ip] ?? null;
    }

    private function fromDatabase(string $ip): ?array
    {
        try {
            $city = $this->city?->get($ip);
            $asn = $this->asn?->get($ip);
        } catch (\Throwable) {
            return null;
        }
        if (!$city && !$asn) {
            return null;
        }
        return [
            'city' => $city['city']['names']['en'] ?? null,
            'region' => $city['subdivisions'][0]['names']['en'] ?? null,
            'country' => $city['country']['names']['en'] ?? null,
            'countryCode' => $city['country']['iso_code'] ?? null,
            'lat' => isset($city['location']['latitude']) ? (float) $city['location']['latitude'] : null,
            'lon' => isset($city['location']['longitude']) ? (float) $city['location']['longitude'] : null,
            'asn' => isset($asn['autonomous_system_number']) ? (int) $asn['autonomous_system_number'] : null,
            'org' => $asn['autonomous_system_organization'] ?? null,
            'anycast' => null, // unknown: the database can't tell
        ];
    }

    /**
     * ipinfo.io batch API. Returns only the IPs it answered; anything missing
     * (quota reached, outage, bad token) falls through to the next source.
     *
     * @param list<string> $ips
     * @return array<string,?array>
     */
    private function fromIpinfo(array $ips): array
    {
        $out = [];
        $uncached = [];
        foreach ($ips as $ip) {
            $cached = $this->cache->get("geo:ipinfo:{$ip}");
            if (is_array($cached)) {
                $out[$ip] = $cached ?: null;
            } else {
                $uncached[] = $ip;
            }
        }
        if (!$uncached || $this->cache->get(self::IPINFO_PAUSE_KEY)) {
            return $out;
        }

        foreach (array_chunk($uncached, 100) as $chunk) {
            $ch = curl_init('https://ipinfo.io/batch?token=' . rawurlencode((string) $this->ipinfoToken));
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => json_encode($chunk),
                CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_TIMEOUT => 5,
            ]);
            $body = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $this->apiCalls++;

            // The batch endpoint reports errors per IP inside a 200 response
            // ({"8.8.8.8": {"status": 429, "error": {…}}}), so check both levels.
            $rows = $status === 200 && is_string($body) ? (json_decode($body, true) ?: []) : [];
            $errorStatus = $status !== 200 ? $status : null;
            foreach ($rows as $row) {
                if (is_array($row) && isset($row['error'])) {
                    $errorStatus = (int) ($row['status'] ?? 500);
                    break;
                }
            }

            if (in_array($errorStatus, [401, 403, 429], true)) {
                // 429: monthly quota used up. 401/403: bad token. Either way, stop
                // asking for a while; the local database covers the gap.
                $reason = json_decode((string) $body, true)['error'] ?? null;
                $reason = is_array($reason) ? ($reason['message'] ?? $reason['title'] ?? '') : (string) $reason;
                error_log("ipinfo.io returned HTTP {$errorStatus} ({$reason}); using the local database for the next hour");
                $this->cache->set(self::IPINFO_PAUSE_KEY, $errorStatus, self::IPINFO_PAUSE_SECONDS);
                break;
            }
            if ($errorStatus !== null) {
                error_log("ipinfo.io batch failed with HTTP {$errorStatus}");
                break;
            }

            foreach ($rows as $ip => $row) {
                if (!is_array($row) || !in_array($ip, $chunk, true)) {
                    continue;
                }
                $location = null;
                if (empty($row['bogon'])) {
                    [$lat, $lon] = array_pad(array_map('floatval', explode(',', (string) ($row['loc'] ?? ''))), 2, null);
                    $code = $row['country'] ?? null;
                    $location = [
                        'city' => ($row['city'] ?? '') ?: null,
                        'region' => ($row['region'] ?? '') ?: null,
                        'country' => $code ? $this->countryName($code, $ip) : null,
                        'countryCode' => $code,
                        'lat' => isset($row['loc']) ? $lat : null,
                        'lon' => isset($row['loc']) ? $lon : null,
                        // "AS15169 Google LLC"
                        'asn' => preg_match('/^AS(\d+)/', $row['org'] ?? '', $m) ? (int) $m[1] : null,
                        'org' => trim((string) preg_replace('/^AS\d+\s*/', '', $row['org'] ?? '')) ?: null,
                        // Announced from many sites (common for DNS/CDNs); the city is just one of them.
                        'anycast' => !empty($row['anycast']),
                    ];
                }
                $out[$ip] = $location;
                $this->cache->set("geo:ipinfo:{$ip}", $location ?? [], self::CACHE_TTL);
            }
        }
        return $out;
    }

    /** ipinfo gives ISO codes only; prefer the local database's English name. */
    private function countryName(string $code, string $ip): string
    {
        try {
            $name = $this->city?->get($ip)['country']['names']['en'] ?? null;
            if ($name && ($this->city->get($ip)['country']['iso_code'] ?? null) === $code) {
                return $name;
            }
        } catch (\Throwable) {
        }
        if (class_exists(\Locale::class)) {
            $name = \Locale::getDisplayRegion('-' . $code, 'en');
            if ($name !== '' && $name !== $code) {
                return $name;
            }
        }
        return $code;
    }

    /**
     * ip-api free tier: 15 batch requests/minute, 100 IPs each, HTTP only.
     *
     * @param list<string> $ips
     * @return array<string,?array>
     */
    private function fromIpApi(array $ips): array
    {
        $out = [];
        $uncached = [];
        foreach ($ips as $ip) {
            $cached = $this->cache->get("geo:{$ip}");
            if (is_array($cached)) {
                $out[$ip] = $cached ?: null;
            } else {
                $uncached[] = $ip;
            }
        }

        foreach (array_chunk($uncached, 100) as $chunk) {
            $ch = curl_init('http://ip-api.com/batch?fields=status,query,country,countryCode,regionName,city,lat,lon,as,org,isp');
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => json_encode($chunk),
                CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 3,
                CURLOPT_TIMEOUT => 5,
            ]);
            $body = curl_exec($ch);
            $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $this->apiCalls++;
            if ($status !== 200 || !is_string($body)) {
                error_log("ip-api batch failed with HTTP {$status}");
                continue;
            }
            foreach (json_decode($body, true) ?: [] as $row) {
                $ip = $row['query'] ?? null;
                if ($ip === null) {
                    continue;
                }
                $location = ($row['status'] ?? '') !== 'success' ? null : [
                    'city' => $row['city'] ?: null,
                    'region' => $row['regionName'] ?: null,
                    'country' => $row['country'] ?: null,
                    'countryCode' => $row['countryCode'] ?: null,
                    'lat' => isset($row['lat']) ? (float) $row['lat'] : null,
                    'lon' => isset($row['lon']) ? (float) $row['lon'] : null,
                    'asn' => preg_match('/^AS(\d+)/', $row['as'] ?? '', $m) ? (int) $m[1] : null,
                    'org' => ($row['org'] ?? '') ?: ($row['isp'] ?? null),
                    'anycast' => null,
                ];
                $out[$ip] = $location;
                $this->cache->set("geo:{$ip}", $location ?? [], self::CACHE_TTL);
            }
        }
        return $out;
    }
}
