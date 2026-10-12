<?php

declare(strict_types=1);

namespace Whois\Support;

/**
 * cURL wrapper for outbound HTTP.
 *
 * Every hop (including redirects) is resolved up front, refused if it points
 * at a non-public address, and pinned with CURLOPT_RESOLVE so DNS can't be
 * rebound between the check and the connection. That matters because some
 * URLs we fetch are attacker-influenced: the user's own domain, and registrar
 * RDAP links advertised inside registry responses.
 */
final class HttpClient
{
    public function __construct(private readonly string $userAgent)
    {
    }

    /**
     * @param array<int,string> $headers
     */
    public function get(
        string $url,
        array $headers = [],
        float $timeout = 6.0,
        int $maxRedirects = 3,
        int $maxBytes = 2_000_000,
    ): HttpResponse {
        $redirects = [];
        while (true) {
            $response = $this->single($url, $headers, $timeout, $maxBytes);
            $response->redirects = $redirects;
            if ($response->status < 300 || $response->status >= 400 || $response->header('location') === null) {
                return $response;
            }
            if (count($redirects) >= $maxRedirects) {
                $response->error = 'Too many redirects';
                return $response;
            }
            $redirects[] = ['url' => $url, 'status' => $response->status];
            $url = self::resolveUrl($url, (string) $response->header('location'));
        }
    }

    /**
     * @param array<int,string> $headers
     */
    private function single(string $url, array $headers, float $timeout, int $maxBytes): HttpResponse
    {
        $response = new HttpResponse($url);
        $parts = parse_url($url);
        $scheme = strtolower($parts['scheme'] ?? '');
        $host = strtolower(trim($parts['host'] ?? '', '[]'));
        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            $response->error = 'Unsupported URL';
            return $response;
        }
        $port = $parts['port'] ?? ($scheme === 'https' ? 443 : 80);

        $ip = $this->resolvePublic($host);
        if ($ip === null) {
            $response->error = 'Host does not resolve to a public address';
            return $response;
        }
        $response->ip = $ip;

        $body = '';
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT_MS => (int) min(4000, $timeout * 1000),
            CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000),
            CURLOPT_USERAGENT => $this->userAgent,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_ENCODING => '',
            CURLOPT_RESOLVE => [sprintf('%s:%d:%s', $host, $port, Ip::isV6($ip) ? "[{$ip}]" : $ip)],
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use ($response): int {
                $trimmed = trim($line);
                if (preg_match('#^HTTP/\S+\s+(\d{3})#', $trimmed, $m)) {
                    // 100-continue etc. — start over for the real status line.
                    $response->status = (int) $m[1];
                    $response->headers = [];
                } elseif (str_contains($trimmed, ':')) {
                    [$name, $value] = explode(':', $trimmed, 2);
                    $response->headers[strtolower(trim($name))][] = trim($value);
                }
                return strlen($line);
            },
            CURLOPT_WRITEFUNCTION => static function ($ch, string $chunk) use (&$body, $maxBytes): int {
                $body .= $chunk;
                // Returning a short count aborts the transfer once we have enough.
                return strlen($body) > $maxBytes ? 0 : strlen($chunk);
            },
        ]);
        if (defined('CURLOPT_PROTOCOLS_STR')) {
            curl_setopt($ch, CURLOPT_PROTOCOLS_STR, 'http,https');
        }

        $ok = curl_exec($ch);
        $errno = curl_errno($ch);
        if (!$ok && $errno !== CURLE_WRITE_ERROR) {
            $response->error = curl_error($ch) ?: 'Request failed';
        }
        $response->body = substr($body, 0, $maxBytes);
        $response->elapsedMs = (int) round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);

        return $response;
    }

    private function resolvePublic(string $host): ?string
    {
        if (Ip::isIp($host)) {
            return Ip::isPublic($host) ? $host : null;
        }
        $ips = @gethostbynamel($host) ?: [];
        if (!$ips) {
            foreach (@dns_get_record($host, DNS_AAAA) ?: [] as $record) {
                $ips[] = $record['ipv6'];
            }
        }
        foreach ($ips as $ip) {
            if (!Ip::isPublic($ip)) {
                // One private answer is enough to refuse the whole host.
                return null;
            }
        }
        return $ips[0] ?? null;
    }

    public static function resolveUrl(string $base, string $location): string
    {
        if (preg_match('#^https?://#i', $location)) {
            return $location;
        }
        $parts = parse_url($base);
        $origin = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
        if (str_starts_with($location, '//')) {
            return $parts['scheme'] . ':' . $location;
        }
        if (str_starts_with($location, '/')) {
            return $origin . $location;
        }
        $path = $parts['path'] ?? '/';
        return $origin . substr($path, 0, (int) strrpos($path, '/') + 1) . $location;
    }
}
