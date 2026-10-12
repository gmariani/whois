<?php

declare(strict_types=1);

namespace Whois\Rdap;

use Whois\Support\Cache;
use Whois\Support\DomainName;
use Whois\Support\HttpClient;

/**
 * Queries the registry (and, for thin registries like .com, the registrar)
 * RDAP servers directly instead of going through a third-party lookup API.
 */
final class RdapClient
{
    private const ACCEPT = ['Accept: application/rdap+json, application/json;q=0.9'];

    public function __construct(
        private readonly HttpClient $http,
        private readonly Cache $cache,
        private readonly RdapBootstrap $bootstrap,
    ) {
    }

    public function hasServerFor(string $domain): bool
    {
        return $this->bootstrap->forTld(DomainName::tld($domain)) !== null;
    }

    /**
     * @return array{status:int,url:?string,data:?array,error:?string}
     */
    public function domain(string $domain): array
    {
        $base = $this->bootstrap->forTld(DomainName::tld($domain));
        if ($base === null) {
            return ['status' => 0, 'url' => null, 'data' => null, 'error' => 'No RDAP server for this TLD'];
        }
        return $this->fetch($base . 'domain/' . rawurlencode($domain), 3600);
    }

    /**
     * Follow the registry's "related" link to the registrar's RDAP record,
     * which (for thin registries) is where contact details live.
     *
     * @return array{status:int,url:?string,data:?array,error:?string}|null
     */
    public function registrarRecord(array $registryRecord): ?array
    {
        $self = null;
        foreach ($registryRecord['links'] ?? [] as $link) {
            if (($link['rel'] ?? '') === 'self') {
                $self = $link['href'] ?? null;
            }
        }
        foreach ($registryRecord['links'] ?? [] as $link) {
            $href = $link['href'] ?? '';
            $type = $link['type'] ?? 'application/rdap+json';
            if (($link['rel'] ?? '') === 'related' && $href !== $self && str_contains($type, 'json') && preg_match('#^https?://#', $href)) {
                return $this->fetch($href, 3600, 5.0);
            }
        }
        return null;
    }

    /**
     * @return array{status:int,url:?string,data:?array,error:?string}
     */
    public function ip(string $ip): array
    {
        $base = $this->bootstrap->forIp($ip);
        if ($base === null) {
            return ['status' => 0, 'url' => null, 'data' => null, 'error' => 'No RDAP server for this address'];
        }
        return $this->fetch($base . 'ip/' . rawurlencode($ip), 86400);
    }

    /**
     * @return array{status:int,url:?string,data:?array,error:?string}
     */
    private function fetch(string $url, int $ttl, float $timeout = 8.0): array
    {
        $key = 'rdap:' . $url;
        if (is_array($cached = $this->cache->get($key))) {
            return $cached;
        }

        $response = $this->http->get($url, self::ACCEPT, $timeout);
        $result = [
            'status' => $response->status,
            'url' => $response->url,
            'data' => $response->ok() ? $response->json() : null,
            'error' => $response->error ?? ($response->ok() ? null : "HTTP {$response->status}"),
        ];
        // Only cache real answers; timeouts and 5xx should be retried next time.
        if ($response->status === 200 || $response->status === 404) {
            $this->cache->set($key, $result, $ttl);
        }
        return $result;
    }
}
