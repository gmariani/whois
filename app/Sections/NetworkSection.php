<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;
use Whois\Providers\ProviderCatalog;
use Whois\Rdap\RdapParser;

/**
 * The web server: its IP, reverse DNS, the network block it belongs to
 * (from the Regional Internet Registry's RDAP server — replaces the old
 * ARIN-only REST lookup, so RIPE/APNIC/LACNIC/AFRINIC addresses work too),
 * its location, and a guess at the hosting provider.
 */
final class NetworkSection implements Section
{
    public function build(Context $context): array
    {
        $servers = $context->authority()['ips'] ?: null;
        $results = $context->dns()->lookupKeyed([[$context->domain, 'A'], [$context->domain, 'AAAA']], $servers);

        $ipv4 = array_column($results[$context->domain . '|A']['records'] ?? [], 'ip');
        $ipv6 = array_column($results[$context->domain . '|AAAA']['records'] ?? [], 'ipv6');
        $ip = $ipv4[0] ?? $ipv6[0] ?? null;

        if ($ip === null) {
            return ['ip' => null, 'ipv4' => [], 'ipv6' => [], 'hostname' => null, 'network' => null, 'location' => null, 'webHost' => null];
        }

        $hostname = $context->dns()->reverse([$ip])[$ip] ?? null;
        $location = $context->geo()->locate($ip);

        $rdap = $context->rdap()->ip($ip);
        $network = is_array($rdap['data']) ? RdapParser::network($rdap['data'], $rdap['url']) : null;

        $webHost = ProviderCatalog::organization([
            $network['organization']['name'] ?? null,
            $location['org'] ?? null,
            $hostname,
            $network['name'] ?? null,
        ]) ?? ($network['organization']['name'] ?? $location['org'] ?? null);

        return [
            'ip' => $ip,
            'ipv4' => $ipv4,
            'ipv6' => $ipv6,
            'hostname' => $hostname,
            'network' => $network,
            'networkError' => $network === null ? ($rdap['error'] ?? 'Unavailable') : null,
            'location' => $location,
            'geoSource' => $context->geo()->source(),
            'webHost' => $webHost,
        ];
    }
}
