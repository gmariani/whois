<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;
use Whois\Providers\ProviderCatalog;
use Whois\Support\DomainName;

/**
 * Records at the domain itself, asked of the zone's own name servers in one
 * parallel batch. DS records come from the parent zone's servers.
 */
final class DnsSection implements Section
{
    private const DOMAIN_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'NAPTR'];

    public function build(Context $context): array
    {
        $started = microtime(true);
        $domain = $context->domain;
        $dns = $context->dns();

        if (!$context->isDelegated()) {
            return [
                'zone' => null,
                'delegated' => false,
                'nameservers' => [],
                'records' => array_fill_keys(['soa', 'ns', 'a', 'aaaa', 'cname', 'mx', 'txt', 'caa', 'naptr', 'dnskey', 'ds', 'dmarc', 'ptr'], []),
                'targets' => [],
                'dsServer' => null,
                'dnsHosts' => [],
                'stats' => ['queries' => $dns->client->queries, 'elapsedMs' => (int) round((microtime(true) - $started) * 1000)],
            ];
        }

        $authority = $context->authority();
        $zone = $authority['zone'];
        $servers = $authority['ips'] ?: null;

        $questions = [[$zone, 'SOA'], [$zone, 'NS'], [$zone, 'DNSKEY'], ["_dmarc.{$domain}", 'TXT']];
        foreach (self::DOMAIN_TYPES as $type) {
            $questions[] = [$domain, $type];
        }
        $results = $dns->lookupKeyed($questions, $servers);

        $records = array_fill_keys(['soa', 'ns', 'a', 'aaaa', 'cname', 'mx', 'txt', 'caa', 'naptr', 'dnskey', 'ds', 'dmarc', 'ptr'], []);
        $records['soa'] = $results["{$zone}|SOA"]['records'] ?? [];
        $records['ns'] = $results["{$zone}|NS"]['records'] ?? [];
        $records['dnskey'] = $results["{$zone}|DNSKEY"]['records'] ?? [];
        $records['dmarc'] = self::onlyOwn($results["_dmarc.{$domain}|TXT"] ?? null, $records['cname']);

        foreach (self::DOMAIN_TYPES as $type) {
            $key = strtolower($type);
            $records[$key] = array_merge($records[$key], self::onlyOwn($results["{$domain}|{$type}"] ?? null, $records['cname']));
        }
        $records['cname'] = self::unique($records['cname']);
        usort($records['mx'], fn ($a, $b) => $a['pri'] <=> $b['pri']);

        // DS lives in the parent zone (com, co.uk…), so ask the parent's servers.
        $dsServer = null;
        $parent = DomainName::parent($zone);
        if ($parent !== null && ($parentZone = $dns->zoneApex($parent)) !== null) {
            $parentAuthority = $dns->authority($parentZone);
            $ds = $dns->lookup([[$zone, 'DS']], $parentAuthority['ips'] ?: null)[0];
            $records['ds'] = $ds['records'];
            $dsServer = $parentAuthority['nameservers'][0]['host'] ?? $parentZone;
        }

        // Reverse DNS for the first web server address.
        $primaryIp = $records['a'][0]['ip'] ?? $records['aaaa'][0]['ipv6'] ?? null;
        if ($primaryIp === null) {
            // A CNAME'd name has no A of its own; follow it for the PTR.
            $chased = $results["{$domain}|A"]['records'] ?? [];
            $primaryIp = $chased[0]['ip'] ?? null;
        }
        if ($primaryIp !== null && ($arpa = \Whois\Support\Ip::arpa($primaryIp)) !== null) {
            $records['ptr'] = $dns->lookup([[$arpa, 'PTR']])[0]['records'];
        }

        // Addresses of everything the records point at, for tooltips and the map.
        $hosts = array_merge(
            array_column($records['ns'], 'target'),
            array_column($records['mx'], 'target'),
            array_column($records['cname'], 'target'),
        );
        $targets = $dns->addresses($hosts);

        return [
            'zone' => $zone,
            'delegated' => true,
            'nameservers' => $authority['nameservers'],
            'records' => $records,
            'targets' => $targets,
            'dsServer' => $dsServer,
            'dnsHosts' => ProviderCatalog::dnsHosts(array_column($records['ns'], 'target')),
            'stats' => ['queries' => $dns->client->queries, 'elapsedMs' => (int) round((microtime(true) - $started) * 1000)],
        ];
    }

    /**
     * Records owned by the queried name itself. If the name turned out to be a
     * CNAME, keep only the CNAME (an alias can't have other records of its own).
     *
     * @param array<string,mixed>|null $result
     * @param list<array<string,mixed>> $cnames collects alias records
     * @return list<array<string,mixed>>
     */
    public static function onlyOwn(?array $result, array &$cnames): array
    {
        if ($result === null) {
            return [];
        }
        if ($result['chain']) {
            $cnames[] = $result['chain'][0];
            return [];
        }
        return array_values(array_filter($result['records'], fn ($r) => $r['host'] === $result['name']));
    }

    /**
     * @param list<array<string,mixed>> $records
     * @return list<array<string,mixed>>
     */
    public static function unique(array $records): array
    {
        $seen = [];
        $out = [];
        foreach ($records as $record) {
            $copy = $record;
            unset($copy['ttl']);
            $key = md5((string) json_encode($copy));
            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $out[] = $record;
            }
        }
        return $out;
    }
}
