<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;

/**
 * Where the web, mail and name servers are, for the map and for the
 * "who runs this IP" tooltips in the DNS table.
 */
final class LocationsSection implements Section
{
    public function build(Context $context): array
    {
        $dns = $context->section('dns');
        $records = $dns['records'];
        $targets = $dns['targets'];

        $servers = [];
        foreach ($records['a'] as $record) {
            $servers[] = ['role' => 'Web Server', 'host' => $record['host'], 'ip' => $record['ip']];
        }
        foreach ($records['aaaa'] as $record) {
            $servers[] = ['role' => 'Web Server', 'host' => $record['host'], 'ip' => $record['ipv6']];
        }
        foreach ($records['cname'] as $record) {
            foreach ($targets[$record['target']] ?? [] as $ip) {
                $servers[] = ['role' => 'Web Server', 'host' => $record['target'], 'ip' => $ip];
            }
        }
        foreach ($records['mx'] as $record) {
            foreach ($targets[$record['target']] ?? [] as $ip) {
                $servers[] = ['role' => 'Email Server', 'host' => $record['target'], 'ip' => $ip];
            }
        }
        foreach ($records['ns'] as $record) {
            foreach ($targets[$record['target']] ?? [] as $ip) {
                $servers[] = ['role' => 'Name Server', 'host' => $record['target'], 'ip' => $ip];
            }
        }

        $ips = array_values(array_unique(array_column($servers, 'ip')));
        $locations = $context->geo()->locateMany($ips);
        $hostnames = $context->dns()->reverse($ips);

        $info = [];
        foreach ($ips as $ip) {
            $info[$ip] = ['hostname' => $hostnames[$ip] ?? null, 'location' => $locations[$ip] ?? null];
        }

        // One marker per coordinate, listing everything hosted there.
        $markers = [];
        foreach ($servers as $server) {
            $location = $locations[$server['ip']] ?? null;
            if (!isset($location['lat'], $location['lon']) || ($location['lat'] == 0 && $location['lon'] == 0)) {
                continue;
            }
            $key = $location['lat'] . ',' . $location['lon'];
            $markers[$key] ??= ['lat' => $location['lat'], 'lng' => $location['lon'], 'servers' => []];
            $markers[$key]['servers'][] = $server + ['org' => $location['org'] ?? null, 'anycast' => $location['anycast'] ?? null];
        }

        return [
            'ips' => (object) $info,
            'markers' => array_values($markers),
            'geoSource' => $context->geo()->source(),
        ];
    }
}
