<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;
use Whois\Support\DataFile;

/**
 * DNS has no "list everything" query (ANY/AXFR are refused), so guess:
 * probe well-known subdomains and service records (app/data/subdomains.php)
 * plus DKIM selectors (app/data/dkim-selectors.php), and filter out anything
 * that merely matches a wildcard record.
 */
final class SubdomainsSection implements Section
{
    public function build(Context $context): array
    {
        $started = microtime(true);
        $records = ['a' => [], 'cname' => [], 'txt' => [], 'srv' => []];
        if (!$context->isDelegated()) {
            return ['domains' => [], 'wildcard' => false, 'checked' => 0, 'records' => $records, 'stats' => ['queries' => 0, 'elapsedMs' => 0]];
        }

        $domains = array_values(array_unique([$context->domain, $context->registrableDomain()]));
        $servers = $context->authority()['ips'] ?: null;

        $wildcard = false;
        $checked = 0;

        $names = DataFile::load('subdomains');
        $txtNames = array_merge(
            $names['txt'],
            array_map(fn ($selector) => "{$selector}._domainkey", array_keys(DataFile::load('dkim-selectors'))),
        );

        foreach ($domains as $domain) {
            $probe = 'wildcard-check-' . bin2hex(random_bytes(4)) . '.' . $domain;
            $questions = [[$probe, 'A'], [$probe, 'TXT']];
            foreach ($names['hosts'] as $sub) {
                $questions[] = ["{$sub}.{$domain}", 'A'];
            }
            foreach ($txtNames as $sub) {
                $questions[] = ["{$sub}.{$domain}", 'TXT'];
            }
            foreach ($names['srv'] as $sub) {
                $questions[] = ["{$sub}.{$domain}", 'SRV'];
            }
            $checked += count($questions) - 2;

            // Only the alias itself matters here, so don't chase CNAMEs out of the zone.
            $results = $context->dns()->lookupKeyed($questions, $servers, false);

            // Anything a random name also returns is wildcard noise.
            $wild = ['ips' => [], 'targets' => [], 'txt' => []];
            foreach (['A', 'TXT'] as $type) {
                $result = $results["{$probe}|{$type}"] ?? null;
                if (!$result) {
                    continue;
                }
                foreach ($result['chain'] as $cname) {
                    $wild['targets'][] = $cname['target'];
                    $records['cname'][] = ['host' => "*.{$domain}"] + $cname;
                    $wildcard = true;
                }
                if (!$result['chain']) {
                    foreach ($result['records'] as $record) {
                        $wildcard = true;
                        $records[strtolower($type)][] = ['host' => "*.{$domain}"] + $record;
                        if ($type === 'A') {
                            $wild['ips'][] = $record['ip'];
                        } else {
                            $wild['txt'][] = $record['txt'];
                        }
                    }
                }
                unset($results["{$probe}|{$type}"]);
            }

            foreach ($results as $result) {
                if ($result['chain']) {
                    $cname = $result['chain'][0];
                    if (!in_array($cname['target'], $wild['targets'], true)) {
                        $records['cname'][] = $cname;
                    }
                    continue;
                }
                $own = array_values(array_filter($result['records'], fn ($r) => $r['host'] === $result['name']));
                if (!$own) {
                    continue;
                }
                $type = strtolower($result['type']);
                if ($type === 'a' && !array_diff(array_column($own, 'ip'), $wild['ips'])) {
                    continue;
                }
                if ($type === 'txt' && !array_diff(array_column($own, 'txt'), $wild['txt'])) {
                    continue;
                }
                array_push($records[$type], ...$own);
            }
        }

        foreach ($records as $type => $list) {
            $records[$type] = DnsSection::unique($list);
            usort($records[$type], fn ($a, $b) => strcmp($a['host'], $b['host']));
        }

        return [
            'domains' => $domains,
            'wildcard' => $wildcard,
            'checked' => $checked,
            'records' => $records,
            'stats' => ['queries' => $context->dns()->client->queries, 'elapsedMs' => (int) round((microtime(true) - $started) * 1000)],
        ];
    }
}
