<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;
use Whois\Providers\ProviderCatalog;
use Whois\Support\DataFile;
use Whois\Support\Ip;

/**
 * SPF, DKIM and DMARC records, plus who handles the domain's mail.
 */
final class EmailSection implements Section
{
    private const SPF_LOOKUP_LIMIT = 10;
    private const SPF_MAX_RECORDS = 40;

    public function build(Context $context): array
    {
        $dnsData = $context->section('dns');
        $domain = $context->domain;

        return [
            'spf' => $this->spf($context, $domain, $dnsData['records']['txt']),
            'dkim' => $this->dkim($context, $domain),
            'dmarc' => self::dmarc($dnsData['records']['dmarc']),
            'emailHost' => $this->emailHost($context, $domain, $dnsData['records']['mx'], $dnsData['targets']),
            'dane' => $this->dane($context, $dnsData['records']['mx']),
            'dkimSelectors' => DataFile::load('dkim-selectors'),
        ];
    }

    // ---------------------------------------------------------------- SPF

    /**
     * @param list<array<string,mixed>> $txtRecords
     * @return array<string,mixed>|null
     */
    private function spf(Context $context, string $domain, array $txtRecords): ?array
    {
        $raws = [];
        foreach ($txtRecords as $record) {
            if (preg_match('/^v=spf1(\s|$)/i', trim($record['txt']))) {
                $raws[] = trim($record['txt']);
            }
        }
        if (!$raws) {
            return null;
        }

        // Fetch everything reachable through include:/redirect= (breadth first, batched).
        $known = [$domain => self::parseSpf($raws[0])];
        $frontier = self::referencedDomains($known[$domain]);
        for ($depth = 0; $frontier && $depth < 10 && count($known) < self::SPF_MAX_RECORDS; $depth++) {
            $questions = array_map(fn ($d) => [$d, 'TXT'], $frontier);
            $next = [];
            foreach ($context->dns()->lookup($questions) as $result) {
                $raw = null;
                foreach ($result['records'] as $record) {
                    if (preg_match('/^v=spf1(\s|$)/i', trim($record['txt']))) {
                        $raw = trim($record['txt']);
                        break;
                    }
                }
                $known[$result['name']] = $raw === null ? null : self::parseSpf($raw);
                foreach ($raw === null ? [] : self::referencedDomains($known[$result['name']]) as $d) {
                    if (!array_key_exists($d, $known)) {
                        $next[$d] = $d;
                    }
                }
            }
            $frontier = array_values($next);
        }

        $terms = $known[$domain]['terms'];
        $this->resolveTerms($context, $domain, $terms);

        $lookups = self::countLookups($domain, $known, []);
        $all = null;
        foreach ($terms as $term) {
            if (($term['mechanism'] ?? null) === 'all') {
                $all = $term['qualifier'];
            }
        }

        $warnings = [];
        if (count($raws) > 1) {
            $warnings[] = 'More than one SPF record is published; receivers will treat this as a permanent error (RFC 7208 §4.5).';
        }
        if ($lookups > self::SPF_LOOKUP_LIMIT) {
            $warnings[] = "SPF evaluation needs {$lookups} DNS lookups; the limit is " . self::SPF_LOOKUP_LIMIT . ', so receivers will fail it with a permerror.';
        }
        if ($all === null && !self::hasRedirect($terms)) {
            $warnings[] = 'No "all" mechanism: mail from unlisted servers gets a neutral result.';
        } elseif ($all === 'pass') {
            $warnings[] = '"+all" lets any server on the internet send mail as this domain.';
        }

        $includes = [];
        foreach ($known as $name => $record) {
            if ($name !== $domain) {
                $includes[$name] = $record === null ? null : ['raw' => $record['raw'], 'terms' => $record['terms']];
            }
        }

        return [
            'raw' => $raws[0],
            'records' => $raws,
            'terms' => $terms,
            'includes' => $includes,
            'lookups' => $lookups,
            'lookupLimit' => self::SPF_LOOKUP_LIMIT,
            'all' => $all,
            'warnings' => $warnings,
        ];
    }

    /**
     * @return array{raw:string,terms:list<array<string,mixed>>}
     */
    public static function parseSpf(string $raw): array
    {
        $terms = [];
        $tokens = preg_split('/\s+/', trim($raw)) ?: [];
        array_shift($tokens); // v=spf1
        foreach ($tokens as $token) {
            if ($token === '') {
                continue;
            }
            if (preg_match('/^([a-z][a-z0-9_.-]*)=(.*)$/i', $token, $m)) {
                $terms[] = ['kind' => 'modifier', 'mechanism' => strtolower($m[1]), 'value' => $m[2], 'qualifier' => null, 'raw' => $token];
                continue;
            }
            $qualifier = match ($token[0]) {
                '-' => 'fail',
                '~' => 'softfail',
                '?' => 'neutral',
                default => 'pass', // "+" or no prefix (RFC 7208 §4.6.2)
            };
            $body = ltrim($token, '+-~?');
            preg_match('#^([a-z0-9]+)(?::([^/]*))?(/\d+)?(//\d+)?$#i', $body, $m);
            $terms[] = [
                'kind' => 'mechanism',
                'qualifier' => $qualifier,
                'mechanism' => strtolower($m[1] ?? $body),
                'value' => ($m[2] ?? '') !== '' ? $m[2] : null,
                'cidr' => ($m[3] ?? '') !== '' ? $m[3] : null,
                'raw' => $token,
            ];
        }
        return ['raw' => $raw, 'terms' => $terms];
    }

    /**
     * @param array{raw:string,terms:list<array<string,mixed>>}|null $record
     * @return list<string>
     */
    private static function referencedDomains(?array $record): array
    {
        $out = [];
        foreach ($record['terms'] ?? [] as $term) {
            $isInclude = $term['kind'] === 'mechanism' && $term['mechanism'] === 'include';
            $isRedirect = $term['kind'] === 'modifier' && $term['mechanism'] === 'redirect';
            // Skip macro-expanded names (%{i}…); they depend on the sending IP.
            if (($isInclude || $isRedirect) && $term['value'] && !str_contains($term['value'], '%')) {
                $out[] = strtolower(rtrim($term['value'], '.'));
            }
        }
        return array_values(array_unique($out));
    }

    /**
     * RFC 7208 §4.6.4: include, a, mx, ptr, exists and redirect each cost a lookup.
     *
     * @param array<string,?array> $known
     * @param array<string,bool> $seen
     */
    private static function countLookups(string $domain, array $known, array $seen): int
    {
        if (isset($seen[$domain]) || empty($known[$domain])) {
            return 0;
        }
        $seen[$domain] = true;
        $count = 0;
        foreach ($known[$domain]['terms'] as $term) {
            $name = $term['mechanism'];
            if (in_array($name, ['a', 'mx', 'ptr', 'exists'], true)) {
                $count++;
            } elseif ($name === 'include' || ($term['kind'] === 'modifier' && $name === 'redirect')) {
                $count++;
                if ($term['value']) {
                    $count += self::countLookups(strtolower(rtrim($term['value'], '.')), $known, $seen);
                }
            }
        }
        return $count;
    }

    /**
     * @param list<array<string,mixed>> $terms
     */
    private static function hasRedirect(array $terms): bool
    {
        foreach ($terms as $term) {
            if ($term['kind'] === 'modifier' && $term['mechanism'] === 'redirect') {
                return true;
            }
        }
        return false;
    }

    /**
     * Attach the servers each top-level a/mx/ip term actually covers.
     *
     * @param list<array<string,mixed>> $terms
     */
    private function resolveTerms(Context $context, string $domain, array &$terms): void
    {
        $dns = $context->dns();

        $aHosts = [];
        $mxDomains = [];
        foreach ($terms as $term) {
            if ($term['mechanism'] === 'a') {
                $aHosts[] = $term['value'] ?? $domain;
            } elseif ($term['mechanism'] === 'mx') {
                $mxDomains[] = $term['value'] ?? $domain;
            }
        }

        $mxTargets = [];
        foreach ($dns->lookup(array_map(fn ($d) => [$d, 'MX'], array_unique($mxDomains))) as $result) {
            $mxTargets[$result['name']] = array_column($result['records'], 'target');
        }
        $addresses = $dns->addresses(array_merge($aHosts, ...array_values($mxTargets ?: [[]])));

        $ips = [];
        foreach ($terms as &$term) {
            $servers = [];
            switch ($term['mechanism']) {
                case 'ip4':
                case 'ip6':
                    $single = $term['value'] && ($term['cidr'] === null || in_array($term['cidr'], ['/32', '/128'], true));
                    if ($single && Ip::isIp($term['value'])) {
                        $servers[] = ['host' => null, 'ip' => $term['value']];
                    }
                    break;
                case 'a':
                    $host = $term['value'] ?? $domain;
                    foreach ($addresses[$host] ?? [] as $ip) {
                        $servers[] = ['host' => $host, 'ip' => $ip];
                    }
                    break;
                case 'mx':
                    foreach ($mxTargets[$term['value'] ?? $domain] ?? [] as $host) {
                        foreach ($addresses[$host] ?? [] as $ip) {
                            $servers[] = ['host' => $host, 'ip' => $ip];
                        }
                    }
                    break;
            }
            $term['servers'] = $servers;
            array_push($ips, ...array_column($servers, 'ip'));
        }
        unset($term);

        if (!$ips) {
            return;
        }
        $locations = $context->geo()->locateMany($ips);
        $hostnames = $dns->reverse(array_slice(array_values(array_unique($ips)), 0, 40));
        foreach ($terms as &$term) {
            foreach ($term['servers'] as &$server) {
                $server['hostname'] = $hostnames[$server['ip']] ?? null;
                $server['location'] = $locations[$server['ip']] ?? null;
            }
            unset($server);
        }
        unset($term);
    }

    // ---------------------------------------------------------------- DKIM

    /**
     * @return list<array<string,mixed>>
     */
    private function dkim(Context $context, string $domain): array
    {
        $selectors = DataFile::load('dkim-selectors');
        $questions = [];
        foreach (array_keys($selectors) as $selector) {
            $questions[] = ["{$selector}._domainkey.{$domain}", 'TXT'];
        }
        $servers = $context->authority()['ips'] ?: null;

        $keys = [];
        foreach ($context->dns()->lookup($questions, $servers) as $result) {
            foreach ($result['records'] as $record) {
                $txt = trim($record['txt']);
                // Some providers omit v=DKIM1, so also accept a bare key record.
                if (!preg_match('/(^|;)\s*(v=DKIM1|k=|p=)/i', $txt)) {
                    continue;
                }
                $selector = substr($result['name'], 0, (int) strpos($result['name'], '._domainkey.'));
                $keys[] = self::parseDkim($selector, $result['name'], $txt) + [
                    'provider' => $selectors[$selector] ?? null,
                    'cname' => $result['chain'] ? end($result['chain'])['target'] : null,
                ];
            }
        }
        return $keys;
    }

    /**
     * @return array<string,mixed>
     */
    public static function parseDkim(string $selector, string $host, string $txt): array
    {
        $tags = [];
        foreach (explode(';', $txt) as $part) {
            if (str_contains($part, '=')) {
                [$key, $value] = explode('=', $part, 2);
                $tags[strtolower(trim($key))] = trim($value);
            }
        }
        $keyType = strtolower($tags['k'] ?? 'rsa');
        $p = preg_replace('/\s+/', '', $tags['p'] ?? '');

        $bits = null;
        $pem = null;
        if ($p !== '') {
            $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($p, 64, "\n") . '-----END PUBLIC KEY-----';
            if ($keyType === 'ed25519') {
                $bits = 256;
            } else {
                $key = @openssl_pkey_get_public($pem);
                $bits = $key ? (openssl_pkey_get_details($key)['bits'] ?? null) : null;
            }
        }

        return [
            'selector' => $selector,
            'host' => $host,
            'tags' => $tags,
            'keyType' => $keyType,
            'keyBits' => $bits,
            'publicKey' => $pem,
            'revoked' => $p === '',
            'testing' => in_array('y', array_map('trim', explode(':', strtolower($tags['t'] ?? ''))), true),
            'weak' => $bits !== null && $keyType === 'rsa' && $bits < 1024,
            'raw' => $txt,
        ];
    }

    // --------------------------------------------------------------- DMARC

    /**
     * @param list<array<string,mixed>> $records
     * @return array<string,mixed>|null
     */
    public static function dmarc(array $records): ?array
    {
        foreach ($records as $record) {
            $txt = trim($record['txt']);
            if (!preg_match('/^v=DMARC1/i', $txt)) {
                continue;
            }
            $tags = [];
            foreach (explode(';', $txt) as $part) {
                if (str_contains($part, '=')) {
                    [$key, $value] = explode('=', $part, 2);
                    $tags[strtolower(trim($key))] = trim($value);
                }
            }
            foreach (['rua', 'ruf'] as $key) {
                if (isset($tags[$key])) {
                    $tags[$key] = implode(', ', array_map(fn ($u) => preg_replace('/^mailto:/i', '', trim($u)), explode(',', $tags[$key])));
                }
            }
            return ['raw' => $txt, 'host' => $record['host'], 'tags' => $tags];
        }
        return null;
    }

    // ---------------------------------------------------------------- DANE

    /**
     * TLSA records at _25._tcp.<mx host>: which certificate each mail server must
     * present (RFC 7672). They live in the mail provider's zone, so ask recursively.
     *
     * @param list<array<string,mixed>> $mx
     * @return list<array{host:string,records:list<array<string,mixed>>}>
     */
    private function dane(Context $context, array $mx): array
    {
        $hosts = array_values(array_unique(array_column($mx, 'target')));
        if (!$hosts) {
            return [];
        }
        $out = [];
        foreach ($context->dns()->lookup(array_map(fn ($h) => ["_25._tcp.{$h}", 'TLSA'], $hosts)) as $i => $result) {
            $out[] = ['host' => $hosts[$i], 'records' => $result['records']];
        }
        return $out;
    }

    // ---------------------------------------------------------- Email host

    /**
     * @param list<array<string,mixed>> $mx
     * @param array<string,list<string>> $targets hostname => IPs
     * @return array{providers:list<string>,gateway:bool,via:?string}|null
     */
    private function emailHost(Context $context, string $domain, array $mx, array $targets): ?array
    {
        if (!$mx) {
            return null;
        }
        $firstIps = [];
        foreach ($mx as $record) {
            if (isset($targets[$record['target']][0])) {
                $firstIps[$record['target']] = $targets[$record['target']][0];
            }
        }
        $locations = $context->geo()->locateMany(array_values($firstIps));

        $providers = [];
        $gateway = false;
        foreach ($mx as $record) {
            $host = $record['target'];
            $ip = $firstIps[$host] ?? '';
            $match = ProviderCatalog::emailHost($host);
            if ($match === null && str_starts_with($ip, '216.55.')) {
                $match = ['SpamWall', true];
            }
            if ($match === null) {
                $org = ProviderCatalog::organization([$locations[$ip]['org'] ?? null, $host]);
                $match = [$org ?? 'Unknown/Self', false];
            }
            $providers[$match[0]] = $match[0];
            $gateway = $gateway || $match[1];
        }

        // Behind a spam filter: the mail./autodiscover. records reveal the real mailbox host.
        $via = null;
        if ($gateway) {
            $servers = $context->authority()['ips'] ?: null;
            foreach ($context->dns()->lookup([["mail.{$domain}", 'A'], ["autodiscover.{$domain}", 'A']], $servers) as $result) {
                $target = $result['chain'][0]['target'] ?? '';
                if (str_contains($target, 'outlook.com') || str_contains($target, 'office365.com')) {
                    $via = 'Microsoft 365';
                    continue;
                }
                $ip = $result['records'][0]['ip'] ?? null;
                if ($ip !== null && !in_array($ip, $firstIps, true)) {
                    $via = ProviderCatalog::organization([$context->geo()->locate($ip)['org'] ?? null, $target]) ?? $via;
                }
            }
        }

        return ['providers' => array_values($providers), 'gateway' => $gateway, 'via' => $via];
    }
}
