<?php

declare(strict_types=1);

namespace Whois\Dns;

use NetDNS2\RR;

/**
 * Converts NetDNS2 RR objects into plain arrays for JSON. Field names match
 * PHP's dns_get_record() (ip, ipv6, target, pri, txt…) as the old code did.
 */
final class RecordFormatter
{
    /**
     * @return array<string,mixed>|null
     */
    public static function format(RR $rr): ?array
    {
        $type = $rr->type->label();
        $base = [
            'host' => rtrim(strtolower((string) $rr->name), '.'),
            'ttl' => $rr->ttl,
            'class' => $rr->class->label(),
            'type' => $type,
        ];

        try {
            $fields = match ($type) {
                'A' => ['ip' => (string) $rr->address],
                'AAAA' => ['ipv6' => (string) $rr->address],
                'CNAME' => ['target' => self::host($rr->cname)],
                'NS' => ['target' => self::host($rr->nsdname)],
                'PTR' => ['target' => self::host($rr->ptrdname)],
                'MX' => ['pri' => $rr->preference, 'target' => self::host($rr->exchange)],
                'SOA' => [
                    'mname' => self::host($rr->mname),
                    'rname' => self::mailbox((string) $rr->rname),
                    'serial' => $rr->serial,
                    'refresh' => $rr->refresh,
                    'retry' => $rr->retry,
                    'expire' => $rr->expire,
                    'minimum-ttl' => $rr->minimum,
                ],
                'TXT' => (static function (array $text): array {
                    $entries = array_map('strval', $text);
                    return ['txt' => implode('', $entries), 'entries' => $entries];
                })($rr->text),
                'SRV' => [
                    'pri' => $rr->priority,
                    'weight' => $rr->weight,
                    'port' => $rr->port,
                    'target' => self::host($rr->target),
                ],
                'NAPTR' => [
                    'order' => $rr->order,
                    'pref' => $rr->preference,
                    'flags' => (string) $rr->flags,
                    'services' => (string) $rr->services,
                    'regex' => (string) $rr->regexp,
                    'replacement' => self::host($rr->replacement),
                ],
                'CAA' => ['flags' => $rr->flags, 'tag' => (string) $rr->tag, 'value' => (string) $rr->value],
                'DNSKEY' => [
                    'flags' => $rr->flags,
                    'protocol' => $rr->protocol,
                    'algorithm' => $rr->algorithm->value,
                    'key' => $rr->key,
                ],
                'DS' => [
                    'keytag' => $rr->keytag,
                    'algorithm' => $rr->algorithm->value,
                    'digesttype' => $rr->digesttype->value,
                    'digest' => strtoupper($rr->digest),
                ],
                default => null,
            };
        } catch (\Throwable) {
            return null;
        }

        return $fields === null ? null : $base + $fields;
    }

    private static function host(mixed $value): string
    {
        return rtrim(strtolower((string) $value), '.');
    }

    /** The library renders SOA RNAME as "user@example.com"; zone files want "user.example.com". */
    private static function mailbox(string $value): string
    {
        $value = rtrim(strtolower($value), '.');
        if (!str_contains($value, '@')) {
            return $value;
        }
        [$local, $domain] = explode('@', $value, 2);
        return str_replace('.', '\\.', $local) . '.' . $domain;
    }
}
