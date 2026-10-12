<?php

declare(strict_types=1);

namespace Whois\Rdap;

/**
 * Flattens RDAP JSON (RFC 9083) into the shapes the front-end renders.
 */
final class RdapParser
{
    /**
     * @param array<string,mixed> $registry  registry response
     * @param array<string,mixed>|null $registrar  registrar response (thin registries)
     * @return array<string,mixed>
     */
    public static function domain(array $registry, ?array $registrar): array
    {
        $registrarEntity = self::entitiesWithRole($registry['entities'] ?? [], 'registrar')[0]
            ?? self::entitiesWithRole($registrar['entities'] ?? [], 'registrar')[0]
            ?? null;
        $registrarCard = $registrarEntity ? self::vcard($registrarEntity) : null;

        $abuse = $registrarEntity ? (self::entitiesWithRole($registrarEntity['entities'] ?? [], 'abuse')[0] ?? null) : null;
        $abuseCard = $abuse ? self::vcard($abuse) : null;

        $ianaId = null;
        foreach ($registrarEntity['publicIds'] ?? [] as $id) {
            if (stripos($id['type'] ?? '', 'IANA') !== false) {
                $ianaId = $id['identifier'] ?? null;
            }
        }

        // The registrar's record usually has the more complete contact data.
        $registrantEntity = self::entitiesWithRole($registrar['entities'] ?? [], 'registrant')[0]
            ?? self::entitiesWithRole($registry['entities'] ?? [], 'registrant')[0]
            ?? null;

        $events = array_merge($registrar['events'] ?? [], $registry['events'] ?? []);
        $nameservers = array_map(
            fn ($ns) => strtolower(rtrim((string) ($ns['ldhName'] ?? $ns['unicodeName'] ?? ''), '.')),
            $registry['nameservers'] ?? $registrar['nameservers'] ?? []
        );

        return [
            'handle' => $registry['handle'] ?? null,
            'registrar' => $registrarEntity === null ? null : [
                'name' => $registrarCard['org'] ?? $registrarCard['name'] ?? ($registrarEntity['handle'] ?? null),
                'url' => $registrarCard['url'] ?? self::linkHref($registrarEntity, 'about'),
                'ianaId' => $ianaId,
                'abuseEmail' => $abuseCard['email'] ?? null,
                'abusePhone' => $abuseCard['phone'] ?? null,
            ],
            'created' => self::eventDate($events, 'registration'),
            'updated' => self::eventDate($events, 'last changed'),
            'expires' => self::eventDate($events, 'expiration'),
            'status' => array_values(array_unique(array_merge($registry['status'] ?? [], $registrar['status'] ?? []))),
            'nameservers' => array_values(array_filter($nameservers)),
            'dnssec' => isset($registry['secureDNS']['delegationSigned']) ? (bool) $registry['secureDNS']['delegationSigned'] : null,
            'registrant' => $registrantEntity ? self::contact($registrantEntity) : null,
        ];
    }

    /**
     * IP network (inetnum / NetRange) response from a Regional Internet Registry.
     *
     * @param array<string,mixed> $data
     * @return array<string,mixed>
     */
    public static function network(array $data, ?string $url): array
    {
        $org = self::entitiesWithRole($data['entities'] ?? [], 'registrant')[0]
            ?? self::entitiesWithRole($data['entities'] ?? [], 'administrative')[0]
            ?? ($data['entities'][0] ?? null);
        $orgCard = $org ? self::vcard($org) : [];

        $abuse = self::entitiesWithRole($data['entities'] ?? [], 'abuse')[0] ?? null;

        $cidrs = [];
        foreach ($data['cidr0_cidrs'] ?? [] as $cidr) {
            $prefix = $cidr['v4prefix'] ?? $cidr['v6prefix'] ?? null;
            if ($prefix !== null) {
                $cidrs[] = $prefix . '/' . ($cidr['length'] ?? '?');
            }
        }

        return [
            'registry' => self::registryName($url),
            'url' => $url,
            'handle' => $data['handle'] ?? null,
            'name' => $data['name'] ?? null,
            'type' => $data['type'] ?? null,
            'country' => $data['country'] ?? ($orgCard['country'] ?? null),
            'startAddress' => $data['startAddress'] ?? null,
            'endAddress' => $data['endAddress'] ?? null,
            'cidrs' => $cidrs,
            'parentHandle' => $data['parentHandle'] ?? null,
            'registered' => self::eventDate($data['events'] ?? [], 'registration'),
            'updated' => self::eventDate($data['events'] ?? [], 'last changed'),
            'organization' => $org === null ? null : [
                'name' => $orgCard['org'] ?? $orgCard['name'] ?? null,
                'handle' => $org['handle'] ?? null,
                'address' => $orgCard['address'] ?? null,
                'url' => self::linkHref($org, 'self'),
            ],
            'abuseEmail' => $abuse ? (self::vcard($abuse)['email'] ?? null) : null,
            'remarks' => array_values(array_filter(array_map(
                fn ($r) => trim(implode(' ', (array) ($r['description'] ?? []))),
                $data['remarks'] ?? []
            ))),
        ];
    }

    /**
     * Entities with a role, searched recursively (abuse contacts are often
     * nested inside the registrar or organization entity).
     *
     * @param list<array<string,mixed>> $entities
     * @return list<array<string,mixed>>
     */
    public static function entitiesWithRole(array $entities, string $role): array
    {
        $found = [];
        foreach ($entities as $entity) {
            if (in_array($role, $entity['roles'] ?? [], true)) {
                $found[] = $entity;
            }
            foreach (self::entitiesWithRole($entity['entities'] ?? [], $role) as $nested) {
                $found[] = $nested;
            }
        }
        return $found;
    }

    /**
     * jCard (RFC 7095) => flat contact fields.
     *
     * @param array<string,mixed> $entity
     * @return array{name?:string,org?:string,email?:string,phone?:string,url?:string,address?:string,country?:string}
     */
    public static function vcard(array $entity): array
    {
        $out = [];
        foreach ($entity['vcardArray'][1] ?? [] as $property) {
            [$name, $params, , $value] = array_pad((array) $property, 4, null);
            $name = strtolower((string) $name);
            switch ($name) {
                case 'fn':
                    $out['name'] = trim((string) $value);
                    break;
                case 'org':
                    $out['org'] = trim(is_array($value) ? implode(' ', $value) : (string) $value);
                    break;
                case 'email':
                    $out['email'] ??= trim((string) $value);
                    break;
                case 'tel':
                    $out['phone'] ??= preg_replace('/^tel:/', '', trim((string) $value));
                    break;
                case 'url':
                    $out['url'] ??= trim((string) $value);
                    break;
                case 'adr':
                    $label = $params['label'] ?? null;
                    if (is_string($label) && trim($label) !== '') {
                        $out['address'] = trim($label);
                    } elseif (is_array($value)) {
                        $parts = array_map(fn ($p) => is_array($p) ? implode(', ', array_filter($p)) : (string) $p, $value);
                        $out['address'] = implode(', ', array_filter(array_map('trim', $parts)));
                        $country = end($value);
                        if (is_string($country) && $country !== '') {
                            $out['country'] = $country;
                        }
                    }
                    if (isset($params['cc'])) {
                        $out['country'] = (string) $params['cc'];
                    }
                    break;
            }
        }
        return array_filter($out, fn ($v) => $v !== '' && $v !== null);
    }

    /**
     * @param array<string,mixed> $entity
     * @return array<string,?string>
     */
    private static function contact(array $entity): array
    {
        $card = self::vcard($entity);
        return [
            'name' => $card['name'] ?? null,
            'organization' => $card['org'] ?? null,
            'email' => $card['email'] ?? null,
            'phone' => $card['phone'] ?? null,
            'address' => $card['address'] ?? null,
            'country' => $card['country'] ?? null,
        ];
    }

    /**
     * @param list<array<string,mixed>> $events
     */
    private static function eventDate(array $events, string $action): ?string
    {
        foreach ($events as $event) {
            if (strcasecmp($event['eventAction'] ?? '', $action) === 0 && !empty($event['eventDate'])) {
                return (string) $event['eventDate'];
            }
        }
        return null;
    }

    /**
     * @param array<string,mixed> $object
     */
    private static function linkHref(array $object, string $rel): ?string
    {
        foreach ($object['links'] ?? [] as $link) {
            if (($link['rel'] ?? '') === $rel && !empty($link['href'])) {
                return (string) $link['href'];
            }
        }
        return null;
    }

    private static function registryName(?string $url): ?string
    {
        $host = (string) parse_url((string) $url, PHP_URL_HOST);
        foreach (['arin' => 'ARIN', 'ripe' => 'RIPE NCC', 'apnic' => 'APNIC', 'lacnic' => 'LACNIC', 'afrinic' => 'AFRINIC'] as $needle => $name) {
            if (str_contains($host, $needle)) {
                return $name;
            }
        }
        return $host ?: null;
    }
}
