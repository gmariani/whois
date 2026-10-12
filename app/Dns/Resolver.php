<?php

declare(strict_types=1);

namespace Whois\Dns;

use Whois\Support\DomainName;

/**
 * High-level DNS: finds a zone's authoritative servers and asks them directly
 * (so TTLs are the real ones, not a cache's countdown), falls back to a
 * recursive resolver when they refuse or refer us elsewhere, and follows
 * CNAMEs that leave the zone.
 */
final class Resolver
{
    private const FALLBACK_RECURSIVE = ['1.1.1.1', '8.8.8.8', '9.9.9.9'];

    /** @var array<string,?string> */
    private array $apexCache = [];
    /** @var array<string,array{zone:string,nameservers:list<array{host:string,ips:list<string>}>,ips:list<string>}> */
    private array $authorityCache = [];

    /**
     * @param list<string> $recursive
     */
    public function __construct(
        public readonly DnsClient $client,
        private readonly array $recursive,
    ) {
    }

    /**
     * The recursive resolver is only used to discover where to ask (NS/SOA
     * lookups, CNAME targets, PTRs); actual zone data comes from the zone's own
     * servers. Local stubs like systemd-resolved (127.0.0.53) mishandle some
     * query types, so public resolvers are the default; DNS_RESOLVERS overrides.
     */
    public static function create(?string $override = null): self
    {
        $servers = $override
            ? array_values(array_filter(array_map('trim', explode(',', $override)), fn ($ip) => filter_var($ip, FILTER_VALIDATE_IP)))
            : [];
        return new self(new DnsClient(), $servers ?: self::FALLBACK_RECURSIVE);
    }

    /**
     * @param list<array{0:string,1:string}> $questions
     * @return list<DnsAnswer>
     */
    public function recursive(array $questions): array
    {
        return $this->client->query($questions, $this->recursive, true);
    }

    /**
     * Name of the zone that holds $name, e.g. www.example.co.uk => example.co.uk.
     */
    public function zoneApex(string $name): ?string
    {
        if (array_key_exists($name, $this->apexCache)) {
            return $this->apexCache[$name];
        }
        [$answer] = $this->recursive([[$name, 'SOA']]);
        $apex = null;
        foreach ([...$answer->answer, ...$answer->authority] as $rr) {
            if ($rr->type->label() === 'SOA') {
                $apex = rtrim(strtolower((string) $rr->name), '.');
                break;
            }
            if ($rr->type->label() === 'CNAME') {
                break; // $name is an alias; its record lives in the parent's zone.
            }
        }
        if ($apex === null && ($parent = DomainName::parent($name)) !== null) {
            $apex = $this->zoneApex($parent);
        }
        return $this->apexCache[$name] = $apex;
    }

    /**
     * Name servers (with IPv4 addresses) for a zone.
     *
     * @return array{zone:string,nameservers:list<array{host:string,ips:list<string>}>,ips:list<string>}
     */
    public function authority(string $zone): array
    {
        if (isset($this->authorityCache[$zone])) {
            return $this->authorityCache[$zone];
        }
        [$answer] = $this->recursive([[$zone, 'NS']]);
        $hosts = [];
        foreach ($answer->answer as $rr) {
            if ($rr->type->label() === 'NS') {
                $hosts[] = rtrim(strtolower((string) $rr->nsdname), '.');
            }
        }
        $hosts = array_values(array_unique($hosts));
        sort($hosts);

        $addresses = $this->addresses($hosts);
        $nameservers = array_map(fn (string $host) => ['host' => $host, 'ips' => $addresses[$host] ?? []], $hosts);
        $ips = array_values(array_unique(array_merge(...array_values($addresses ?: [[]]))));

        return $this->authorityCache[$zone] = ['zone' => $zone, 'nameservers' => $nameservers, 'ips' => $ips];
    }

    /**
     * Resolve hostnames to IPv4 addresses (via the recursive resolver).
     *
     * @param list<string> $hosts
     * @return array<string,list<string>>
     */
    public function addresses(array $hosts, bool $withIpv6 = false): array
    {
        $hosts = array_values(array_unique(array_filter($hosts)));
        $questions = array_map(fn ($h) => [$h, 'A'], $hosts);
        if ($withIpv6) {
            foreach ($hosts as $h) {
                $questions[] = [$h, 'AAAA'];
            }
        }
        $out = [];
        foreach ($this->recursive($questions) as $answer) {
            foreach ($answer->answer as $rr) {
                $type = $rr->type->label();
                if ($type === 'A' || $type === 'AAAA') {
                    $out[$answer->name][] = (string) $rr->address;
                }
            }
        }
        return array_map(fn ($ips) => array_values(array_unique($ips)), $out);
    }

    /**
     * Look records up, preferring the given authoritative servers.
     *
     * @param list<array{0:string,1:string}> $questions [name, type]
     * @param list<string>|null $servers authoritative server IPs, or null for recursive
     * @param bool $followCnames resolve out-of-zone CNAME targets for the requested type
     * @return list<array{name:string,type:string,status:string,records:list<array<string,mixed>>,chain:list<array<string,mixed>>,server:?string}>
     */
    public function lookup(array $questions, ?array $servers = null, bool $followCnames = true): array
    {
        if (!$questions) {
            return [];
        }
        $answers = $servers
            ? $this->client->query($questions, $servers, false)
            : $this->recursive($questions);

        // Anything the authoritative servers wouldn't answer cleanly gets a second opinion.
        if ($servers) {
            $retry = [];
            foreach ($answers as $i => $answer) {
                if (!$answer->isDefinitive() || $answer->isReferral()) {
                    $retry[$i] = [$answer->name, $answer->type];
                }
            }
            if ($retry) {
                foreach (array_combine(array_keys($retry), $this->recursive(array_values($retry))) as $i => $answer) {
                    $answers[$i] = $answer;
                }
            }
        }

        $results = [];
        $chase = [];
        foreach ($answers as $i => $answer) {
            $records = [];
            $chain = [];
            foreach ($answer->answer as $rr) {
                $record = RecordFormatter::format($rr);
                if ($record === null) {
                    continue;
                }
                if ($record['type'] === $answer->type) {
                    $records[] = $record;
                } elseif ($record['type'] === 'CNAME') {
                    $chain[] = $record;
                }
            }
            $results[$i] = [
                'name' => $answer->name,
                'type' => $answer->type,
                'status' => $answer->rcode,
                'records' => $records,
                'chain' => $chain,
                'server' => $answer->server,
            ];
            // CNAME pointing out of the zone: the authoritative server can't finish the job.
            if ($followCnames && !$records && $chain && $answer->type !== 'CNAME') {
                $chase[$i] = [end($chain)['target'], $answer->type];
            }
        }

        if ($chase) {
            foreach (array_combine(array_keys($chase), $this->recursive(array_values($chase))) as $i => $answer) {
                foreach ($answer->answer as $rr) {
                    $record = RecordFormatter::format($rr);
                    if ($record === null) {
                        continue;
                    }
                    if ($record['type'] === $answer->type) {
                        $results[$i]['records'][] = $record;
                    } elseif ($record['type'] === 'CNAME') {
                        $results[$i]['chain'][] = $record;
                    }
                }
                if ($results[$i]['records']) {
                    $results[$i]['status'] = 'NOERROR';
                }
            }
        }

        return array_values($results);
    }

    /**
     * Convenience: lookup() results keyed by "name|TYPE".
     *
     * @param list<array{0:string,1:string}> $questions
     * @param list<string>|null $servers
     * @return array<string,array{name:string,type:string,status:string,records:list<array<string,mixed>>,chain:list<array<string,mixed>>,server:?string}>
     */
    public function lookupKeyed(array $questions, ?array $servers = null, bool $followCnames = true): array
    {
        $out = [];
        foreach ($this->lookup($questions, $servers, $followCnames) as $result) {
            $out[$result['name'] . '|' . $result['type']] = $result;
        }
        return $out;
    }

    /**
     * Reverse DNS for many IPs at once.
     *
     * @param list<string> $ips
     * @return array<string,?string> ip => hostname
     */
    public function reverse(array $ips): array
    {
        $ips = array_values(array_unique($ips));
        $questions = [];
        foreach ($ips as $ip) {
            $arpa = \Whois\Support\Ip::arpa($ip);
            if ($arpa !== null) {
                $questions[$arpa] = [$arpa, 'PTR'];
            }
        }
        $byArpa = [];
        foreach ($this->lookup(array_values($questions)) as $result) {
            $byArpa[$result['name']] = $result['records'][0]['target'] ?? null;
        }
        $out = [];
        foreach ($ips as $ip) {
            $out[$ip] = $byArpa[\Whois\Support\Ip::arpa($ip)] ?? null;
        }
        return $out;
    }
}
