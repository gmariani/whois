<?php

declare(strict_types=1);

namespace Whois\Dns;

use NetDNS2\Packet\Request;
use NetDNS2\Packet\Response;

/**
 * Sends many DNS questions in parallel over UDP and collects the answers.
 *
 * The old code asked one question at a time with a 1 s timeout, so probing
 * ~100 common subdomains took a long time. Here every question goes out at once
 * (with a small per-server window to stay under response-rate-limits),
 * answers are matched back by transaction id, lost packets are retried on the
 * next server, and truncated answers are re-asked over TCP.
 */
final class DnsClient
{
    private const EDNS_UDP_SIZE = 1232;

    public int $queries = 0;

    public function __construct(
        private readonly float $timeout = 1.5,
        private readonly int $attempts = 2,
        private readonly int $window = 20,
    ) {
    }

    /**
     * @param list<array{0:string,1:string}> $questions [name, type]
     * @param list<string> $servers IP addresses
     * @return list<DnsAnswer> same order as $questions
     */
    public function query(array $questions, array $servers, bool $recursionDesired = true): array
    {
        /** @var array<int,DnsAnswer> $results */
        $results = [];
        foreach ($questions as $i => [$name, $type]) {
            $results[$i] = new DnsAnswer($name, $type);
        }
        $servers = array_values(array_unique($servers));
        if (!$servers || !$questions) {
            return array_values($results);
        }

        $pending = array_fill_keys(array_keys($questions), true);
        for ($attempt = 0; $attempt < $this->attempts && $pending; $attempt++) {
            $this->udpRound($questions, $servers, $pending, $results, $attempt, $recursionDesired);
        }

        // Retry truncated answers over TCP (large TXT sets, DNSKEY, etc.).
        foreach ($results as $i => $result) {
            if ($result->truncated && $result->server !== null) {
                $results[$i] = $this->tcpQuery($result->name, $result->type, $result->server, $recursionDesired) ?? $result;
            }
        }

        return array_values($results);
    }

    /**
     * @param list<array{0:string,1:string}> $questions
     * @param list<string> $servers
     * @param array<int,bool> $pending
     * @param array<int,DnsAnswer> $results
     */
    private function udpRound(array $questions, array $servers, array &$pending, array &$results, int $attempt, bool $rd): void
    {
        $serverCount = count($servers);
        $lanes = [];
        foreach (array_keys($pending) as $i) {
            // Rotate servers between attempts so a dead server gets skipped.
            $s = ($i + $attempt) % $serverCount;
            $lanes[$s]['queue'][] = $i;
        }

        foreach ($lanes as $s => &$lane) {
            $ip = $servers[$s];
            $target = str_contains($ip, ':') ? "udp://[{$ip}]:53" : "udp://{$ip}:53";
            $socket = @stream_socket_client($target, $errno, $errstr, 1);
            if ($socket === false) {
                $lane['queue'] = [];
                continue;
            }
            stream_set_blocking($socket, false);
            $lane['socket'] = $socket;
            $lane['server'] = $ip;
            $lane['inflight'] = [];
        }
        unset($lane);

        while (true) {
            $now = microtime(true);
            $readable = [];
            foreach ($lanes as $s => &$lane) {
                if (!isset($lane['socket'])) {
                    continue;
                }
                // Expire packets that never came back; they stay pending for the next attempt.
                foreach ($lane['inflight'] as $id => [, $sentAt]) {
                    if ($now - $sentAt > $this->timeout) {
                        unset($lane['inflight'][$id]);
                    }
                }
                while (count($lane['inflight']) < $this->window && $lane['queue']) {
                    $i = array_shift($lane['queue']);
                    $packet = $this->buildPacket($questions[$i][0], $questions[$i][1], $rd, $lane['inflight']);
                    if ($packet === null) {
                        $results[$i]->rcode = 'FORMERR';
                        unset($pending[$i]);
                        continue;
                    }
                    [$id, $bytes] = $packet;
                    @fwrite($lane['socket'], $bytes);
                    $this->queries++;
                    $lane['inflight'][$id] = [$i, microtime(true)];
                }
                if ($lane['inflight']) {
                    $readable[$s] = $lane['socket'];
                }
            }
            unset($lane);

            if (!$readable) {
                break;
            }

            $read = array_values($readable);
            $write = $except = null;
            if (@stream_select($read, $write, $except, 0, 50_000) === false) {
                break;
            }

            foreach ($read as $socket) {
                $s = array_search($socket, $readable, true);
                $lane = &$lanes[$s];
                while (($data = @fread($socket, 65535)) !== false && $data !== '') {
                    if (strlen($data) < 12) {
                        continue;
                    }
                    $id = unpack('n', $data)[1];
                    if (!isset($lane['inflight'][$id])) {
                        continue;
                    }
                    [$i] = $lane['inflight'][$id];
                    try {
                        $response = new Response($data, strlen($data));
                    } catch (\Throwable) {
                        continue;
                    }
                    // Make sure the answer is for the question we asked. (NetDNS2 doesn't
                    // parse the body of truncated replies, so those only get the id check.)
                    $question = $response->question[0] ?? null;
                    if ($question === null
                        ? $response->header->tc !== 1
                        : strcasecmp(rtrim((string) $question->qname, '.'), $questions[$i][0]) !== 0
                    ) {
                        continue;
                    }
                    unset($lane['inflight'][$id]);
                    $results[$i] = DnsAnswer::fromResponse($questions[$i][0], $questions[$i][1], $response, $lane['server']);
                    // SERVFAIL/REFUSED: worth trying another server on the next attempt.
                    if ($results[$i]->rcode === 'NOERROR' || $results[$i]->rcode === 'NXDOMAIN') {
                        unset($pending[$i]);
                    }
                }
                unset($lane);
            }
        }

        foreach ($lanes as $lane) {
            if (isset($lane['socket'])) {
                fclose($lane['socket']);
            }
        }
    }

    /**
     * @param array<int,mixed> $inflight ids already in use on this socket
     * @return array{0:int,1:string}|null
     */
    private function buildPacket(string $name, string $type, bool $rd, array $inflight): ?array
    {
        try {
            \NetDNS2\Data::$compressed = [];
            $request = new Request($name, $type);
            do {
                $request->header->id = random_int(0, 65535);
            } while (isset($inflight[$request->header->id]));
            $request->header->rd = $rd ? 1 : 0;

            $opt = new \NetDNS2\RR\OPT();
            $opt->udp_length = self::EDNS_UDP_SIZE;
            $request->additional[] = $opt;
            $request->header->arcount = 1;

            return [$request->header->id, $request->get()];
        } catch (\Throwable) {
            return null;
        }
    }

    private function tcpQuery(string $name, string $type, string $server, bool $rd): ?DnsAnswer
    {
        try {
            $resolver = new \NetDNS2\Resolver([
                'nameservers' => [$server],
                'use_tcp' => true,
                'timeout' => 3,
                'recurse' => $rd,
            ]);
            $this->queries++;
            return DnsAnswer::fromResponse($name, $type, $resolver->query($name, $type), $server);
        } catch (\NetDNS2\Exception $e) {
            $response = $e->getResponse();
            return $response ? DnsAnswer::fromResponse($name, $type, $response, $server) : null;
        } catch (\Throwable) {
            return null;
        }
    }
}
