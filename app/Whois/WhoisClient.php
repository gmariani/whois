<?php

declare(strict_types=1);

namespace Whois\Whois;

use Whois\Support\Cache;
use Whois\Support\DomainName;

/**
 * Port-43 WHOIS, used only for TLDs that have no RDAP service yet.
 * Asks whois.iana.org which server runs the TLD, then asks that server
 * (and the registrar's server, if the registry points to one).
 */
final class WhoisClient
{
    public function __construct(private readonly Cache $cache)
    {
    }

    /**
     * @return array{server:?string,text:string,registrarServer:?string,registrarText:?string}
     */
    public function lookup(string $domain): array
    {
        $server = $this->serverForTld(DomainName::tld($domain));
        if ($server === null) {
            return ['server' => null, 'text' => '', 'registrarServer' => null, 'registrarText' => null];
        }

        $text = $this->query($server, $domain);

        $registrarServer = null;
        $registrarText = null;
        if (preg_match('/^\s*(?:Registrar WHOIS Server|refer|whois):\s*(\S+)\s*$/mi', $text, $m)) {
            $candidate = strtolower(preg_replace('#^\w+://#', '', $m[1]));
            if ($candidate !== $server && preg_match('/^[a-z0-9.-]+$/', $candidate)) {
                $registrarServer = $candidate;
                $registrarText = $this->query($candidate, $domain) ?: null;
            }
        }

        return ['server' => $server, 'text' => $text, 'registrarServer' => $registrarServer, 'registrarText' => $registrarText];
    }

    private function serverForTld(string $tld): ?string
    {
        return $this->cache->remember("whois-server:{$tld}", 86400 * 7, function () use ($tld): ?string {
            $iana = $this->query('whois.iana.org', $tld);
            return preg_match('/^\s*whois:\s+(\S+)/mi', $iana, $m) ? strtolower($m[1]) : null;
        });
    }

    private function query(string $server, string $query): string
    {
        $fp = @fsockopen($server, 43, $errno, $errstr, 4);
        if (!$fp) {
            error_log("WHOIS connection to {$server} failed: {$errstr} ({$errno})");
            return '';
        }
        stream_set_timeout($fp, 6);
        fwrite($fp, $query . "\r\n");

        $out = '';
        $deadline = microtime(true) + 8;
        while (!feof($fp) && microtime(true) < $deadline && strlen($out) < 200_000) {
            $chunk = fread($fp, 8192);
            if ($chunk === false || (stream_get_meta_data($fp)['timed_out'] ?? false)) {
                break;
            }
            $out .= $chunk;
        }
        fclose($fp);

        return mb_convert_encoding($out, 'UTF-8', 'UTF-8, ISO-8859-1');
    }
}
