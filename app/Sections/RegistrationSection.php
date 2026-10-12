<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;
use Whois\Providers\ProviderCatalog;
use Whois\Rdap\RdapParser;
use Whois\Whois\WhoisParser;

/**
 * Who the domain is registered with, when it expires, and who owns it.
 * Asks the registry's RDAP server (found via IANA's bootstrap file), follows
 * it to the registrar's RDAP server when the registry links one, and only
 * falls back to port-43 WHOIS for TLDs without RDAP.
 */
final class RegistrationSection implements Section
{
    public function build(Context $context): array
    {
        $domain = $context->registrableDomain();
        $rdap = $context->rdap();

        if ($rdap->hasServerFor($domain)) {
            $registry = $rdap->domain($domain);

            if ($registry['status'] === 404) {
                return $this->result($domain, 'rdap', $registry['url'], null, registered: false);
            }
            if (is_array($registry['data'])) {
                $registrar = $rdap->registrarRecord($registry['data']);
                $parsed = RdapParser::domain($registry['data'], $registrar['data'] ?? null);
                $raw = [
                    ['label' => 'Registry', 'source' => $registry['url'], 'text' => self::json($registry['data'])],
                ];
                if (!empty($registrar['data'])) {
                    $raw[] = ['label' => 'Registrar', 'source' => $registrar['url'], 'text' => self::json($registrar['data'])];
                }
                return $this->result($domain, 'rdap', $registry['url'], $parsed, raw: $raw);
            }
            // RDAP server down or misbehaving: fall through to WHOIS.
        }

        $whois = $context->whois()->lookup($domain);
        if ($whois['text'] === '') {
            // Usually a timeout or a momentary refusal: don't cache it, so the next visitor retries.
            return ['transient' => true] + $this->result($domain, 'none', $whois['server'], null);
        }

        $raw = [['label' => 'Registry', 'source' => $whois['server'], 'text' => $whois['text']]];
        if ($whois['registrarText']) {
            $raw[] = ['label' => 'Registrar', 'source' => $whois['registrarServer'], 'text' => $whois['registrarText']];
        }

        $notFound = (bool) preg_match('/^\s*(no match|not found|no data found|no entries found|status:\s*(free|available))/mi', $whois['text']);
        $parsed = $notFound ? null : WhoisParser::domain($whois['text'], $whois['registrarText']);

        return $this->result($domain, 'whois', $whois['server'], $parsed, registered: !$notFound, raw: $raw);
    }

    /**
     * @param array<string,mixed>|null $parsed
     * @param list<array{label:string,source:?string,text:string}> $raw
     * @return array<string,mixed>
     */
    private function result(string $domain, string $source, ?string $server, ?array $parsed, bool $registered = true, array $raw = []): array
    {
        if ($parsed !== null) {
            if (isset($parsed['registrar']['name'])) {
                $parsed['registrar']['label'] = ProviderCatalog::registrar($parsed['registrar']['name']);
            }
            // Blank out redaction notices; drop the registrant entirely if nothing is left.
            $registrant = array_map(
                fn ($v) => $v !== null && preg_match('/redacted|privacy|not disclosed|withheld|data protected/i', (string) $v) ? null : $v,
                $parsed['registrant'] ?? []
            );
            $parsed['registrant'] = array_filter($registrant, fn ($v) => $v !== null) ? $registrant : null;
        }

        return [
            'domain' => $domain,
            'source' => $source,
            'server' => $server,
            'registered' => $registered,
            'record' => $parsed,
            'raw' => $raw,
        ];
    }

    private static function json(array $data): string
    {
        unset($data['notices']); // Boilerplate terms of use; noise in the raw view.
        return (string) json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
