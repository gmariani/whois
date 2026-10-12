<?php

declare(strict_types=1);

namespace Whois\Support;

/**
 * Finds the registrable domain ("blog.example.co.uk" => "example.co.uk") using
 * the Public Suffix List, fetched from publicsuffix.org and cached for a week.
 */
final class PublicSuffix
{
    private const LIST_URL = 'https://publicsuffix.org/list/public_suffix_list.dat';

    /** @var array{rules: array<string,int>, wildcards: array<string,int>, exceptions: array<string,int>}|null */
    private ?array $list = null;

    public function __construct(
        private readonly HttpClient $http,
        private readonly Cache $cache,
    ) {
    }

    public function registrableDomain(string $domain): string
    {
        $labels = explode('.', $domain);
        $suffixLength = $this->suffixLength($labels);
        if ($suffixLength >= count($labels)) {
            return $domain; // The input itself is a public suffix; nothing better to offer.
        }
        return implode('.', array_slice($labels, -($suffixLength + 1)));
    }

    /**
     * @param list<string> $labels
     */
    private function suffixLength(array $labels): int
    {
        $list = $this->load();
        $count = count($labels);

        // Walk from the longest candidate to the shortest; first match wins.
        for ($i = 0; $i < $count; $i++) {
            $candidate = implode('.', array_slice($labels, $i));
            if (isset($list['exceptions'][$candidate])) {
                return $count - $i - 1;
            }
            if (isset($list['rules'][$candidate])) {
                return $count - $i;
            }
            $parent = implode('.', array_slice($labels, $i + 1));
            if ($parent !== '' && isset($list['wildcards'][$parent])) {
                return $count - $i;
            }
        }
        return 1; // Default rule "*": the TLD is the suffix.
    }

    /**
     * @return array{rules: array<string,int>, wildcards: array<string,int>, exceptions: array<string,int>}
     */
    private function load(): array
    {
        if ($this->list !== null) {
            return $this->list;
        }

        $list = $this->cache->remember('psl:v1', 86400 * 7, function (): ?array {
            $response = $this->http->get(self::LIST_URL, [], 10.0);
            return $response->ok() ? self::parse($response->body) : null;
        });

        // Offline fallback: enough to handle the common two-level ccTLD suffixes.
        $this->list = $list ?? [
            'rules' => array_fill_keys(['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br', 'com.mx', 'co.za', 'com.cn', 'co.in'], 1),
            'wildcards' => [],
            'exceptions' => [],
        ];
        return $this->list;
    }

    /**
     * @return array{rules: array<string,int>, wildcards: array<string,int>, exceptions: array<string,int>}
     */
    public static function parse(string $text): array
    {
        $out = ['rules' => [], 'wildcards' => [], 'exceptions' => []];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            $line = trim(explode(' ', trim($line))[0]);
            if ($line === '' || str_starts_with($line, '//')) {
                continue;
            }
            if (preg_match('/[^\x20-\x7e]/', $line)) {
                if (!function_exists('idn_to_ascii')) {
                    continue;
                }
                $prefix = $line[0] === '!' ? '!' : (str_starts_with($line, '*.') ? '*.' : '');
                $ascii = idn_to_ascii(substr($line, strlen($prefix)), IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
                if ($ascii === false) {
                    continue;
                }
                $line = $prefix . strtolower($ascii);
            }
            if ($line[0] === '!') {
                $out['exceptions'][substr($line, 1)] = 1;
            } elseif (str_starts_with($line, '*.')) {
                $out['wildcards'][substr($line, 2)] = 1;
            } else {
                $out['rules'][$line] = 1;
            }
        }
        return $out;
    }
}
