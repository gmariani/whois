<?php

declare(strict_types=1);

namespace Whois\Providers;

use Whois\Support\DataFile;

/**
 * Turns hostnames and network-operator names into friendly provider names.
 * The lists themselves live in app/data/providers.php.
 */
final class ProviderCatalog
{
    /**
     * @return array<string,mixed>
     */
    private static function table(string $name): array
    {
        return DataFile::load('providers')[$name];
    }

    public static function registrar(?string $name): ?string
    {
        if ($name === null || $name === '') {
            return null;
        }
        return self::match(strtolower($name), self::table('registrars')) ?? $name;
    }

    /**
     * @param list<?string> $hints organization names, ASN names, reverse-DNS hostnames…
     */
    public static function organization(array $hints): ?string
    {
        foreach ($hints as $hint) {
            if ($hint && ($label = self::match(strtolower($hint), self::table('organizations')))) {
                return $label;
            }
        }
        return null;
    }

    /**
     * @param list<string> $nameservers
     * @return list<string>
     */
    public static function dnsHosts(array $nameservers): array
    {
        $hosts = [];
        foreach ($nameservers as $ns) {
            $hosts[] = self::match(strtolower($ns), self::table('dns')) ?? "Unknown ({$ns})";
        }
        $hosts = array_values(array_unique($hosts));
        // If any are recognized, don't clutter the answer with the raw hostnames.
        $known = array_values(array_filter($hosts, fn ($h) => !str_starts_with($h, 'Unknown (')));
        return $known ?: array_slice($hosts, 0, 2);
    }

    /**
     * @return array{0:string,1:bool}|null [provider, isFilteringGateway]
     */
    public static function emailHost(string $mxHost): ?array
    {
        return self::match(strtolower($mxHost), self::table('email'));
    }

    /**
     * @template T
     * @param array<string,T> $table
     * @return T|null
     */
    private static function match(string $haystack, array $table): mixed
    {
        foreach ($table as $needle => $label) {
            if (str_contains($haystack, $needle)) {
                return $label;
            }
        }
        return null;
    }
}
