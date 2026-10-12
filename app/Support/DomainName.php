<?php

declare(strict_types=1);

namespace Whois\Support;

use InvalidArgumentException;

final class DomainName
{
    /**
     * Turn whatever the user typed (URL, host with port, IDN, trailing dot…)
     * into a lower-case ASCII hostname, or throw with a user-facing message.
     */
    public static function normalize(string $input): string
    {
        $value = strtolower(trim($input));
        if ($value === '') {
            throw new InvalidArgumentException('Enter a domain name.');
        }

        if (str_contains($value, '://')) {
            $value = (string) parse_url($value, PHP_URL_HOST);
        } else {
            // Drop path / query / fragment / userinfo from "example.com/foo?x".
            $value = (string) preg_replace('#[/?\#].*$#', '', $value);
            $value = (string) preg_replace('#^.*@#', '', $value);
        }
        // Check for IPs before stripping a ":port", which would mangle IPv6 ("…::1111").
        if (Ip::isIp(trim($value, '[]'))) {
            throw new InvalidArgumentException('IP address lookups are not supported yet; enter a domain name.');
        }
        $value = (string) preg_replace('#:\d+$#', '', $value); // port
        $value = trim($value, '.');
        if (str_starts_with($value, '*.')) {
            $value = substr($value, 2);
        }
        if (Ip::isIp($value)) {
            throw new InvalidArgumentException('IP address lookups are not supported yet; enter a domain name.');
        }

        if (preg_match('/[^\x20-\x7e]/', $value)) {
            if (!function_exists('idn_to_ascii')) {
                throw new InvalidArgumentException('Internationalized domain names require the PHP intl extension.');
            }
            $ascii = idn_to_ascii($value, IDNA_DEFAULT, INTL_IDNA_VARIANT_UTS46);
            if ($ascii === false) {
                throw new InvalidArgumentException('That does not look like a valid domain name.');
            }
            $value = strtolower($ascii);
        }

        if (!self::isValid($value)) {
            throw new InvalidArgumentException('That does not look like a valid domain name.');
        }

        return $value;
    }

    public static function isValid(string $domain): bool
    {
        if (strlen($domain) > 253 || !str_contains($domain, '.')) {
            return false;
        }
        $labels = explode('.', $domain);
        foreach ($labels as $label) {
            // Underscores are legal in DNS (_dmarc, _domainkey) even if not in hostnames.
            if (!preg_match('/^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/', $label)) {
                return false;
            }
        }
        $tld = end($labels);
        return (bool) preg_match('/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/', $tld);
    }

    public static function tld(string $domain): string
    {
        $labels = explode('.', $domain);
        return end($labels);
    }

    /** example.com => com, a.b.example.com => b.example.com */
    public static function parent(string $domain): ?string
    {
        $pos = strpos($domain, '.');
        return $pos === false ? null : substr($domain, $pos + 1);
    }

    public static function isSubdomainOf(string $name, string $zone): bool
    {
        return $name === $zone || str_ends_with($name, '.' . $zone);
    }
}
