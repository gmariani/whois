<?php

declare(strict_types=1);

namespace Whois\Support;

/**
 * Loads the editable lists in app/data/ (subdomains to probe, DKIM selectors,
 * provider names). Each file returns a plain PHP array.
 */
final class DataFile
{
    /** @var array<string,array<mixed>> */
    private static array $loaded = [];

    /**
     * @return array<mixed>
     */
    public static function load(string $name): array
    {
        return self::$loaded[$name] ??= require dirname(__DIR__) . "/data/{$name}.php";
    }
}
