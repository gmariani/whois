<?php

declare(strict_types=1);

namespace Whois\Lookup;

use Whois\Sections;

/**
 * Maps section names to their builders and caches each result briefly, so a
 * page refresh (or two sections needing the same data) doesn't redo the work.
 */
final class SectionRunner
{
    /** name => [class, cache seconds] */
    public const SECTIONS = [
        'registration' => [Sections\RegistrationSection::class, 3600],
        'network' => [Sections\NetworkSection::class, 900],
        'dns' => [Sections\DnsSection::class, 300],
        'subdomains' => [Sections\SubdomainsSection::class, 600],
        'email' => [Sections\EmailSection::class, 600],
        'http' => [Sections\HttpSection::class, 300],
        'tls' => [Sections\TlsSection::class, 900],
        'locations' => [Sections\LocationsSection::class, 600],
    ];

    private const CACHE_VERSION = 'v2'; // bump when a section's output shape changes

    public static function exists(string $name): bool
    {
        return isset(self::SECTIONS[$name]);
    }

    /**
     * @return array{data:array<string,mixed>,cached:bool}
     */
    public function run(string $name, Context $context): array
    {
        [$class, $ttl] = self::SECTIONS[$name];
        $key = sprintf('section:%s:%s:%s', self::CACHE_VERSION, $name, $context->domain);

        $data = $context->cache->remember($key, $ttl, function () use ($class, $context): array {
            /** @var Sections\Section $section */
            $section = new $class();
            return $section->build($context);
        }, $hit);

        return ['data' => $data, 'cached' => (bool) $hit];
    }
}
