<?php

declare(strict_types=1);

namespace Whois;

/**
 * Application settings, read once from the environment (.env).
 */
final class Config
{
    public function __construct(
        public readonly string $rootDir,
        public readonly string $storageDir,
        public readonly bool $debug,
        public readonly ?string $viteDevServer,
        public readonly string $googleMapsKey,
        public readonly string $userAgent,
        public readonly string $geoCityDb,
        public readonly string $geoAsnDb,
        public readonly bool $geoFallbackIpApi,
        public readonly ?string $ipinfoToken,
        public readonly int $lookupsPerWindow,
        public readonly int $requestsPerWindow,
        public readonly int $requestsPerToken,
        public readonly int $rateWindow,
        public readonly int $tokenTtl,
        public readonly ?string $clientIpHeader,
    ) {
    }

    public static function fromEnv(string $rootDir): self
    {
        $env = static fn (string $key, string $default = ''): string =>
            isset($_ENV[$key]) && $_ENV[$key] !== '' ? (string) $_ENV[$key] : $default;

        $storage = $env('STORAGE_DIR', $rootDir . '/storage');
        $debug = $env('APP_ENV', 'production') === 'development';
        $appUrl = $env('APP_URL', 'https://mariani.life/projects/dns/');

        return new self(
            rootDir: $rootDir,
            storageDir: $storage,
            debug: $debug,
            viteDevServer: $debug && $env('VITE_DEV_SERVER') !== '' ? rtrim($env('VITE_DEV_SERVER'), '/') : null,
            googleMapsKey: $env('GOOGLE_MAPS'),
            userAgent: "DomainInspector/2.0 (+{$appUrl})",
            geoCityDb: $env('GEOIP_CITY_DB', $storage . '/geoip/dbip-city-lite.mmdb'),
            geoAsnDb: $env('GEOIP_ASN_DB', $storage . '/geoip/dbip-asn-lite.mmdb'),
            geoFallbackIpApi: $env('GEO_FALLBACK', 'ip-api') === 'ip-api',
            ipinfoToken: $env('IP_INFO') !== '' ? $env('IP_INFO') : null,
            lookupsPerWindow: (int) $env('RATE_LIMIT_LOOKUPS', '30'),
            requestsPerWindow: (int) $env('RATE_LIMIT_REQUESTS', '400'),
            requestsPerToken: (int) $env('RATE_LIMIT_PER_TOKEN', '40'),
            rateWindow: (int) $env('RATE_LIMIT_WINDOW', '600'),
            tokenTtl: (int) $env('TOKEN_TTL', '1800'),
            clientIpHeader: $env('CLIENT_IP_HEADER') !== '' ? $env('CLIENT_IP_HEADER') : null,
        );
    }
}
