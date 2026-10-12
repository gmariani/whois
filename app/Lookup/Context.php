<?php

declare(strict_types=1);

namespace Whois\Lookup;

use Whois\Config;
use Whois\Dns\Resolver;
use Whois\Geo\GeoLocator;
use Whois\Rdap\RdapBootstrap;
use Whois\Rdap\RdapClient;
use Whois\Support\Cache;
use Whois\Support\HttpClient;
use Whois\Support\PublicSuffix;
use Whois\Whois\WhoisClient;

/**
 * Everything a section needs to look one domain up. Services are created
 * lazily so a section only pays for what it uses.
 */
final class Context
{
    private ?Resolver $resolver = null;
    private ?HttpClient $http = null;
    private ?GeoLocator $geo = null;
    private ?RdapClient $rdap = null;
    private ?string $registrable = null;
    private ?string $zone = null;
    /** @var array{zone:string,nameservers:list<array{host:string,ips:list<string>}>,ips:list<string>}|null */
    private ?array $authority = null;

    public function __construct(
        public readonly string $domain,
        public readonly Config $config,
        public readonly Cache $cache,
        private readonly SectionRunner $runner,
    ) {
    }

    public function dns(): Resolver
    {
        return $this->resolver ??= Resolver::create($_ENV['DNS_RESOLVERS'] ?? null);
    }

    public function http(): HttpClient
    {
        return $this->http ??= new HttpClient($this->config->userAgent);
    }

    public function geo(): GeoLocator
    {
        return $this->geo ??= new GeoLocator(
            $this->config->geoCityDb,
            $this->config->geoAsnDb,
            $this->cache,
            $this->config->geoFallbackIpApi,
            $this->config->ipinfoToken,
        );
    }

    public function rdap(): RdapClient
    {
        return $this->rdap ??= new RdapClient($this->http(), $this->cache, new RdapBootstrap($this->http(), $this->cache));
    }

    public function whois(): WhoisClient
    {
        return new WhoisClient($this->cache);
    }

    /** The domain as registered with a registry: blog.example.co.uk => example.co.uk */
    public function registrableDomain(): string
    {
        return $this->registrable ??= (new PublicSuffix($this->http(), $this->cache))->registrableDomain($this->domain);
    }

    public function isSubdomain(): bool
    {
        return $this->domain !== $this->registrableDomain();
    }

    /** DNS zone holding the domain's records (usually the registrable domain). */
    public function zone(): string
    {
        return $this->zone ??= $this->dns()->zoneApex($this->domain) ?? $this->registrableDomain();
    }

    /**
     * False when the closest zone is above the registrable domain (e.g. "com"),
     * which means the domain isn't delegated in DNS at all.
     */
    public function isDelegated(): bool
    {
        return \Whois\Support\DomainName::isSubdomainOf($this->zone(), $this->registrableDomain());
    }

    /**
     * @return array{zone:string,nameservers:list<array{host:string,ips:list<string>}>,ips:list<string>}
     */
    public function authority(): array
    {
        return $this->authority ??= $this->dns()->authority($this->zone());
    }

    /**
     * Another section's (cached) result, e.g. "locations" reuses "dns".
     *
     * @return array<string,mixed>
     */
    public function section(string $name): array
    {
        return $this->runner->run($name, $this)['data'];
    }
}
