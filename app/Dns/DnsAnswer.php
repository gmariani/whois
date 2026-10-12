<?php

declare(strict_types=1);

namespace Whois\Dns;

/**
 * One raw DNS response (or the reason there wasn't one).
 */
final class DnsAnswer
{
    /** @var list<\NetDNS2\RR> */
    public array $answer = [];
    /** @var list<\NetDNS2\RR> */
    public array $authority = [];
    public bool $authoritative = false;
    public bool $truncated = false;
    public ?string $server = null;

    public function __construct(
        public readonly string $name,
        public readonly string $type,
        public string $rcode = 'TIMEOUT',
    ) {
    }

    public static function fromResponse(string $name, string $type, \NetDNS2\Packet\Response $response, string $server): self
    {
        $answer = new self($name, $type, $response->header->rcode->name);
        $answer->answer = array_values($response->answer);
        $answer->authority = array_values($response->authority);
        $answer->authoritative = $response->header->aa === 1;
        $answer->truncated = $response->header->tc === 1;
        $answer->server = $server;
        return $answer;
    }

    /** Got a definitive reply (records, NODATA or NXDOMAIN). */
    public function isDefinitive(): bool
    {
        return $this->rcode === 'NXDOMAIN' || ($this->rcode === 'NOERROR' && !$this->truncated);
    }

    /**
     * An authoritative server that isn't authoritative for this name answers
     * with a referral (no answer, aa=0) instead of data.
     */
    public function isReferral(): bool
    {
        return $this->rcode === 'NOERROR' && !$this->answer && !$this->authoritative;
    }
}
