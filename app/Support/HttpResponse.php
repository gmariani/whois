<?php

declare(strict_types=1);

namespace Whois\Support;

final class HttpResponse
{
    public int $status = 0;
    /** @var array<string, list<string>> lower-cased header name => values */
    public array $headers = [];
    public string $body = '';
    public ?string $error = null;
    public ?string $ip = null;
    public int $elapsedMs = 0;
    /** @var list<array{url:string,status:int}> */
    public array $redirects = [];

    public function __construct(public string $url)
    {
    }

    public function ok(): bool
    {
        return $this->error === null && $this->status >= 200 && $this->status < 300;
    }

    /** Last value of a header, which is what matters when a header repeats. */
    public function header(string $name): ?string
    {
        $values = $this->headers[strtolower($name)] ?? [];
        return $values ? end($values) : null;
    }

    public function json(): ?array
    {
        $data = json_decode($this->body, true);
        return is_array($data) ? $data : null;
    }
}
