<?php

declare(strict_types=1);

namespace Whois\Http;

use InvalidArgumentException;
use Whois\Config;
use Whois\Lookup\Context;
use Whois\Lookup\SectionRunner;
use Whois\Support\Cache;
use Whois\Support\DomainName;

/**
 * GET api.php?section=<name>&q=<domain>  =>  {"ok":true,"data":{…},"meta":{…}}
 */
final class Api
{
    public function __construct(private readonly Config $config)
    {
    }

    public function handle(): never
    {
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        header('X-Robots-Tag: noindex');
        header('Cross-Origin-Resource-Policy: same-origin');

        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'GET') {
            $this->fail(405, 'Method not allowed.');
        }

        $section = (string) ($_GET['section'] ?? '');
        if (!SectionRunner::exists($section)) {
            $this->fail(404, 'Unknown section.');
        }

        try {
            $domain = DomainName::normalize((string) ($_GET['q'] ?? ''));
        } catch (InvalidArgumentException $e) {
            $this->fail(422, $e->getMessage());
        }

        $denied = (new ApiGuard($this->config))->check($domain);
        if ($denied !== null) {
            if (isset($denied[2])) {
                header('Retry-After: ' . $denied[2]);
            }
            $this->fail($denied[0], $denied[1]);
        }

        set_time_limit(30);
        $started = microtime(true);
        $cache = new Cache($this->config->storageDir . '/cache');
        $runner = new SectionRunner();

        try {
            $result = $runner->run($section, new Context($domain, $this->config, $cache, $runner));
        } catch (\Throwable $e) {
            error_log(sprintf('[api] %s for %s failed: %s in %s:%d', $section, $domain, $e->getMessage(), $e->getFile(), $e->getLine()));
            $this->fail(500, $this->config->debug ? $e->getMessage() : 'Lookup failed. Please try again.');
        }

        $cache->gc();
        $this->send(200, [
            'ok' => true,
            'data' => $result['data'],
            'meta' => [
                'section' => $section,
                'domain' => $domain,
                'cached' => $result['cached'],
                'elapsedMs' => (int) round((microtime(true) - $started) * 1000),
            ],
        ]);
    }

    private function fail(int $status, string $message): never
    {
        $this->send($status, ['ok' => false, 'error' => $message]);
    }

    /**
     * @param array<string,mixed> $body
     */
    private function send(int $status, array $body): never
    {
        http_response_code($status);
        echo json_encode($body, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        exit;
    }
}
