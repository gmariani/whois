<?php

declare(strict_types=1);

namespace Whois\Http;

use Whois\Config;

/**
 * Keeps the JSON API for this site's own pages only.
 *
 * - index.php issues a token per looked-up domain: an HMAC of
 *   "domain|issued-at" keyed with a random secret held in the visitor's PHP
 *   session. The API accepts it only for that domain, from that session,
 *   before it expires, and for a limited number of requests.
 * - The session cookie is HttpOnly + SameSite=Strict, and the token travels in
 *   a custom header, so other sites can't make a browser call the API
 *   (cross-origin requests with custom headers need a CORS preflight, which
 *   we never grant).
 * - Requests must look same-origin (Sec-Fetch-Site / Origin).
 * - Per-IP limits on how many domains can be looked up and how many API
 *   calls can be made per window.
 *
 * None of this stops a determined scraper that drives a real browser, but it
 * makes the API useless as a free backend for anyone else's site and caps
 * what any single client can cost us.
 */
final class ApiGuard
{
    public const TOKEN_HEADER = 'HTTP_X_LOOKUP_TOKEN';
    private const SESSION_NAME = 'dnsinspector';
    private const SESSION_KEY = 'lookup_secret';

    private RateLimiter $limiter;

    public function __construct(private readonly Config $config)
    {
        $this->limiter = new RateLimiter($config->storageDir . '/ratelimit');
    }

    /**
     * Called by index.php for a page that shows $domain.
     *
     * @return array{token:?string,error:?string}
     */
    public function issueToken(string $domain): array
    {
        $this->startSession(readOnly: false);
        if (empty($_SESSION[self::SESSION_KEY])) {
            $_SESSION[self::SESSION_KEY] = bin2hex(random_bytes(32));
        }
        $secret = $_SESSION[self::SESSION_KEY];
        session_write_close();

        $limit = $this->limiter->hit('lookups:' . $this->clientIp(), $this->config->lookupsPerWindow, $this->config->rateWindow);
        if (!$limit['allowed']) {
            return ['token' => null, 'error' => self::retryMessage($limit['retryAfter'])];
        }

        $issued = time();
        return ['token' => $issued . '.' . hash_hmac('sha256', "{$domain}|{$issued}", $secret), 'error' => null];
    }

    /**
     * Called by api.php. Returns null when allowed, or [status, message].
     *
     * @return array{0:int,1:string,2?:int}|null
     */
    public function check(string $domain): ?array
    {
        if (!$this->isSameOrigin()) {
            return [403, 'Cross-site requests are not allowed.'];
        }

        $token = (string) ($_SERVER[self::TOKEN_HEADER] ?? '');
        if (!preg_match('/^(\d{10})\.([a-f0-9]{64})$/', $token, $m)) {
            return [401, 'Missing lookup token. Reload the page.'];
        }
        [, $issued, $signature] = $m;
        if ((int) $issued + $this->config->tokenTtl < time()) {
            return [401, 'This page has expired. Reload to look the domain up again.'];
        }

        // read_and_close: don't hold the session lock, or parallel section requests would run one at a time.
        $this->startSession(readOnly: true);
        $secret = $_SESSION[self::SESSION_KEY] ?? null;
        if (!is_string($secret) || !hash_equals(hash_hmac('sha256', "{$domain}|{$issued}", $secret), $signature)) {
            return [401, 'Invalid lookup token. Reload the page.'];
        }

        $ip = $this->clientIp();
        $result = $this->limiter->hit("requests:{$ip}", $this->config->requestsPerWindow, $this->config->rateWindow);
        if (!$result['allowed']) {
            return [429, self::retryMessage($result['retryAfter']), $result['retryAfter']];
        }
        // Each page's token is good for one round of sections plus a few retries.
        $result = $this->limiter->hit("token:{$signature}", $this->config->requestsPerToken, $this->config->tokenTtl);
        if (!$result['allowed']) {
            return [429, 'Too many requests from this page. Reload to look the domain up again.'];
        }

        $this->limiter->gc();
        return null;
    }

    private function isSameOrigin(): bool
    {
        // Modern browsers always send this on fetch().
        $site = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
        if ($site !== null && $site !== 'same-origin') {
            return false;
        }
        $origin = $_SERVER['HTTP_ORIGIN'] ?? null;
        if ($origin !== null && strcasecmp((string) parse_url($origin, PHP_URL_HOST), $this->host()) !== 0) {
            return false;
        }
        // Require the custom header that only our own script sets.
        return ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'DomainInspector';
    }

    private function startSession(bool $readOnly): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        $path = rtrim(dirname($_SERVER['SCRIPT_NAME'] ?? '/'), '/') . '/';
        if (!headers_sent()) {
            session_name(self::SESSION_NAME);
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => $path,
                'secure' => $this->isHttps(),
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
        }
        @session_start($readOnly ? ['read_and_close' => true] : []);
    }

    public function clientIp(): string
    {
        // Only trust a forwarding header when explicitly configured (e.g. behind Cloudflare).
        if ($this->config->clientIpHeader !== null) {
            $key = 'HTTP_' . strtoupper(str_replace('-', '_', $this->config->clientIpHeader));
            $forwarded = trim(explode(',', (string) ($_SERVER[$key] ?? ''))[0]);
            if (filter_var($forwarded, FILTER_VALIDATE_IP)) {
                return $forwarded;
            }
        }
        return (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    }

    private function host(): string
    {
        return strtolower(preg_replace('/:\d+$/', '', (string) ($_SERVER['HTTP_HOST'] ?? '')));
    }

    private function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https';
    }

    private static function retryMessage(int $seconds): string
    {
        $minutes = max(1, (int) ceil($seconds / 60));
        return "Too many lookups from your network. Try again in {$minutes} minute" . ($minutes === 1 ? '' : 's') . '.';
    }
}
