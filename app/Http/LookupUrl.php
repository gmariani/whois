<?php

declare(strict_types=1);

namespace Whois\Http;

/**
 * Pretty lookup URLs: <base>/google.com/ instead of <base>/?q=google.com.
 *
 * Anything typed after the base path is the query, so
 * <base>/https://example.com/some/page works too. It's read from the raw
 * REQUEST_URI because web servers may collapse the "//" before rewrite rules see it.
 */
final class LookupUrl
{
    /** Requests browsers make on their own that must not count as lookups. */
    private const NOT_LOOKUPS = '#^(favicon\.ico|robots\.txt|apple-touch-icon.*\.png|sitemap\.xml|\.well-known/.*)$#i';

    /** URL path of the app's directory, e.g. "/projects/dns/". */
    public static function base(): string
    {
        $dir = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/'));
        return rtrim($dir, '/') . '/';
    }

    /**
     * @return array{query:string,legacy:bool,ignored:bool} legacy: came from ?q=
     */
    public static function requested(string $base): array
    {
        if (isset($_GET['q'])) {
            return ['query' => trim((string) $_GET['q']), 'legacy' => true, 'ignored' => false];
        }

        $path = (string) strtok((string) ($_SERVER['REQUEST_URI'] ?? '/'), '?');
        if (str_starts_with($path, $base)) {
            $path = substr($path, strlen($base));
        } elseif (str_starts_with($path . '/', $base)) {
            $path = '';
        }
        $path = ltrim(rawurldecode($path), '/');
        if ($path === 'index.php') {
            $path = '';
        }
        // "https:/example.com" when a server merged the slashes.
        $path = (string) preg_replace('#^([a-z][a-z0-9+.-]*):/+#i', '$1://', $path);

        return [
            'query' => trim($path, " \t/"),
            'legacy' => false,
            'ignored' => (bool) preg_match(self::NOT_LOOKUPS, $path),
        ];
    }

    public static function to(string $base, string $domain): string
    {
        return $base . $domain . '/';
    }
}
