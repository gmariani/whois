<?php

declare(strict_types=1);

namespace Whois\Http;

/**
 * Fixed-window counters stored as small files (no APCu/Redis needed on
 * shared hosting). flock() keeps concurrent requests from losing counts.
 */
final class RateLimiter
{
    public function __construct(private readonly string $dir)
    {
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0775, true);
        }
    }

    /**
     * Count one hit against $key.
     *
     * @return array{allowed:bool,remaining:int,retryAfter:int}
     */
    public function hit(string $key, int $limit, int $window): array
    {
        $now = time();
        $fp = @fopen($this->dir . '/' . sha1($key), 'c+');
        if ($fp === false) {
            // Fail open: a broken storage dir shouldn't take the site down.
            return ['allowed' => true, 'remaining' => $limit, 'retryAfter' => 0];
        }
        flock($fp, LOCK_EX);
        $state = json_decode((string) stream_get_contents($fp), true);
        if (!is_array($state) || ($state['reset'] ?? 0) <= $now) {
            $state = ['count' => 0, 'reset' => $now + $window];
        }
        $state['count']++;
        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, (string) json_encode($state));
        flock($fp, LOCK_UN);
        fclose($fp);

        return [
            'allowed' => $state['count'] <= $limit,
            'remaining' => max(0, $limit - $state['count']),
            'retryAfter' => max(0, $state['reset'] - $now),
        ];
    }

    public function gc(int $probabilityPercent = 1): void
    {
        if (random_int(1, 100) > $probabilityPercent) {
            return;
        }
        $cutoff = time() - 86400;
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            if (@filemtime($file) < $cutoff) {
                @unlink($file);
            }
        }
    }
}
