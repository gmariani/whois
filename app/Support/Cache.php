<?php

declare(strict_types=1);

namespace Whois\Support;

/**
 * Tiny JSON file cache. Works on shared hosting without APCu/Redis.
 *
 * remember() takes a per-key lock so parallel API requests that need the same
 * expensive value (e.g. the DNS section, used by both "dns" and "locations")
 * compute it once while the others wait.
 */
final class Cache
{
    private string $dir;

    public function __construct(string $dir)
    {
        $this->dir = rtrim($dir, '/');
        if (!is_dir($this->dir)) {
            @mkdir($this->dir, 0775, true);
        }
    }

    public function get(string $key): mixed
    {
        $file = $this->path($key);
        $raw = @file_get_contents($file);
        if ($raw === false) {
            return null;
        }
        $entry = json_decode($raw, true);
        if (!is_array($entry) || ($entry['expires'] ?? 0) < time()) {
            return null;
        }
        return $entry['value'];
    }

    public function set(string $key, mixed $value, int $ttl): void
    {
        $file = $this->path($key);
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $json = json_encode(['expires' => time() + $ttl, 'value' => $value], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json !== false && @file_put_contents($tmp, $json) !== false) {
            @rename($tmp, $file);
        }
    }

    /**
     * @template T
     * @param callable():T $compute
     * @param (callable(T):bool)|null $cacheIf skip caching when this returns false (e.g. a transient failure)
     * @return T
     */
    public function remember(string $key, int $ttl, callable $compute, ?bool &$hit = null, ?callable $cacheIf = null): mixed
    {
        $hit = false;
        $value = $this->get($key);
        if ($value !== null) {
            $hit = true;
            return $value;
        }

        $lock = @fopen($this->path($key) . '.lock', 'c');
        if ($lock !== false) {
            flock($lock, LOCK_EX);
        }
        try {
            // Another request may have filled it while we waited for the lock.
            $value = $this->get($key);
            if ($value !== null) {
                $hit = true;
                return $value;
            }
            $value = $compute();
            if ($value !== null && ($cacheIf === null || $cacheIf($value))) {
                $this->set($key, $value, $ttl);
            }
            return $value;
        } finally {
            if ($lock !== false) {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
        }
    }

    /**
     * Occasionally sweep expired files so the directory doesn't grow forever.
     */
    public function gc(int $probabilityPercent = 1, int $maxAge = 86400 * 8): void
    {
        if (random_int(1, 100) > $probabilityPercent) {
            return;
        }
        $cutoff = time() - $maxAge;
        foreach (glob($this->dir . '/*') ?: [] as $file) {
            if (@filemtime($file) < $cutoff) {
                @unlink($file);
            }
        }
    }

    private function path(string $key): string
    {
        return $this->dir . '/' . sha1($key) . '.json';
    }
}
