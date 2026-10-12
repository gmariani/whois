<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Whois\Support\Cache;

final class CacheTest extends TestCase
{
    private function cache(): Cache
    {
        return new Cache(sys_get_temp_dir() . '/whois-cache-test-' . bin2hex(random_bytes(4)));
    }

    public function testRememberComputesOnceThenHits(): void
    {
        $cache = $this->cache();
        $calls = 0;
        $compute = function () use (&$calls) {
            $calls++;
            return ['value' => 42];
        };

        self::assertSame(['value' => 42], $cache->remember('k', 60, $compute, $hit));
        self::assertFalse($hit);
        self::assertSame(['value' => 42], $cache->remember('k', 60, $compute, $hit));
        self::assertTrue($hit);
        self::assertSame(1, $calls);
    }

    public function testTransientResultsAreNotCached(): void
    {
        $cache = $this->cache();
        $onlyGood = fn (array $v) => empty($v['transient']);

        $cache->remember('k', 60, fn () => ['transient' => true], $hit, $onlyGood);
        self::assertNull($cache->get('k'), 'a transient failure must not stick');

        $cache->remember('k', 60, fn () => ['ok' => true], $hit, $onlyGood);
        self::assertSame(['ok' => true], $cache->get('k'));
    }

    public function testExpiry(): void
    {
        $cache = $this->cache();
        $cache->set('k', 'v', -1);
        self::assertNull($cache->get('k'));
    }
}
