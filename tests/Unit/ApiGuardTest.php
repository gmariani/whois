<?php

declare(strict_types=1);

namespace Whois\Tests\Unit;

use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use PHPUnit\Framework\TestCase;
use Whois\Config;
use Whois\Http\ApiGuard;

/**
 * The API's abuse protection. Each test runs in its own process because it
 * uses a real PHP session.
 */
#[RunTestsInSeparateProcesses]
final class ApiGuardTest extends TestCase
{
    private string $storage;

    protected function setUp(): void
    {
        $this->storage = sys_get_temp_dir() . '/whois-guard-' . bin2hex(random_bytes(4));
        ini_set('session.save_path', sys_get_temp_dir());
        session_id('guardtest' . bin2hex(random_bytes(8)));

        $_SERVER['SCRIPT_NAME'] = '/projects/dns/api.php';
        $_SERVER['HTTP_HOST'] = 'mariani.life';
        $_SERVER['REMOTE_ADDR'] = '198.51.100.7';
        $_SERVER['HTTP_SEC_FETCH_SITE'] = 'same-origin';
        $_SERVER['HTTP_X_REQUESTED_WITH'] = 'DomainInspector';
        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_X_LOOKUP_TOKEN']);
    }

    private function guard(int $lookups = 30, int $perToken = 40, int $ttl = 1800): ApiGuard
    {
        return new ApiGuard(new Config(
            rootDir: sys_get_temp_dir(),
            storageDir: $this->storage,
            debug: false,
            viteDevServer: null,
            googleMapsKey: '',
            userAgent: 'test',
            geoCityDb: '',
            geoAsnDb: '',
            geoFallbackIpApi: false,
            ipinfoToken: null,
            lookupsPerWindow: $lookups,
            requestsPerWindow: 400,
            requestsPerToken: $perToken,
            rateWindow: 600,
            tokenTtl: $ttl,
            clientIpHeader: null,
        ));
    }

    /** Issue a token as index.php would, then present it as the browser would. */
    private function issue(string $domain, ?ApiGuard $guard = null): string
    {
        $issued = ($guard ?? $this->guard())->issueToken($domain);
        self::assertNull($issued['error']);
        $_SERVER['HTTP_X_LOOKUP_TOKEN'] = $issued['token'];
        return $issued['token'];
    }

    public function testValidTokenIsAccepted(): void
    {
        $this->issue('github.com');
        self::assertNull($this->guard()->check('github.com'));
    }

    public function testTokenOnlyWorksForItsDomain(): void
    {
        $this->issue('github.com');
        self::assertSame(401, $this->guard()->check('example.com')[0]);
    }

    public function testMissingOrTamperedTokenIsRejected(): void
    {
        self::assertSame(401, $this->guard()->check('github.com')[0], 'no token');

        $token = $this->issue('github.com');
        $_SERVER['HTTP_X_LOOKUP_TOKEN'] = substr($token, 0, -1) . ($token[-1] === 'a' ? 'b' : 'a');
        self::assertSame(401, $this->guard()->check('github.com')[0], 'flipped signature');
    }

    public function testTokenFromAnotherSessionIsRejected(): void
    {
        $this->issue('github.com');
        session_id('someone-else-' . bin2hex(random_bytes(8)));
        self::assertSame(401, $this->guard()->check('github.com')[0]);
    }

    public function testExpiredTokenIsRejected(): void
    {
        $this->issue('github.com');
        $old = time() - 3600;
        $_SERVER['HTTP_X_LOOKUP_TOKEN'] = $old . '.' . hash_hmac('sha256', "github.com|{$old}", $_SESSION['lookup_secret']);

        $denied = $this->guard(ttl: 1800)->check('github.com');
        self::assertSame(401, $denied[0]);
        self::assertStringContainsString('expired', $denied[1]);
    }

    public function testCrossSiteRequestsAreRejected(): void
    {
        $this->issue('github.com');

        $_SERVER['HTTP_SEC_FETCH_SITE'] = 'cross-site';
        self::assertSame(403, $this->guard()->check('github.com')[0], 'Sec-Fetch-Site');

        $_SERVER['HTTP_SEC_FETCH_SITE'] = 'same-origin';
        $_SERVER['HTTP_ORIGIN'] = 'https://evil.example';
        self::assertSame(403, $this->guard()->check('github.com')[0], 'foreign Origin');

        unset($_SERVER['HTTP_ORIGIN'], $_SERVER['HTTP_X_REQUESTED_WITH']);
        self::assertSame(403, $this->guard()->check('github.com')[0], 'missing X-Requested-With');
    }

    public function testEachTokenHasARequestBudget(): void
    {
        $this->issue('github.com');
        $guard = $this->guard(perToken: 3);
        for ($i = 0; $i < 3; $i++) {
            self::assertNull($guard->check('github.com'));
        }
        self::assertSame(429, $guard->check('github.com')[0]);
    }

    public function testLookupsPerIpAreLimited(): void
    {
        $guard = $this->guard(lookups: 2);
        $this->issue('one.com', $guard);
        $this->issue('two.com', $guard);

        $third = $guard->issueToken('three.com');
        self::assertNull($third['token']);
        self::assertStringContainsString('Too many lookups', (string) $third['error']);
    }
}
