<?php

declare(strict_types=1);

/*
 * Page shell. Renders instantly; the React app then loads each results
 * section from api.php in parallel. Server code lives in app/, front-end source in frontend/.
 */

// PHP's built-in dev server (`npm run serve`) uses this file as its router:
// let it serve real files (api.php, build/…) itself.
if (PHP_SAPI === 'cli-server') {
    $file = $_SERVER['DOCUMENT_ROOT'] . rawurldecode((string) strtok((string) $_SERVER['REQUEST_URI'], '?'));
    if (is_file($file) && realpath($file) !== __FILE__) {
        return false;
    }
}

$config = require __DIR__ . '/app/bootstrap.php';

use Whois\Http\ApiGuard;
use Whois\Http\LookupUrl;
use Whois\Http\Vite;
use Whois\Support\DomainName;

$base = LookupUrl::base();
$request = LookupUrl::requested($base);
if ($request['ignored']) {
    http_response_code(404);
    exit;
}

$query = $request['query'];
$domain = null;
$token = null;
$error = null;

if ($query !== '') {
    try {
        $domain = DomainName::normalize($query);
    } catch (InvalidArgumentException $e) {
        $error = $e->getMessage();
    }

    // Send old ?q= links and non-canonical paths (https://…, missing slash, upper case)
    // to the clean URL, e.g. /projects/dns/google.com/
    $canonical = $domain === null ? null : LookupUrl::to($base, $domain);
    if ($canonical !== null && ($request['legacy'] || strtok((string) $_SERVER['REQUEST_URI'], '?') !== $canonical)) {
        header('Location: ' . $canonical, true, 301);
        exit;
    }

    if ($domain !== null) {
        ['token' => $token, 'error' => $error] = (new ApiGuard($config))->issueToken($domain);
    }
}

$boot = [
    'query' => $query,
    'domain' => $domain,
    'token' => $token,
    'error' => $error,
    'base' => $base,
    'api' => $base . 'api.php',
    'mapsKey' => $config->googleMapsKey,
];

header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('X-Frame-Options: SAMEORIGIN');

$e = static fn (?string $value): string => htmlspecialchars((string) $value, ENT_QUOTES);
$usesDbIp = is_file($config->geoCityDb) && str_contains(basename($config->geoCityDb), 'dbip');
?>
<!doctype html>
<html lang="en" data-bs-theme="dark">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $domain ? $e($domain) . ' — ' : '' ?>Domain Inspector</title>
    <meta name="description" content="Look up a domain's registration (RDAP/WHOIS), DNS records, email authentication, TLS certificate and hosting.">
    <!-- Google tag (gtag.js) -->
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-0XDKVS3VTR"></script>
    <script>
        window.dataLayer = window.dataLayer || [];

        function gtag() {
            dataLayer.push(arguments);
        }
        gtag('js', new Date());
        gtag('config', 'G-0XDKVS3VTR');
    </script>
    <script>
        window.__DOMAIN_INSPECTOR__ = <?= json_encode($boot, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES) ?>;
    </script>
    <?= (new Vite($config, $base))->tags() ?>

</head>

<body class="<?= $query === '' ? 'no-query' : '' ?>">
    <div id="root"></div>

    <?php if ($domain) { ?>
        <footer class="bd-footer py-2 py-md-3 mt-5 bg-body-tertiary">
            <div class="container py-2 py-md-3 px-4 px-md-3 text-body-secondary text-center">
                <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-4393629565174725" crossorigin="anonymous"></script>
                <!-- DNS Lookup Footer -->
                <ins class="adsbygoogle" style="display:block" data-ad-client="ca-pub-4393629565174725" data-ad-slot="4188568892" data-ad-format="auto" data-full-width-responsive="true"></ins>
                <script>
                    (adsbygoogle = window.adsbygoogle || []).push({});
                </script>
                <small class="mb-3 d-block mt-3">The records displayed may not be completely accurate due to the nature of how they were acquired. DNS does not allow access to all DNS records of a particular domain. Instead they must be requested by name. This website attempts many known combinations but ultimately will never be 100% accurate.</small>
                <small class="d-block">
                    Registration data from the registry's and registrar's own <abbr title="Registration Data Access Protocol">RDAP</abbr> servers (located via <a href="https://www.iana.org/domains/root/db" target="_blank" rel="noopener">IANA</a>), with WHOIS as a fallback.
                    IP network data from the Regional Internet Registries. DNS answers come from each zone's authoritative name servers.
                </small>
                <small class="d-block">
                    <?php if ($config->ipinfoToken) { ?>IP data powered by <a href="https://ipinfo.io" target="_blank" rel="noopener">IPinfo</a><?= $usesDbIp ? ' and ' : '' ?><?php } ?>
                    <?php if ($usesDbIp) { ?><a href="https://db-ip.com" target="_blank" rel="noopener">IP Geolocation by DB-IP</a><?php } ?>
                </small>
            </div>
        </footer>
    <?php } ?>
</body>

</html>
