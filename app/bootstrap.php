<?php

declare(strict_types=1);

/*
 * Shared bootstrap for index.php (page shell) and api.php (JSON API).
 */

if (!is_file(__DIR__ . '/vendor/autoload.php')) {
    http_response_code(500);
    exit('Dependencies missing: run `composer install` (they install into app/vendor).');
}

require __DIR__ . '/vendor/autoload.php';

// Settings live in the site root, next to index.php. A local .env.development
// (gitignored, never packaged into dist/) overrides .env when present.
// Immutable loading means the first file to define a value wins.
Dotenv\Dotenv::createImmutable(dirname(__DIR__), ['.env.development', '.env'], false)->safeLoad();

// Library deprecation notices must never leak into JSON responses or HTML.
error_reporting(E_ALL & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

return Whois\Config::fromEnv(dirname(__DIR__));
