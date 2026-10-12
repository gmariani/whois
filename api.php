<?php

declare(strict_types=1);

/*
 * JSON API used by the front-end; each results-page section is fetched separately.
 * See app/Http/Api.php and app/Http/ApiGuard.php.
 */

$config = require __DIR__ . '/app/bootstrap.php';

(new Whois\Http\Api($config))->handle();
