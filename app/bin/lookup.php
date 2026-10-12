<?php

declare(strict_types=1);

/*
 * Run sections from the command line, bypassing the web API's token and
 * rate-limit checks. Handy for debugging:
 *
 *   php app/bin/lookup.php example.com            # all sections
 *   php app/bin/lookup.php example.com dns email  # just these
 *   php app/bin/lookup.php example.com dns --fresh  # ignore cached results
 */

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$config = require __DIR__ . '/../bootstrap.php';

use Whois\Lookup\Context;
use Whois\Lookup\SectionRunner;
use Whois\Support\Cache;
use Whois\Support\DomainName;

$args = array_slice($argv, 1);
$fresh = in_array('--fresh', $args, true);
$args = array_values(array_diff($args, ['--fresh']));

if (!$args) {
    fwrite(STDERR, "Usage: php app/bin/lookup.php <domain> [section ...] [--fresh]\n");
    fwrite(STDERR, 'Sections: ' . implode(', ', array_keys(SectionRunner::SECTIONS)) . "\n");
    exit(1);
}

$domain = DomainName::normalize(array_shift($args));
$sections = $args ?: array_keys(SectionRunner::SECTIONS);

$cacheDir = $fresh ? sys_get_temp_dir() . '/whois-cli-' . getmypid() : $config->storageDir . '/cache';
$runner = new SectionRunner();
$context = new Context($domain, $config, new Cache($cacheDir), $runner);

foreach ($sections as $name) {
    if (!SectionRunner::exists($name)) {
        fwrite(STDERR, "Unknown section: {$name}\n");
        continue;
    }
    $started = microtime(true);
    $result = $runner->run($name, $context);
    $elapsed = round((microtime(true) - $started) * 1000);
    fwrite(STDERR, sprintf("== %s (%d ms%s)\n", $name, $elapsed, $result['cached'] ? ', cached' : ''));
    echo json_encode($result['data'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
}
