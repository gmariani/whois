<?php

declare(strict_types=1);

/*
 * Download the free DB-IP "lite" geolocation databases (CC BY 4.0, updated
 * monthly, no account needed) so IP lookups are local instead of hitting a
 * rate-limited API. Run monthly from cron:
 *
 *   0 4 3 * * php /path/to/whois/bin/update-geoip.php
 *
 * The license requires attribution; index.php adds the "IP Geolocation by
 * DB-IP" link automatically when these files are in use.
 */

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$config = require __DIR__ . '/../bootstrap.php';

$targets = [
    'city' => $config->geoCityDb,
    'asn' => $config->geoAsnDb,
];

$failed = false;
foreach ($targets as $kind => $destination) {
    @mkdir(dirname($destination), 0775, true);

    // This month's file may not be published yet on the 1st, so fall back to last month.
    foreach ([date('Y-m'), date('Y-m', strtotime('first day of last month'))] as $month) {
        $url = "https://download.db-ip.com/free/dbip-{$kind}-lite-{$month}.mmdb.gz";
        echo "Downloading {$url}\n";

        $gz = $destination . '.download.gz';
        $fp = fopen($gz, 'wb');
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_FILE => $fp,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_CONNECTTIMEOUT => 15,
            CURLOPT_TIMEOUT => 600,
            CURLOPT_USERAGENT => $config->userAgent,
        ]);
        curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        fclose($fp);

        if ($status !== 200) {
            echo "  HTTP {$status}\n";
            @unlink($gz);
            continue;
        }

        // Decompress to a temp file, sanity-check it, then swap it in atomically.
        $tmp = $destination . '.tmp';
        $in = gzopen($gz, 'rb');
        $out = fopen($tmp, 'wb');
        while (!gzeof($in)) {
            fwrite($out, gzread($in, 1 << 20));
        }
        gzclose($in);
        fclose($out);
        unlink($gz);

        try {
            $reader = new MaxMind\Db\Reader($tmp);
            $probe = $reader->get('8.8.8.8');
            $reader->close();
            if (!$probe) {
                throw new RuntimeException('test lookup returned nothing');
            }
        } catch (Throwable $e) {
            echo "  Downloaded file is not a valid database: {$e->getMessage()}\n";
            @unlink($tmp);
            continue;
        }

        rename($tmp, $destination);
        printf("  Installed %s (%.1f MB)\n", $destination, filesize($destination) / 1048576);
        continue 2;
    }

    $failed = true;
    fwrite(STDERR, "Could not download the {$kind} database.\n");
}

exit($failed ? 1 : 0);
