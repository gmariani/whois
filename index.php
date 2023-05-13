<?php

require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

// require("vendor/autoload.php");
// include "Hostinger/DigClient.php";
// include "Hostinger/ExecuteDigCommand.php";
// include "Hostinger/RecordTypeFactory.php";
// include "Hostinger/RecordType/Cname.php";
// include "Hostinger/RecordType/Mx.php";
// include "Hostinger/RecordType/Ns.php";
// include "Hostinger/RecordType/RecordType.php";
// require __DIR__ . '/autoloader.php';

// AUTO LOADER //
// function fqcnToPath(string $fqcn, string $prefix)
// {
//     // $relativeClass = ltrim($fqcn, $prefix);
//     $relativeClass = str_replace($prefix, '', $fqcn);
//     return str_replace('\\', '/', $relativeClass) . '.php';
// }
// spl_autoload_register(function (string $class) {
//     $namespaces = [
//         'Spatie\\Dns\\' => 'vendor/dns-2.5.3/src'
//     ];

//     $keyExists = array_filter($namespaces, function ($key) use ($class) {
//         // return str_starts_with($class, $key) === true;
//         return strpos($class, $key) === 0;
//     }, ARRAY_FILTER_USE_KEY);

//     // We don't handle that namespace.
//     // Return and hope some other autoloader handles it.
//     if (count($keyExists) === 0) return;

//     $baseDirectory = array_values($keyExists)[0];
//     $prefix = array_keys($keyExists)[0];
//     $path = fqcnToPath($class, $prefix);
//     require $baseDirectory . '/' . $path;
// });
// AUTO LOADER //

// use Spatie\Dns\Dns;

error_reporting(E_ALL ^ E_WARNING);
set_time_limit(20);
$host_cache = array();
$ip_cache = array();
$dns_cache = array();
$ipinfo_cache = array();
$ipinfo_count = 0;
$ipapi_count = 0;
$keycdn_count = 0;
$arin_count = 0;
$dns_count = 0;
$server_locations = array();
$errors = array();

// COX Hosting: 7trees.com
// LiquidWeb: Coursevector.com

// based on original work from the PHP Laravel framework
if (!function_exists('str_contains')) {
    function str_contains($haystack, $needle)
    {
        return $needle !== '' && mb_strpos($haystack, $needle) !== false;
    }
}

function get_host_by_ip($ip)
{
    global $host_cache, $ip_cache, $dns_count;

    if (!isset($host_cache[$ip])) {
        $host_cache[$ip] = gethostbyaddr($ip);
        $ip_cache[$host_cache[$ip]] = $ip;
        $dns_count++;
    }
    return $host_cache[$ip];
}

function get_host_by_name($domain)
{
    global $host_cache, $ip_cache, $dns_count, $errors;

    if (!isset($ip_cache[$domain])) {
        $result = gethostbyname($domain);
        if ($result === $domain) {
            $errors[] = "Invalid domain, unable to lookup IP";
            return false;
        }

        $ip_cache[$domain] = gethostbyname($domain);
        $host_cache[$ip_cache[$domain]] = $domain;
        $dns_count++;
    }
    return $ip_cache[$domain];
}

function get_dns_record($host, $type)
{
    global $dns_cache, $dns_count;
    if (!isset($dns_cache[$host])) {
        $dns_cache[$host] = array();
    }

    if (!isset($dns_cache[$host][$type])) {
        // error_log("Hostinger getRecord {$host} - {$type}");
        // $client = new Hostinger\DigClient();
        // $result = $client->getRecord($host, $type);
        // error_log(print_r($result, true));

        // error_log("dns_get_record {$host} - {$type}");
        // BUG: There is no timeout for dns_get_record and it can wait minutes for a reply
        // https://github.com/hostinger/php-dig
        // composer require hostinger/php-dig

        $result = dns_get_record($host, $type);

        // https://github.com/spatie/dns
        // $dns = new Dns();
        // $result = $dns->getRecords($host, $type === DNS_A ? 'A' : 'CNAME'); // returns only A records
        // if ($host === 'autodiscover.jplcreative.com') {
        //     error_log("dns_get_record {$host} - {$type}");
        //     error_log(print_r($result, true));
        // }
        // exit;

        // https://mariani.life/projects/dns/?q=jplcreative.com
        // https://mariani.life/projects/dns/?q=pipershores.org
        foreach ($result as &$record) {
            if ((DNS_TXT === $type || DNS_A === $type) && $host !== $record['host']) {
                $record['cname'] = $record['host'];
                $record['host'] = $host;
            }
        }

        // If it fails, just skip it
        if (is_bool($result)) $result = [];

        $dns_cache[$host][$type] = $result;
        $dns_count++;
    }

    // if ($dns_cache[$host][DNS_A] && $dns_cache[$host][DNS_CNAME]) {
    //     unset($dns_cache[$host][DNS_A]);
    // }
    // if ($dns_cache[$host][DNS_TXT] && $dns_cache[$host][DNS_CNAME]) {
    //     unset($dns_cache[$host][DNS_TXT]);
    // }

    return $dns_cache[$host][$type];
}

function get_clean_domain($url)
{
    if (strlen($url) <= 0) die("get_clean_domain - Invalid URL passed");

    if (substr($url, 0, 4) === 'http') {
        $parse = parse_url($url, PHP_URL_HOST);
        return str_replace('_', '', $parse);
    }

    // Remove folders
    $parts = explode('/', $url);
    while (count($parts) > 1) {
        array_pop($parts);
    }
    $url = $parts[0];

    return $url;
}

function get_root_domain($url)
{
    $parts = explode('.', $url);
    $min_parts = 2;

    // If like .co.uk, then leave 3 parts instead of 2
    if (preg_match('/\.[^\.]{2}\.[^\.]{2}$/g', $url) == true) {
        $min_parts = 3;
    }

    while (count($parts) > $min_parts) {
        array_shift($parts);
    }
    $url = implode('.', $parts);

    return $url;
}

function get_tld($domain2)
{
    global $domain;
    if (strlen($domain2) <= 0) die("get_tld - Invalid domain passed $domain");

    $parts = explode('.', $domain2);

    return '.' . $parts[count($parts) - 1];
}

function whois_request($hostname, $server)
{
    $fp = fsockopen($server, 43, $errno, $errstr, 10);
    $tld = get_tld($hostname);

    // Connection refused
    if (!$fp) {
        $errstr = str_replace(array("\r", "\n"), "", $errstr);
        error_log("WhoIs error: $errstr ($errno)");
        return '';
    }

    // The data we're sending
    // if (($tld === '.com' || $tld === '.net')) {
    //     // SO far only verisign uses this command, others fail to work
    //     $out = "={$hostname}\r\n";
    // } else {
    /*
		This domain cannot be registered because it contravenes the Nominet UK naming rules.
		The reason is: Domain names may only comprise the characters A-Z, a-z, 0-9, hyphen (-) and dot (.)..
		*/
    $out = "{$hostname}\r\n";
    // }
    $whois = '';

    // Send the data
    fwrite($fp, $out);

    // Listen for data and "append" all the bits of information to
    // our result variable until the data stream is finished
    // Simple: "give me all the data and tell me when you've reached the end"
    while (!feof($fp)) {
        $whois .= fgets($fp, 128);
    }

    // Close the Socket Connection
    fclose($fp);

    return $whois;
}

function get_whois($domain)
{
    global $errors;
    $debug = false;

    // https://www.iana.org/help/whois
    if ($debug) error_log($domain . ' whois.iana.org');
    $whois = whois_request($domain, 'whois.iana.org');
    // if ($debug) error_log($whois);

    // // http://www.iana.org/domains/root/db
    // $whois_servers = array(
    //     '.org' => "whois.pir.org",
    //     '.info' => "whois.afilias.net",
    //     '.buzz' => "whois.nic.buzz",
    //     '.edu' => "whois.educause.edu",
    //     '.li' => "whois.nic.li",
    //     '.io' => "whois.nic.io",
    //     '.ni' => "whois.nic.io",
    //     '.services' => "whois.donuts.co",
    //     '.agency' => "whois.donuts.co",
    //     '.life' => "whois.donuts.co",
    //     '.today' => "whois.donuts.co",
    //     '.biz' => "whois.biz",
    //     '.us' => "whois.nic.us",
    //     '.uk' => "whois.nic.uk",
    //     '.co' => "whois.nic.co",
    //     '.work' => "whois.nic.work",
    //     '.net' => "whois.verisign-grs.com",
    //     //'.net' => "whois.networksolutions.com",
    //     '.com' => "whois.verisign-grs.com",
    //     //'.com' => "whois.networksolutions.com",
    //     //'.com' => "whois.godaddy.com",
    //     // '.com' => 'whois.google.com',
    //     '.stream' => "whois.nic.stream"
    // ); // whois.godaddy.com

    // Check TLD whois
    if (preg_match_all("/^\s*refer:\s+(.+)$/m", $whois, $matches) > 0) {
        $whois_server = $matches[1][0];
        if ($debug) error_log($domain . ' ' . $whois_server);
        $whois = whois_request($domain, $whois_server);
        if ($debug) error_log($whois);

        // If something like co.uk
        if (preg_match_all("/^\s*refer:\s+(.+)$/m", $whois, $matches) > 0) {
            $whois_server = $matches[1][0];
            $whois = whois_request($domain, $whois_server);
            if ($debug) error_log($whois);
            return $whois;
        } else {
            return $whois;
        }
    }

    return '';
}

function get_nameservers($whois)
{
    // Name Server: ns1.dnszone7.com
    // Name Server: ns2.dnszone7.com
    if (preg_match_all("/^\s*Name Server: (.+)$/m", $whois, $matches) == true) {
        return $matches[1];
    }

    // Try to handle multiline nameservers
    if (preg_match_all("/^\s*Name Servers?:\s*(.+)$/m", $whois, $matches) == true) {
        return $matches[1];
    }

    // UK WhoIs formatted differently
    // Name servers:
    //  ns1.onetouchdns.co.uk     151.236.44.146
    //  ns2.onetouchdns.co.uk     92.48.76.242
    if (preg_match_all("/^\s+Name servers?:\r\n\s+([^\s]+)\s{5}[^\s]+\r\n\s+([^\s]+)\s{5}[^\s]+\r\n/m", $whois, $matches) == true) {
        return [$matches[1], $matches[2]];
    }

    return 'Unknown';
}

// function get_whois_server($whois, $used)
// {
//     $result = false;

//     // Verisign
//     if (preg_match_all("/^\s*Whois Server:?\s+(.+)$/m", $whois, $matches) == true) {
//         $result = $matches[1][0];
//     }

//     if (preg_match_all("/^\s*Registrar WHOIS Server:?\s+(.+)$/m", $whois, $matches) == true) {
//         $result = $matches[1][0];
//         // Registrar WHOIS Server: whois.godaddy.com/
//         $result = get_clean_domain($result);
//     }

//     if ($result === $used) return false;
//     return trim($result);
// }

function get_expiration($whois)
{
    $line_breaks = array("\r", "\n");
    $result = 'Unknown';

    if (preg_match_all("/^\s*Registry Expiry Date: (.+)$/m", $whois, $matches) > 0) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Expiration Date: (.+)$/m", $whois, $matches) > 0) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Domain expires: (.+)$/m", $whois, $matches) > 0) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Domain Expiration Date: (.+)$/m", $whois, $matches) > 0) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Registrar Registration Expiration Date: (.+)$/m", $whois, $matches) > 0) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Expiry date:?\s+(.+)$/m", $whois, $matches) > 0) {
        $result = $matches[1][0];
    }

    if ('Unknown' === $result) return $result;

    // Clean it up
    $result = str_replace($line_breaks, "", $result);

    return $result;
}

function to_date_format($date)
{
    $parts = date_parse($date);
    return $parts['month'] . '/' . $parts['day'] . '/' . $parts['year'];
}

function get_registrar($whois)
{
    $result = $company = 'Unknown';

    if (preg_match_all("/^\s*Registrar: (.+)$/m", $whois, $matches) == true) {
        $result = $company = $matches[1][0];
    }
    if ($company === 'Unknown' && preg_match_all("/^\s*Sponsoring Registrar: (.+)$/m", $whois, $matches) == true) {
        $result = $company = $matches[1][0];
    }

    // UK format
    // Registrar:
    //     123-Reg Limited t/a 123-reg [Tag = 123-REG]
    //     URL: http://www.123-reg.co.uk
    if ($company === 'Unknown' && preg_match_all("/^\s+Registrar:\r\n\s+([^\r\n]+)\r\n/m", $whois, $matches) == true) {
        $result = $company = $matches[1][0];
    }

    // Standardize company name
    $lower_company = strtolower($company);
    if (strpos($lower_company, 'godaddy') !== false) {
        $company = 'GoDaddy';
    } elseif (strpos($lower_company, 'google') !== false) {
        $company = 'Google';
    } elseif (strpos($lower_company, 'register.com') !== false) {
        $company = 'Register.com';
    } elseif (strpos($lower_company, 'wild west domains') !== false) {
        $company = 'Wild West Domains (GoDaddy)';
    } elseif (strpos($lower_company, 'automattic') !== false) {
        $company = 'WordPress.com';
    } elseif (strpos($lower_company, 'network solutions') !== false) {
        $company = 'Network Solutions';
    } elseif (strpos($lower_company, 'enom') !== false) {
        $company = 'eNom (Tucows)';
    } elseif (strpos($lower_company, 'ionos') !== false) {
        $company = 'IONOS by 1&1 Internet';
    } elseif (strpos($lower_company, 'tucows') !== false) {
        $company = 'Tucows';
    }

    // Get URL
    if (preg_match_all("/^\s*Registrar URL: (.+)$/m", $whois, $matches) == true) {
        $registrar_url = $matches[1][0];
        if (strpos($registrar_url, 'http') === false) {
            $registrar_url = 'http://' . $registrar_url;
        }
        $result = '<a href="' . $registrar_url . '" target="_blank">' . $company . '</a>';
    }

    // UK Format
    if (preg_match_all("/^\s+Registrar:\r\n.+\r\n\s+URL:\s+([^\r\n]+)\r\n/m", $whois, $matches) == true) {
        $registrar_url = $matches[1][0];
        if (strpos($registrar_url, 'http') === false) {
            $registrar_url = 'http://' . $registrar_url;
        }
        $result = '<a href="' . $registrar_url . '" target="_blank">' . $company . '</a>';
    }

    return $result;
}

function get_contact($whois)
{
    $result = $name = 'Unknown';
    if (empty($whois)) $whois = '';

    if (preg_match_all("/^\s*Registrant Name:?\s+(.+)$/m", $whois, $matches) > 0) {
        // error_log(print_r($matches[1], true));
        $result = $name = $matches[1][0];
    }

    // UK format
    // Registrant:
    //     C Henson
    if ($name === 'Unknown' && preg_match_all("/^\s+Registrant:?\r\n\s+([^\r\n]+)\r\n/m", $whois, $matches) > 0) {
        // error_log(print_r($matches, true));
        $result = $name = $matches[1][0];
    }
    // error_log(print_r($whois, true));
    if (preg_match_all("/^\s*Registrant Email:?\s+(.+)$/m", $whois, $matches) > 0) {
        $email = trim($matches[1][0]);
        $result = filter_var($email, FILTER_VALIDATE_EMAIL) ? "<a href=\"mailto:{$email}\" >{$name}</a>" : $name;
    }

    return $result;
}

function get_dnssec($whois)
{
    if (preg_match_all("/^\s*DNSSEC:?\s+(.+)$/m", $whois, $matches) == true) {
        return $matches[1][0];
    }

    return 'Unknown';
}

function get_spf($records)
{
    if ($records === false) {
        return false;
    }

    $spf = false;
    foreach ($records as $record) {
        if (isset($record['entries'])) $record['txt'] = implode('', $record['entries']);
        if (isset($record['txt']) && strpos($record['txt'], 'v=spf') !== false) {
            if ($spf === false) $spf = array();
            $result = array();
            $result['raw'] = trim($record['txt']);
            $parts = explode(' ', $result['raw']);
            $result['pass'] = array();
            $result['fail'] = array();
            $result['softfail'] = array();
            $result['neutral'] = array();

            array_shift($parts); // remove v=spf1
            foreach ($parts as $part) {
                if (strpos($part, '+') !== false) {
                    $result['pass'][] = $part;
                } elseif (strpos($part, '-') !== false) {
                    $result['fail'][] = $part;
                } elseif (strpos($part, '~') !== false) {
                    $result['softfail'][] = $part;
                } else {
                    if (strpos($part, '=') !== false && (strpos($part, 'exp=') === false || strpos($part, 'redirect=') === false)) {
                        // SKip, not a valid SPF command
                    } else {
                        $result['neutral'][] = $part;
                    }
                }
            }
            $spf[] = $result;
        }
    }

    return $spf;
}

function get_dkim_single($selector, $domain)
{
    // get_dns_record('google._domainkey.' . $domain, DNS_TXT)
    $host = sprintf('%s._domainkey.%s', $selector, $domain);
    // error_log($host);
    $dkim = false;

    // Check TXT records
    $txt_records = get_dns_record($host, DNS_TXT);
    // error_log(print_r($txt_records, true));
    foreach ($txt_records as $record) {
        if (isset($record['entries'])) $record['txt'] = implode('', $record['entries']);

        // Sometimes they don't have v=DKIM
        if (strpos($record['txt'], 'v=DKIM') !== false || strpos($record['txt'], 'k=rsa') !== false) {
            if ($dkim === false) $dkim = array();

            $result = array();
            $result['host'] = $host;
            // Some services like SendGrid will return a CNAME if you ask for TXT in order
            // to map it dynamically
            if (isset($record['cname'])) $result['cname'] = $record['cname'];
            $result['raw'] = $record;
            $parts = explode(';', trim($record['txt']));
            foreach ($parts as $part) {
                // Undefined offset: 1 in /home/mariani/public_html/projects/dns/index.php on line 457
                // if (strlen($part) > 0) {
                if (strlen($part) > 0 && str_contains($part, '=')) {
                    list($key, $val) = explode('=', trim($part), 2);
                    $result[$key] = $val;
                }
            }
            $result['public_key'] = sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", wordwrap($result['p'], 64, "\n", true));

            $keyres = openssl_pkey_get_public($result['public_key']);
            $key = openssl_pkey_get_details($keyres);
            $result['key_bits'] = $key['bits'] ?? '?';
            // If RSA http://php.net/manual/en/function.openssl-pkey-get-details.php
            //$result['key_modulus'] = $key['n'];
            //$result['key_public_exponent'] = $key['e'];
            $dkim[] = $result;
        }
    }
    if ($txt_records === false) return false;

    return $dkim;
}

function get_dkim($domain)
{
    $dkims = [
        get_dkim_single('default', $domain),
        get_dkim_single('google', $domain),
        get_dkim_single('ga1', $domain),
        get_dkim_single('selector1', $domain),
        get_dkim_single('selector2', $domain),
        get_dkim_single('smtp', $domain),
        get_dkim_single('k1', $domain),
        get_dkim_single('k2', $domain),
        get_dkim_single('k3', $domain),
        get_dkim_single('cm', $domain),
        get_dkim_single('x', $domain),
        get_dkim_single('smtp', $domain),
        get_dkim_single('turbo-smtp', $domain),
        get_dkim_single('s1', $domain),
        get_dkim_single('s2', $domain),
        get_dkim_single('m1', $domain),
        get_dkim_single('smtpapi', $domain),
        get_dkim_single('hs1', $domain),
        get_dkim_single('hs2', $domain),
    ];

    // All results are false
    $dkim_result_count = 0;
    foreach ($dkims as $dkim) {
        if ($dkim === false) $dkim_result_count++;
    }
    if ($dkim_result_count === count($dkims)) {
        return false;
    }

    $dkim_result = [];
    foreach ($dkims as $dkim) {
        if ($dkim) $dkim_result = array_merge($dkim_result, $dkim);
    }
    return $dkim_result;
}

function has_ssl($domain)
{
    $stream = stream_context_create(array('ssl' => array('capture_peer_cert' => true)));
    $socket = stream_socket_client("ssl://{$domain}:443", $error_code, $error_message, 10, STREAM_CLIENT_CONNECT, $stream);

    // If we got a ssl certificate we check here, if the certificate domain
    // matches the website domain.
    // On success a stream resource is returned, false on failure.
    if ($socket) {
        $cont = stream_context_get_params($socket);
        $cert_resource = $cont['options']['ssl']['peer_certificate'];
        return $cert_resource;

        // Expected name has format "/CN=*.yourdomain.com"
        // $namepart = explode( '=', $cert['name'] );

        // We want to correctly confirm the certificate even
        // for subdomains like "www.yourdomain.com"
        /* if ( count( $namepart ) == 2 ) {
            $cert_domain = trim( $namepart[1], '*. ' );
            $check_domain = substr( $domain, -strlen( $cert_domain ) );
            $res = ($cert_domain == $check_domain);
        }*/
    } else {
        // No SSL
        error_log("has_ssl({$domain}) error {$error_code}");
        error_log(print_r($error_message, true));
    }

    return false;
}

function get_dmarc($domain)
{
    $host = sprintf('_dmarc.%s', $domain);
    $records = get_dns_record($host, DNS_TXT);

    if ($records === false) {
        return false;
    }
    // "v=DMARC1;p=reject;pct=100;rua=mailto:postmaster@dmarcdomain.com"
    $dmarc = false;
    foreach ($records as $record) {
        if (isset($record['entries'])) $record['txt'] = implode('', $record['entries']);
        if (strpos($record['txt'], 'v=DMARC') !== false) {
            if ($dmarc === false) $dmarc = array();
            $result = array();
            $result['raw'] = $record;
            $parts = explode(';', trim($record['txt']));
            foreach ($parts as $part) {
                if (strlen($part) > 0) {
                    list($key, $val) = explode('=', trim($part), 2);
                    $result[$key] = $val;
                    if ($key === 'rua' || $key === 'ruf') {
                        $result[$key] = str_replace('mailto:', '', $result[$key]);
                    }
                    if ($key === 'adkim' || $key === 'aspf') {
                        if ($result[$key] === 'r') $result[$key] = "Relaxed Mode";
                        if ($result[$key] === 's') $result[$key] = "Strict Mode";
                    }
                }
            }
            $dmarc[] = $result;
        }
    }

    return $dmarc;
}

function get_arin($ip)
{
    global $arin_count, $errors;
    $result = array();

    // Invalid IP
    if (false === $ip) return false;

    // create a new cURL resource
    $ch = curl_init();

    // set URL and other appropriate options
    curl_setopt($ch, CURLOPT_URL, 'http://whois.arin.net/rest/ip/' . $ip);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15); //timeout in seconds
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/json'));

    // execute
    $curl_result = curl_exec($ch);
    // error_log($curl_result);
    $result['raw_id'] = json_decode($curl_result);

    $arin_count++;
    if (isset($result['raw_id']->net->orgRef)) {
        $result['customer_handle'] = $result['raw_id']->net->orgRef->{'@handle'};
        $org_url = 'http://whois.arin.net/rest/org/' . $result['customer_handle'];
    } elseif (isset($result['raw_id']->net->customerRef)) {
        $result['customer_handle'] = $result['raw_id']->net->customerRef->{'@handle'};
        $org_url = 'http://whois.arin.net/rest/customer/' . $result['customer_handle'];
    }
    if (isset($result['raw_id']->net->orgRef)) {
        $result['customer_link'] = $result['raw_id']->net->orgRef->{'$'};
    } elseif (isset($result['raw_id']->net->customerRef)) {
        $result['customer_link'] = $result['raw_id']->net->customerRef->{'$'};

        //'https://whois.arin.net/rest/org/MSFT
        //	'http://whois.arin.net/rest/org/' . $result['customer_handle'];
    }
    if (isset($result['raw_id']->net->orgRef)) {
        $result['customer_name'] = $result['raw_id']->net->orgRef->{'@name'};
        $org_customer = 'org';
    } elseif (isset($result['raw_id']->net->customerRef)) {
        $result['customer_name'] = $result['raw_id']->net->customerRef->{'@name'};
        $org_customer = 'customer';
    }
    $result['name'] = $result['raw_id']->net->name->{'$'};
    $result['start_address'] = $result['raw_id']->net->startAddress->{'$'};
    $result['end_address'] = $result['raw_id']->net->endAddress->{'$'};
    $result['update_date'] = $result['raw_id']->net->updateDate->{'$'};
    $result['registration_date'] = $result['raw_id']->net->registrationDate->{'$'};
    $netblock_data = $result['raw_id']->net->netBlocks->netBlock;

    $result['net_block'] = array();
    if (is_array($netblock_data)) {
        foreach ($netblock_data as $netblock) {
            $result['net_block'][] = array(
                'start_address' => $netblock->startAddress->{'$'},
                'end_address' => $netblock->endAddress->{'$'},
                'cidr_length' => $netblock->cidrLength->{'$'},
                'description' => $netblock->description->{'$'},
                'type' => $netblock->type->{'$'}
            );
        }
    } else {
        $result['net_block'][] = array(
            'start_address' => $netblock_data->startAddress->{'$'},
            'end_address' => $netblock_data->endAddress->{'$'},
            'cidr_length' => $netblock_data->cidrLength->{'$'},
            'description' => $netblock_data->description->{'$'},
            'type' => $netblock_data->type->{'$'}
        );
    }

    // set URL and other appropriate options
    curl_setopt($ch, CURLOPT_URL, 'http://whois.arin.net/rest/' . $org_customer . '/' . $result['customer_handle']);
    //curl_setopt( $ch, CURLOPT_URL, $result['customer_link'] );

    // execute
    $result['raw_customer'] = json_decode(curl_exec($ch));
    $arin_count++;

    $result['customer_city'] = $result['raw_customer']->{$org_customer}->city->{'$'};
    $result['customer_postal_code'] = $result['raw_customer']->{$org_customer}->postalCode->{'$'};
    if (is_array($result['raw_customer']->{$org_customer}->streetAddress->line)) {

        $streetAddress = array();
        foreach ($result['raw_customer']->{$org_customer}->streetAddress->line as $line) {
            $streetAddress[] = $line->{'$'};
        }
        $result['customer_street_address'] = implode("<br>", $streetAddress);
    } else {
        $result['customer_street_address'] = $result['raw_customer']->{$org_customer}->streetAddress->line->{'$'};
    }
    $result['customer_state'] = isset($result['raw_customer']->{$org_customer}->{"iso3166-2"}) ? $result['raw_customer']->{$org_customer}->{"iso3166-2"}->{'$'} : '';
    $result['customer_country'] = $result['raw_customer']->{$org_customer}->{"iso3166-1"}->name->{'$'};

    // close cURL resource, and free up system resources
    curl_close($ch);

    return $result;
}

// This endpoint is limited to 45 requests per minute from an IP address.
// If you go over the limit your requests will be throttled (HTTP 429)
// until your rate limit window is reset. If you constantly go over the limit
// your IP address will be banned for 1 hour.
// https://ip-api.com/docs/api:json
function geo_lookup_ip_api($ip)
{
    $ipinfo_url = "http://ip-api.com/json/{$ip}";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $ipinfo_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); //timeout in seconds
    curl_setopt($ch, CURLOPT_HEADER, 1);
    $response = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($response, 0, $header_size);
    $body = substr($response, $header_size);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (intval($http_code, 10) === 429) {
        error_log("GeoLocate: ip-api.com Rate Limit " . print_r($body, true));
        return false;
    }

    $json_result = json_decode($body);
    if ($json_result->status === 'fail') {
        /*echo '<pre>';
		var_dump($body);
		echo '</pre>';*/
        // $errors[] = "GeoLocate: Error<br><pre>" . print_r($body, true) . '</pre>';
        if (!empty($body)) error_log("GeoLocate: ip-api.com Error - " . print_r($body, true));
        return false;
    }

    $json_result->ip = $json_result->query;
    $json_result->loc = $json_result->lat . ',' . $json_result->lon;
    $json_result->hostname = get_host_by_ip($ip); //'Unknown (' . $json_result->isp . ')';
    return $json_result;
}

// Free usage of our API is limited to 50,000 API requests per month.
// If you exceed that limit, we'll return a 429 HTTP status code to you.
// https://ipinfo.io/developers#rate-limits
// https://ipinfo.io/developers/data-types#geolocation-data
function geo_lookup_ipinfo($ip)
{
    // Token is limited to this server
    $token = $_ENV['IP_INFO'];

    $ipinfo_url = "http://ipinfo.io/{$ip}?token={$token}";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $ipinfo_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); //timeout in seconds
    curl_setopt($ch, CURLOPT_HEADER, 1);
    $response = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($response, 0, $header_size);
    $body = substr($response, $header_size);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (intval($http_code, 10) === 429) {
        error_log("GeoLocate: ipinfo.io Rate Limit " . print_r($body, true));
        return false;
    }

    return json_decode($body);
}

// Keycdn
// We are rate limiting requests (3r/s) to avoid overload of the system.
// Please note that the use of this service requires a link back in your
// project: [IP Location Finder by KeyCDN](https://tools.keycdn.com/geo)
// It is required to set the request header User-Agent in the format
// keycdn-tools:https?://.*, which must include the website you are using
// the API for. Missing attributions or invalid values will be blocked.
// https://tools.keycdn.com/geo
function geo_lookup_keycdn($ip)
{
    $ipinfo_url = "https://tools.keycdn.com/geo.json?host={$ip}";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $ipinfo_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); //timeout in seconds
    curl_setopt($ch, CURLOPT_HEADER, 1);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'User-Agent: keycdn-tools:https://mariani.life/projects/dns/',
    ]);
    $response = curl_exec($ch);
    $header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
    $header = substr($response, 0, $header_size);
    $body = substr($response, $header_size);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (intval($http_code, 10) === 429) {
        error_log("GeoLocate: keycdn.com Rate Limit " . print_r($body, true));
        return false;
    }

    $json_result = json_decode($body);
    if ($json_result->status !== 'success') {
        if (!empty($result)) error_log("GeoLocate: keycdn.com Error - " . print_r($result, true));
        return false;
    }

    $json_result->region = $json_result->data->geo->region_name;
    $json_result->city = $json_result->data->geo->city;
    $json_result->country = $json_result->data->geo->country_name;
    $json_result->org = $json_result->data->geo->isp;
    $json_result->ip = $json_result->data->geo->ip;
    $json_result->loc = $json_result->data->geo->latitude . ',' . $json_result->data->geo->longitude;
    $json_result->hostname = $json_result->data->geo->host;
    return $json_result;
}

// Free usage of our API is limited to 1,000 API requests per day. If you exceed 1,000 requests in a 24 hour period we'll return a 429 HTTP status code to you.
function get_location($ip)
{
    global $ipinfo_cache, $ipinfo_count, $keycdn_count, $ipapi_count, $errors;

    // Invalid IP
    if (false === $ip) return false;

    // Return cached value
    if (isset($ipinfo_cache[$ip])) {
        return $ipinfo_cache[$ip];
    }

    // OneTrust pulled from Nintendo.com
    // https://geolocation.onetrust.com/cookieconsentpub/v1/geo/location

    $json_result = false;

    // ip-api
    if ($json_result === false) {
        $result = geo_lookup_ip_api($ip);
        $ipapi_count++;
        if ($result !== false) {
            $json_result = $result;
        }
    }

    // Keycdn
    if ($json_result === false) {
        $result = geo_lookup_keycdn($ip);
        $keycdn_count++;
        if ($result !== false) {
            $json_result = $result;
        }
    }

    // ipinfo.io
    if ($json_result === false) {
        $result = geo_lookup_ipinfo($ip);
        $ipinfo_count++;
        if ($result !== false) {
            $json_result = $result;
        }
    }

    // [05-Sep-2017 13:16:57 EST] PHP Notice:  Trying to get property of non-object in /home/mariani/public_html/projects/dns/index.php on line 860
    if (!is_object($json_result)) {
        error_log('location json result error');
        error_log(print_r($json_result, true));
    }

    // Save to cache
    $ipinfo_cache[$ip] = $json_result;

    return $json_result;
}

function write_spf_table($domain, $current_ip, $current_ip_info, $spf, $type)
{
    if (count($spf[$type]) > 0) {
        //echo "<h4>{$type}</h4>";
        //echo "<table class=\"records\">";
        foreach ($spf[$type] as $spf_item) {
            $spf_item = str_replace(array('+', '-', '~', '"'), '', $spf_item);

            // Network/Domain with prefix
            // ip4:192.168.0.1/16
            // a:offsite.example.com/24
            if (strpos($spf_item, ':') !== false && strpos($spf_item, '/') !== false) {
                $mechanism_parts = explode(':', trim($spf_item));
                $mechanism = $mechanism_parts[0];
                $address = $mechanism_parts[1];
?>
                <tr>
                    <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                    <td><?php echo $spf_item; ?></td>
                    <td></td>
                    <td></td>
                </tr>
            <?php
            }
            // Mechanism only with prefix
            // a/24
            // mx/24
            elseif (strpos($spf_item, '/') !== false) {
                $mechanism_parts = explode(':', trim($spf_item));
                $mechanism = $mechanism_parts[0];
                $prefix_length = $mechanism_parts[1];
            ?>
                <tr>
                    <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                    <td><?php echo $spf_item; ?></td>
                    <td colspan="2"><?php echo $current_ip . '/' . $prefix_length; ?></td>
                </tr>
                <?php
            }
            // Mechanism has IP address or domain
            // a:mailers.example.com
            // mx:deferrals.domain.com
            // ip4:192.168.0.1
            // exists:<domain>
            // includes:<domain>
            elseif (strpos($spf_item, ':') !== false) {
                $mechanism_parts = explode(':', trim($spf_item));
                $mechanism = strtolower($mechanism_parts[0]);
                $address = $mechanism_parts[1];

                // Address
                if ($mechanism === 'ip4' || $mechanism === 'ip6') {
                    $ip_info = get_location($address);
                ?>
                    <tr>
                        <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                        <td><?php echo $spf_item; ?></td>
                        <td><?php echo $ip_info ? $ip_info->hostname : "API Rate Limit"; ?></td>
                        <td><?php echo $ip_info ? $ip_info->org : "API Rate Limit"; ?><br><?php echo get_location_address($ip_info); ?></td>
                    </tr>
                <?php
                }
                // Recursive loading of SPF records
                elseif ($mechanism === 'include') {
                    $dns_txt_records = get_dns_record($address, DNS_TXT);
                    $spf_records = get_spf($dns_txt_records);
                ?>
                    <tr>
                        <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                        <td><?php echo $spf_item; ?></td>
                        <td colspan="2"><code><?php echo $spf_records && isset($spf_records[0]) && is_array($spf_records[0]) ? $spf_records[0]['raw'] : ''; ?></code></td>
                    </tr>
                <?php
                }
                // Domain
                else {
                    $ip = get_host_by_name($address);
                    $ip_info = get_location($ip);
                ?>
                    <tr>
                        <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                        <td><?php echo $spf_item; ?></td>
                        <td><?php echo $ip; ?><br><?php echo $ip_info ? $ip_info->hostname : 'API Rate Limit'; ?></td>
                        <td><?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?><br><?php echo get_location_address($ip_info); ?></td>
                    </tr>
                <?php
                }
            }
            // Modifier
            // redirect=<domain>
            // exp=<domain>
            elseif (strpos($spf_item, '=') !== false) {
                $mechanism_parts = explode('=', trim($spf_item));
                $mechanism = $mechanism_parts[0];
                $host = $mechanism_parts[1];

                $ip = get_host_by_name($host);
                $ip_info = get_location($ip);
                ?>
                <tr>
                    <th class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                    <td><?php echo $spf_item; ?></td>
                    <td><?php echo $ip; ?><br><?php echo ($ip_info ? $ip_info->hostname : 'API Rate Limit'); ?></td>
                    <td><?php echo ($ip_info ? $ip_info->org : 'API Rate Limit'); ?><br><?php echo get_location_address($ip_info); ?></td>
                </tr>
                <?php
            }
            // Mechanism only
            // a
            // mx
            else {
                switch ($spf_item) {
                    case 'all':
                ?>
                        <tr>
                            <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                            <td>all</td>
                            <td></td>
                            <td></td>
                        </tr>
                        <?php
                        break;
                    case 'a':
                        // current domain
                        $dns_a_records = get_dns_record($domain, DNS_A);
                        foreach ($dns_a_records as $record) {
                            $ip_info = get_location($record['ip']);
                            // Trying to get property 'hostname' of non-object
                            // Trying to get property 'org' of non-object
                        ?>
                            <tr>
                                <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                                <td><?php echo 'a:' . $record['ip']; ?></td>
                                <td><?php echo ($ip_info ? $ip_info->hostname : 'API Rate Limit'); ?></td>
                                <td><?php echo ($ip_info ? $ip_info->org : 'API Rate Limit') . '<br>' . get_location_address($ip_info); ?></td>
                            </tr>
                        <?php
                        }
                        break;
                    case 'mx':
                        $dns_mx_records = get_dns_record($domain, DNS_MX);
                        foreach ($dns_mx_records as $record) {
                            $ip = get_host_by_name($record['target']);
                            $ip_info = get_location($ip);
                            // Trying to get property 'org' of non-object
                        ?>
                            <tr>
                                <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                                <td><?php echo 'mx:' . $record['target']; ?></td>
                                <td><?php echo $ip; ?><br><?php echo ($ip_info ? $ip_info->hostname : 'API Rate Limit'); ?></td>
                                <td><?php echo ($ip_info ? $ip_info->org : 'API Rate Limit'); ?><br><?php echo get_location_address($ip_info); ?></td>
                            </tr>
                        <?php
                        }
                        break;
                    case 'ptr':
                        $dns_ptr_records = get_dns_record($domain, DNS_PTR);
                        foreach ($dns_ptr_records as $record) {
                            // $ip = get_host_by_name($record['host']);
                            // $ip_info = get_location($ip);
                        ?>
                            <tr>
                                <th width="100px" class="spf-<?php echo $type; ?>"><?php echo $type; ?></th>
                                <td colspan="3"><code><?php echo print_r($record, true); ?></code></td>
                            </tr>
<?php
                        }
                        break;
                }
            }
        }
        //echo "</table>";
    }
}

function seconds_to_time($seconds)
{
    $year = floor(floatval($seconds) / 3.154e+7);
    $day = floor(fmod($seconds / 86400, 365.2422));
    $hours = floor(fmod($seconds / 3600, 24));
    $mins = floor(fmod($seconds / 60, 60));
    $secs = floor($seconds % 60);
    $result = array();
    if ($year > 0) $result[] = $year . 'y';
    if ($day > 0) $result[] = $day . 'd';
    if ($hours > 0) $result[] = $hours . 'h';
    if ($mins > 0) $result[] = $mins . 'm';
    if ($secs > 0) $result[] = $secs . 's';

    //$timeFormat = sprintf('%02d:%02d:%02d', $hours, $mins, $secs);
    return implode(' ', $result);
}

/*
API Limitations

Google Maps - https://developers.google.com/maps/pricing-and-plans/#details
Free up to 25,000 map loads per day.3
$0.50 USD / 1,000 additional map loads, up to 100,000 daily, if billing is enabled.

ipinfo.io - https://ipinfo.io/pricing
1,000 Daily Requests

Arin
No known limitations

ip-api.com - https://members.ip-api.com/
Our endpoints are limited to 45 HTTP requests per minute from an IP address.
If you go over this limit your requests will be throttled (HTTP 429) until your
rate limit window is reset.
*/

//$domain = 'nawcc.org';
$domain = isset($_GET['q']) ? strtolower(trim($_GET['q'])) : 'google.com';
//$domain ='boroughs.org';
$line_breaks = array("\r", "\n");
$domain = get_clean_domain($domain);
$root_domain = get_root_domain($domain);
$is_root_domain = $domain === $root_domain ? true : false;
$whois = get_whois($domain);
$ip = get_host_by_name($domain);
$location = get_location($ip);
$ssl = has_ssl($domain);
$http = $ssl ? 'https://' : 'http://';
$headers = get_headers($http . $domain, 1);

// Follow one redirect to account for WWW vs non-WWW
// if ($headers && $headers[0] === 'HTTP/1.1 301 Moved Permanently') {
//     $headers = get_headers($headers['Location'][0], 1);
// }
// Get just the last location's data
foreach ($headers as $key => $value) {
    if (is_array($value)) {
        $value = end($value);
    }
    $headers[$key] = $value;
}

$geo = $location ? explode(',', $location->loc) : array(0, 0);
$now = time();
$date_now = new DateTime();
$date_now->setTimestamp($now);

function get_location_address($location)
{
    // error_log('get_location_address');
    // error_log(print_r($location, true));

    if (false === $location) return 'API Rate Limit';
    // error_log(print_r($location, true));
    $address = '';
    if (strlen($location->country ?? '') > 0) {
        $address = $location->country;
    }
    if (strlen($location->region ?? '') > 0) {
        $address = $location->region . ' ' . $address;
    }
    if (strlen($location->city ?? '') > 0) {
        $address = $location->city . ', ' . $address;
    }
    return $address;
}

function array_merge_unique($array1, $array2)
{
    $index = array();
    $result = array();
    $arrays = array($array1, $array2);

    // Go through both arrays
    foreach ($arrays as $array) {
        // Go through each record
        foreach ($array as $record) {
            // Normalize record to make a fingerprint
            $record2 = $record;
            $record2['ttl'] = 0;
            $json = json_encode($record2);
            $md5 = md5($json);

            //echo $md5 . ' ' . $json . '<br>';
            // See if fingerprint already exists before adding record
            if (!isset($index[$md5])) {
                $index[$md5] = 1;
                $result[] = $record;
            }
        }
    }

    return $result;
}

function val_to_string($val)
{
    if (is_array($val)) {
        return implode('<br>', $val);
    }
    return $val;
}
// error_log('get_dns_records');
// New servers are set to deny DNS_ALL and DNS_ANY
//$dns_records = get_dns_record( $domain, DNS_ALL );
// TODO CAA
// TODO hiinfo
// TODO A6
// TODO quoery only the authoritiave nameservers to get the true TTL For records, use Net_DNS2 https://netdns2.com/
$dns_records = array(
    'a' => get_dns_record($domain, DNS_A),
    'cname' => get_dns_record($domain, DNS_CNAME),
    //'hinfo' => get_dns_record( $domain, DNS_HINFO ),
    //'caa' => get_dns_record( $domain, DNS_CAA ), // PHP 7.1.2+
    'mx' => get_dns_record($domain, DNS_MX),
    'ns' => get_dns_record($domain, DNS_NS),
    'ptr' => get_dns_record($domain, DNS_PTR),
    'soa' => get_dns_record($domain, DNS_SOA),
    'txt' => get_dns_record($domain, DNS_TXT),
    'aaaa' => get_dns_record($domain, DNS_AAAA),
    'srv' => get_dns_record($domain, DNS_SRV),
    'naptr' => get_dns_record($domain, DNS_NAPTR)
);

function check_default_records(&$dns_records, $domain)
{
    $default_subdomains = [
        // Default cPanel
        'ftp', 'www', 'mail', 'webmail', 'webdisk', 'whm', 'cpanel', 'cpcalendars', 'cpcontacts', 'autoconfig',
        // Default MS Exchange
        'autodiscover', 'sip', 'lyncdiscover', 'msoid', 'enterpriseregistration', 'enterpriseenrollment',
        // Common
        '_cf-custom-hostname', '_domainconnect', '_dmarc', 'dev', 'staging', 'stagingwww', 'calendar', 'docs', 'sites', 'start', 'email',
        'fax', 'files', 'imap', 'pop', 'smtp', 'mobileemail',
        'remote', 'course', 'blog', 'server', 'ns1', 'ns2', 'secure', 'vpn', 'm', 'shop', 'test', 'portal', 'host',
        'ww1', 'support', 'web', 'bbs', 'mx', 'cloud', 'forum', 'owa', 'www2', 'admin', 'cdn', 'api', 'app',
        'exchange', 'gov', 'news', 'vps', 'ns', 'mail2', 'mx0', 'mx1', 'mailserver', 'server', 'r.1', 'r.2', 'r.3',
        'spam', 'auth', 'sso', 'webapps', 'securemail', 'online', 'signin', 'account', 'myonline', 'myaccount'
    ];
    // sanity check
    $default_subdomains = array_unique($default_subdomains);

    // Check A record wildcard
    $wildcard_records = get_dns_record("mariani-is-cool.{$domain}", DNS_A);
    $is_wildcard = count($wildcard_records) > 0 ? true : false;
    $wildcard_ips = [];
    if ($is_wildcard) {
        foreach ($wildcard_records as &$wildcard_record) {
            $wildcard_record['host'] = "*.{$domain}";
            $wildcard_ips[] = $wildcard_record['ip'];
        }
        $dns_records['a'] = array_merge_unique($dns_records['a'], $wildcard_records);
    }

    // Common subdomains to test/guess
    foreach ($default_subdomains as $subdomain) {
        $a_record = get_dns_record("{$subdomain}.{$domain}", DNS_A);
        if (isset($a_record[0])) {
            if ($is_wildcard) {
                if (!in_array($a_record[0]['ip'], $wildcard_ips)) {
                    $dns_records['a'] = array_merge_unique($dns_records['a'], $a_record);
                }
            } else {
                $dns_records['a'] = array_merge_unique($dns_records['a'], $a_record);
            }
        } else {
            // sometimes a CNAME will return nothing
            //error_log("${subdomain}.${domain}");
            //error_log(print_r($a_record, true));
        }
    }

    // If this is a c_name, it will return a lot of junk we don't want, so we check if it's related to the domain
    // $autodiscover = get_dns_record('autodiscover.' . $domain, DNS_A);
    // if ($autodiscover && strpos($autodiscover[0]['host'], 'autodiscover.' . $domain) !== false) {
    //     $a_record = get_dns_record('autodiscover.' . $domain, DNS_A);
    //     if (isset($a_record[0])) {
    //         if ($is_wildcard) {
    //             if (!in_array($a_record[0]['ip'], $wildcard_ips)) {
    //                 $dns_records['a'] = array_merge_unique($dns_records['a'], $a_record);
    //             }
    //         } else {
    //             $dns_records['a'] = array_merge_unique($dns_records['a'], $a_record);
    //         }
    //     } else {
    //         // sometimes a CNAME will return nothing
    //         //error_log("${subdomain}.${domain}");
    //         //error_log(print_r($a_record, true));
    //     }
    // }

    // Check CNAME record wildcard
    $wildcard_record = get_dns_record("mariani-is-cool.{$domain}", DNS_CNAME);
    $is_wildcard = count($wildcard_record) > 0 ? true : false;
    $wildcard_targets = [];
    if ($is_wildcard) {
        foreach ($wildcard_records as &$wildcard_record) {
            $wildcard_record['host'] = "*.{$domain}";
            $wildcard_targets[] = $wildcard_record['target'];
        }
        $dns_records['cname'] = array_merge_unique($dns_records['cname'], $wildcard_records);
    }

    // foreach ($default_subdomains as $subdomain) {
    //     $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record("${subdomain}.${domain}", DNS_CNAME));
    // }
    // Common subdomains to test/guess
    foreach ($default_subdomains as $subdomain) {
        $cname_record = get_dns_record("{$subdomain}.{$domain}", DNS_CNAME);
        if (isset($cname_record[0])) {
            if ($is_wildcard) {
                if (!in_array($cname_record[0]['target'], $wildcard_targets)) {
                    $dns_records['cname'] = array_merge_unique($dns_records['cname'], $cname_record);
                }
            } else {
                $dns_records['cname'] = array_merge_unique($dns_records['cname'], $cname_record);
            }
        } else {
            // sometimes a CNAME will return nothing
            //error_log("${subdomain}.${domain}");
            //error_log(print_r($a_record, true));
        }
    }

    // // If this is a c_name, it will return a lot of junk we don't want, so we check if it's related to the domain
    // $autodiscover = get_dns_record('autodiscover.' . $domain, DNS_CNAME);
    // if ($autodiscover && strpos($autodiscover[0]['host'], 'autodiscover.' . $domain) !== false) {
    //     if ($is_wildcard) {
    //         if (!in_array($cname_record[0]['target'], $wildcard_targets)) {
    //             $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('autodiscover.' . $domain, DNS_CNAME));
    //         }
    //     } else {
    //         $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('autodiscover.' . $domain, DNS_CNAME));
    //     }
    // }

    $dns_records['srv'] = array_merge_unique($dns_records['srv'], get_dns_record('_autodiscover._tcp.' . $domain, DNS_SRV));
    $dns_records['srv'] = array_merge_unique($dns_records['srv'], get_dns_record('_caldav._tcp.' . $domain, DNS_SRV));
    $dns_records['srv'] = array_merge_unique($dns_records['srv'], get_dns_record('_caldavs._tcp.' . $domain, DNS_SRV));
    $dns_records['srv'] = array_merge_unique($dns_records['srv'], get_dns_record('_carddav._tcp.' . $domain, DNS_SRV));
    $dns_records['srv'] = array_merge_unique($dns_records['srv'], get_dns_record('_carddavs._tcp.' . $domain, DNS_SRV));

    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('_caldav._tcp.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('_caldavs._tcp.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('_carddav._tcp.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('_carddavs._tcp.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('default._domainkey.' . $domain, DNS_TXT));
    // cPanel
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('_cpanel-dcv-test-record.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('_acme-challenge.' . $domain, DNS_TXT));
    // Google
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('google._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('ga1._domainkey.' . $domain, DNS_TXT));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('google._domainkey.' . $domain, DNS_CNAME));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('ga1._domainkey.' . $domain, DNS_CNAME));
    // MS 365
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('selector1._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('selector2._domainkey.' . $domain, DNS_TXT));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('selector1._domainkey.' . $domain, DNS_CNAME));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('selector2._domainkey.' . $domain, DNS_CNAME));
    // Mailchimp
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('k1._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('k2._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('k3._domainkey.' . $domain, DNS_TXT));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('k1._domainkey.' . $domain, DNS_CNAME));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('k2._domainkey.' . $domain, DNS_CNAME));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('k3._domainkey.' . $domain, DNS_CNAME));
    // Cloudflare
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('_cf-custom-hostname.' . $domain, DNS_TXT));
    // Campaign Monitor
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('cm._domainkey.' . $domain, DNS_TXT));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('cm._domainkey.' . $domain, DNS_CNAME));
    // MXRoute
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('x._domainkey.' . $domain, DNS_TXT));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('x._domainkey.' . $domain, DNS_CNAME));
    // Mailgun
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('smtp._domainkey.' . $domain, DNS_TXT));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('smtp._domainkey.' . $domain, DNS_CNAME));
    // turboSMTP
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('turbo-smtp._domainkey.' . $domain, DNS_TXT));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('turbo-smtp._domainkey.' . $domain, DNS_CNAME));
    // SendGrid
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('s1._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('s2._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('m1._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('smtpapi._domainkey.' . $domain, DNS_TXT));
    // HubSpot
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('hs1._domainkey.' . $domain, DNS_CNAME));
    $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('hs2._domainkey.' . $domain, DNS_CNAME));

    // If a CNAME exists for a matchin A or TXT record, remove them as only the CNAME should exist
    foreach ($dns_records['cname'] as $cname_record) {
        $host = $cname_record['host'];
        foreach ($dns_records['a'] as $key => $a_record) {
            if ($a_record['host'] === $host) {
                unset($dns_records['a'][$key]);
            }
        }
        foreach ($dns_records['txt'] as $key => $txt_record) {
            if ($txt_record['host'] === $host) {
                unset($dns_records['txt'][$key]);
            }
        }
    }
}
// error_log('check_default_records');
// Check any default subdomains
check_default_records($dns_records, $domain);
// If we are working with a subdomain, merge in the parent/root domains records
if (!$is_root_domain) {
    check_default_records($dns_records, $root_domain);
}


// Sort MX records by priority
function sortByPriority($a, $b)
{
    return $a['pri'] - $b['pri'];
}
usort($dns_records['mx'], 'sortByPriority');
// error_log('get_spf');
$spf_records = get_spf($dns_records['txt']);
// error_log('get_dkim');
$dkim_records = get_dkim($domain);
// error_log(print_r($dkim_records, true));
$dns_records['dkim'] = array();
foreach ($dkim_records as $dkim) {
    $dns_records['dkim'][] = $dkim['raw'];
}
// error_log('get_dmarc');
$dmarc_records = get_dmarc($domain);
$dns_records['dmarc'] = array();
foreach ($dmarc_records as $dmarc) {
    $dns_records['dmarc'][] = $dmarc['raw'];
}
// error_log('get_arin');
$arin = get_arin($ip);
// error_log('get_registrar');
$domain_data = array(
    'registrar' => get_registrar($whois),
    'expiration' => get_expiration($whois),
    'contact' => get_contact($whois),
    'dnssec' => get_dnssec($whois),
    'nameservers' => get_nameservers($whois)
);
// $errors[] = "Domain Data:<br><pre>" . print_r($domain_data, true) . '</pre>';

function translate_org($org)
{
    $lower_org = strtolower($org);
    // error_log('translate_org ' . $lower_org);
    if (strpos($lower_org, 'websitewelcome.com') !== false) {
        $org = 'HostGator';
    } elseif (strpos($lower_org, 'cloudflare') !== false) {
        $org = 'Cloudflare';
    } elseif (strpos($lower_org, 'coursevector') !== false) {
        $org = 'CourseVector';
    } elseif (strpos($lower_org, 'sourcedns') !== false) {
        $org = 'Liquid Web';
    } elseif (strpos($lower_org, 'bluehost') !== false) {
        $org = 'BlueHost';
    } elseif (strpos($lower_org, 'media temple') !== false) {
        $org = 'Media Temple';
    } elseif (strpos($lower_org, 'godaddy') !== false) {
        $org = 'GoDaddy';
    } elseif (strpos($lower_org, 'digitalocean') !== false) {
        $org = 'DigitalOcean';
    } elseif (strpos($lower_org, 'centurylink') !== false) {
        $org = 'CenturyLink Communications';
    } elseif (strpos($lower_org, 'squarespace') !== false) {
        $org = 'Squarespace';
    } elseif (str_contains($lower_org, 'nexcess')) {
        // nexcess-net
        $org = 'Nexcess';
    } elseif (strpos($lower_org, 'google') !== false) {
        $org = 'Google';
    } elseif (str_contains($lower_org, 'amazon-aes') !== false) {
        // AMAZON-AES
        $org = 'Amazon';
    }
    return !empty($org) ? $org : 'Unknown/Self';
}
// error_log('ready');
?>
<!doctype html>
<html lang="en" data-bs-theme="dark">

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-KK94CHFLLe+nY2dmCWGMq91rCGa5gtU4mk92HdvYe+M/SXH301p5ILy+dN9+nJOZ" crossorigin="anonymous">
    <title>Domain Inspector</title>
    <!--
    <style>
        @font-face {
        font-family: 'Lato';
        font-style: normal;
        font-weight: 400;
        src: local('Lato Regular'), local('Lato-Regular'), url(https://fonts.gstatic.com/s/lato/v11/7aC-Y4V2UPHQp-tqeekgkA.woff2) format('woff2');
        src: local('Lato Regular'), local('Lato-Regular'), url(https://fonts.gstatic.com/s/lato/v11/9k-RPmcnxYEPm8CNFsH2gg.woff) format('woff');
        /*src: local('Lato Regular'), local('Lato-Regular'), url('../font/Lato-Regular.woff') format('woff');*/
        unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02C6, U+02DA, U+02DC, U+2000-206F, U+2074, U+20AC, U+2212, U+2215, U+E0FF, U+EFFD, U+F000;
        }

        /* Gridly */
        .row {
        display: flex
        }

        .col {
        flex: 1
        }

        @media(max-width:48em) {
        .row {
        flex-direction: column
        }

        .col {
        flex: 0 0 auto
        }
        }

        @media(min-width:48em) {
        .col-tenth {
        flex: 0 0 10%
        }

        .col-fifth {
        flex: 0 0 20%
        }

        .col-quarter {
        flex: 0 0 25%
        }

        .col-third {
        flex: 0 0 33.3333334%
        }

        .col-half {
        flex: 0 0 50%
        }
        }

        *,
        *:after,
        *:before {
        box-sizing: border-box;
        border: 0 solid #e5e7eb;
        }

        html {
        font-feature-settings: "cv02", "cv03", "cv04", "cv11";
        font-variation-settings: normal;
        }

        /* Default to dark theme */
        html {
        --text-color-normal: hsl(210, 10%, 66%);
        --text-color-normal-disabled: hsla(210, 10%, 66%, 50%);
        --text-color-light: hsl(210, 90%, 90%);
        --text-color-richer: hsl(210, 50%, 62%);
        --text-color-richer-see-through: hsl(210, 50%, 62%, 33%);
        --text-color-richer-half-see-through: hsl(210, 50%, 62%, 60%);
        --text-color-highlight: hsl(25, 75%, 50%);
        --text-color-highlight-light: hsla(25, 70%, 45%, 0.507);

        --link-color: hsl(210, 80%, 55%);
        --bright-color: hsl(25, 70%, 60%);
        --error-color: rgb(240, 50, 50);

        --button-background: hsl(210, 63%, 43%);
        --button-background-error: hsl(13, 61%, 50%);
        --button-background-error-highlight: var(--text-color-light);
        --button-text: black;
        --beta-button-background: var(--text-color-light);

        --background: hsl(210, 20%, 12%);
        --list-row-odd-background: hsl(210, 20%, 9%);
        --highlight-background: hsl(210, 22%, 16%);
        --popup-background: black;

        --banner-button-background: var(--highlight-background);
        --banner-button-background-hover: hsl(0, 0%, 83%);
        --banner-button-border: var(--banner-button-background);

        --input-text: var(--text-color-normal);
        --input-background: var(--background);
        --input-border: var(--text-color-normal);

        --popup-menu-selected-background: hsl(210, 29%, 28%);

        --header-gradient-start: black;
        --header-gradient-end: var(--background);

        --header-logo-color: hsl(210, 90%, 70%);
        --avatar-logo-color: hsl(210, 63%, 43%);

        --disabled-opacity: 0.3;
        }

        html[data-theme='light'] {
        /* Normal text color. */
        --text-color-normal: hsl(216, 77%, 17%);
        --text-color-normal-disabled: hsla(216, 77%, 17%, 50%);
        /* Lighter, less prominent variant. */
        --text-color-light: hsl(216, 70%, 50%);
        /* Slightly richer text color, used for headlines, etc. */
        --text-color-richer: hsl(216, 77%, 25%);
        --text-color-richer-see-through: hsla(216, 77%, 25%, 33%);
        --text-color-richer-half-see-through: hsla(216, 77%, 25%, 60%);
        /* Much more rich accent color for text. [Orange] */
        --text-color-highlight: hsl(12, 74%, 50%);
        --text-color-highlight-light: hsla(12, 74%, 50%, 0.507);

        /* Color for links. */
        --link-color: hsl(200, 100%, 42%);
        /* Accent color for UI elements (mostly hover text). [Orange] */
        --bright-color: hsl(12, 82%, 60%);
        /* Color for error states. [Red] */
        --error-color: red;

        /* Button background and text colors. */
        --button-background: var(--text-color-richer);
        --button-background-error: hsl(13, 61%, 50%);
        --button-background-error-highlight: var(--text-color-light);
        --button-text: white;

        /* Normal background. */
        --background: hsl(203, 36%, 95%);
        /* Alternating lists rows. */
        --list-row-even-background: var(--background);
        --list-row-odd-background: #f9faff;
        /* Darker background, e.g. for code blocks etc. */
        --highlight-background: #d7dfe7;
        /* Background for pop-ups. */
        --popup-background: white;

        --banner-button-background: var(--highlight-background);
        --banner-button-background-hover: hsl(212, 72%, 59%);
        --banner-button-border: var(--banner-button-background);

        /* Input background and text colors */
        --input-text: var(--text-color-normal);
        --input-background: var(--background);
        --input-border: var(--text-color-richer);

        /* Shadow for pop-ups. */
        --shadow: 0 0.5rem 10px rgba(0, 0, 0, 0.3);

        /* Colors for text and selected lines for menus (e.g. search completions) */
        --popup-menu-text-color: var(--text-color-normal);
        --popup-menu-selected-background: #ced5df;
        /* Slightly darker than --highlight-background. */

        /* Gradient for the top window header. */
        --header-gradient-start: hsl(216, 100%, 29%);
        --header-gradient-end: hsl(216, 76%, 39%);

        /*Header logo*/
        --header-logo-color: hsl(203, 36%, 87%);
        --avatar-logo-color: hsl(216, 77%, 17%);

        --disabled-opacity: 0.3;
        }

        html[data-theme='high-contrast'] {
        --text-color-normal: white;
        --text-color-light: white;
        --text-color-richer: white;
        --text-color-richer-see-through: white;
        --text-color-richer-half-see-through: white;
        --text-color-highlight: white;
        --text-color-highlight-light: white;

        --link-color: white;
        --bright-color: white;
        --error-color: white;

        --button-background: white;
        --button-background-error: white;
        --button-background-error-highlight: white;
        --button-text: black;

        --background: black;
        --list-row-odd-background: black;
        --highlight-background: black;
        --popup-background: black;

        --banner-button-background: black;
        --banner-button-background-hover: white;
        --banner-button-border: white;

        --shadow: 0 0 5px white, 0 0 5px white;

        --popup-menu-text-color: black;
        --popup-menu-selected-background: white;

        --header-gradient-start: black;
        --header-gradient-end: black;

        --header-logo-color: white;
        --avatar-logo-color: black;

        --disabled-opacity: 0;
        }

        html.color-theme-in-transition,
        html.color-theme-in-transition *,
        html.color-theme-in-transition *:before,
        html.color-theme-in-transition *:after {
        transition: all 750ms !important;
        transition-delay: 0 !important;
        }

        html,
        body {
        height: 100%;
        width: 100%;
        margin: 0;
        padding: 0;
        }

        body {
        font-family: 'Lato', Helvetica, Arial, sans-serif;
        text-rendering: optimizeLegibility;
        background-color: rgb(15 23 42/1);
        color: rgb(148 163 184/1);
        padding-bottom: 2rem;
        display: flex;
        flex-direction: column;
        align-items: center;
        }

        main {
        width: 100%;
        /*height: 100%;*/
        max-width: 1170px;
        flex: 1;
        }

        code,
        pre {
        font-family: Menlo, Consolas, Monaco, monospace;
        /*font-family: "PT Mono", monospace;*/
        font-size: .8rem;
        line-height: 1.26rem;
        margin: 0;
        /*color:#5f5f5f;*/
        }

        pre {
        background-color: var(--highlight-background);
        /*#f9f9f9;*/
        border: 1px solid #333;
        margin-top: 1rem;
        padding: 1rem;
        -moz-tab-size: 4;
        tab-size: 4;
        overflow-x: auto;
        border-radius: 3px;
        color: var(--text-color-highlight);
        /*#333;*/
        }

        h1 {
        font-size: 1.728rem;
        line-height: 1.4;
        margin-top: 2.1rem;
        font-weight: 700;
        }

        @media all and (min-width: 640px) {
        h1 {
        font-size: 2.0736rem;
        }
        }

        h2 {
        font-size: 1.44rem;
        line-height: 1.35;
        margin-top: 1.5rem;
        margin-bottom: 0;
        font-weight: 700;
        border-bottom: 1px solid #ddd;
        }

        h3,
        h4 {
        font-size: 1.2rem;
        line-height: 1.3;
        }

        h3,
        h4,
        h6 {
        font-weight: 500;
        }

        h3 {
        font-weight: 700;
        text-decoration: underline;
        }

        h6 {
        font-size: .69444rem;
        line-height: 1.4rem;
        margin-top: .7rem;
        /*color: #aaa;*/
        font-style: italic;
        }

        h4 {
        text-align: center;
        text-transform: capitalize;
        }

        p {
        color: #dedede;
        font-family: Helvetica, Arial, sans-serif;
        font-size: 1rem;
        }

        a {
        text-decoration: none;
        color: var(--link-color);
        /*#0076B8;*/
        transition: opacity 1s linear;
        opacity: 1;
        outline: medium none;
        }

        a.disabled {
        cursor: default;
        opacity: 0.5;
        }

        table {
        margin-top: 0.5rem;
        border-spacing: 0;
        border-collapse: collapse;
        width: 100%;
        }

        table th {
        max-width: 200px;
        }

        table th,
        table td {
        vertical-align: top;
        text-align: left;
        }

        .search-bar {
        /* padding-top: 1rem; */
        background-color: #1e293b;
        /* padding-bottom: 1rem; */
        margin-bottom: 1rem;
        border-bottom: 1px solid #e2e8f00d;
        display: flex;
        align-content: center;
        justify-content: center;
        width: 100%;
        }

        .search-bar form {
        width: 100%;
        max-width: 1170px;
        display: flex;
        align-items: center;
        flex: 1 1 auto;
        }

        input::placeholder,
        textarea::placeholder {
        color: #9ca3af;
        }

        .search-bar input {
        display: flex;
        flex: 1;
        margin-right: 0.3rem;

        height: 3.5rem;
        margin-left: .75rem;
        margin-right: 1rem;
        font-size: .875rem;
        line-height: 1.42857143;
        color: rgb(226 232 240);
        background: #0000;
        font-weight: 400;

        background-image: none;
        }

        .search-bar input:focus {
        outline: 2px dotted #0000;
        }

        .search-bar label {
        height: 1.5rem;
        width: 1.5rem;
        flex: none;
        }

        .search-bar button {
        padding-top: .25rem;
        padding-bottom: .25rem;
        padding-left: .75rem;
        padding-right: .75rem;
        background-color: #38bdf81a;
        border-radius: 9999px;
        font-weight: 600;
        color: rgb(56 189 248/1);
        line-height: 1.25rem;
        font-size: .75rem;
        }

        /* .records {} */

        .records td,
        .records th,
        .records__col {
        padding: 0.3rem 0.7rem;
        }

        /* .records tr:nth-child(odd),
        .records__row:nth-child(odd) {
        background: #CCC;
        } */

        .records tr:nth-child(even),
        .records__row:nth-child(even) {
        background: rgba(255, 255, 255, 0.075);
        }

        .records td code {
        line-break: anywhere;
        }

        .values-list tr:nth-child(even) td {
        background: rgba(255, 255, 255, 0.075);
        }

        /* Tabs */
        .tabs {
        margin-bottom: 20px;
        padding-left: 0px;
        border-bottom: 1px solid #D8D8D8;
        }

        .tabs__tab {
        display: inline-block;
        padding-left: 3px;
        padding-right: 3px;
        margin-right: 30px;
        color: #dedede;
        font-family: "Lato";
        font-size: 15px;
        cursor: pointer;
        }

        .tabs__tab--active {
        font-family: "Lato";
        font-size: 15px;
        color: #0076b8;
        font-weight: bold;
        padding-bottom: 12px;
        border-bottom: 3px solid;
        }

        .tab-content {
        display: none;
        padding-bottom: 3rem;
        }

        .tab-content--active {
        display: block;
        }

        .google-map {
        width: 100%;
        height: 400px;
        }

        .google-map--tall {
        height: 700px;
        }

        .gm-style .gm-style-iw {
        color: #333;
        }

        .gm-style .gm-style-iw strong {
        font-weight: 700;
        }

        .error {
        color: red;
        }


    </style>
    -->
    <style>
        :root,
        [data-bs-theme="light"] {
            --bd-purple: #4c0bce;
            --bd-violet: #712cf9;
            --bd-accent: #ffe484;
            --bd-violet-rgb: 112.520718, 44.062154, 249.437846;
            --bd-accent-rgb: 255, 228, 132;
            --bd-pink-rgb: 214, 51, 132;
            --bd-teal-rgb: 32, 201, 151;
            --bd-violet-bg: var(--bd-violet);
            --bd-toc-color: var(--bd-violet);
            --bd-sidebar-link-bg: rgba(var(--bd-violet-rgb), .1);
            --bd-callout-link: 10, 88, 202;
            --bd-callout-code-color: #ab296a;
            --bd-pre-bg: var(--bs-tertiary-bg);
        }

        [data-bs-theme="dark"] {
            --bd-violet: #9461fb;
            --bd-violet-bg: #712cf9;
            --bd-toc-color: var(--bs-emphasis-color);
            --bd-sidebar-link-bg: rgba(84, 33, 187, .5);
            --bd-callout-link: 110, 168, 254;
            --bd-callout-code-color: #e685b5;
            --bd-pre-bg: #1b1f22;
        }

        [data-bs-theme="dark"] {
            --docsearch-text-color: #f5f6f7;
            --docsearch-container-background: rgba(9, 10, 17, .8);
            --docsearch-modal-background: #15172a;
            --docsearch-modal-shadow: inset 1px 1px 0 0 #2c2e40, 0 3px 8px 0 #000309;
            --docsearch-searchbox-background: #090a11;
            --docsearch-searchbox-focus-background: #000;
            --docsearch-hit-color: #bec3c9;
            --docsearch-hit-shadow: none;
            --docsearch-hit-background: #090a11;
            --docsearch-key-gradient: linear-gradient(-26.5deg, #565872, #31355b);
            --docsearch-key-shadow: inset 0 -2px 0 0 #282d55, inset 0 0 1px 1px #51577d, 0 2px 2px 0 rgba(3, 4, 9, .3);
            --docsearch-footer-background: #1e2136;
            --docsearch-footer-shadow: inset 0 1px 0 0 rgba(73, 76, 106, .5), 0 -4px 8px 0 rgba(0, 0, 0, .2);
            --docsearch-muted-color: #7f8497;
        }

        .bd-content h2,
        .bd-content h3,
        .bd-content h4 {
            --bs-heading-color: var(--bs-emphasis-color);
        }

        .bd-gutter {
            --bs-gutter-x: 3rem;
        }

        .bd-title {
            --bs-heading-color: var(--bs-emphasis-color);
            /* font-size: calc(1.425rem + 2.1vw) */
        }

        /* @media (min-width: 1200px) {
            .bd-title {
                font-size: 3rem
            }
        } */

        .bd-content dl>dt,
        .bd-content>.table th,
        .bd-content>.table-responsive .table th {
            color: var(--bs-emphasis-color);
        }

        .bd-navbar {
            padding: .75rem 0;
            /* background-color: transparent; */
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15), inset 0 -1px 0 rgba(255, 255, 255, 0.15);
            /* background-color: #1e293b; */
            background-color: linear-gradient(rgba(var(--bd-violet-rgb), 1), rgba(var(--bd-violet-rgb), 0.95));
        }

        .records td code {
            line-break: anywhere;
        }

        .highlight {
            position: relative;
            padding: 0.75rem 1.5rem;
            margin-bottom: 1rem;
            background-color: var(--bd-pre-bg)
        }

        @media (min-width: 768px) {
            .highlight {
                padding: .75rem 1.25rem;
                border-radius: var(--bs-border-radius)
            }
        }

        .highlight pre {
            padding: .25rem 0 .875rem;
            margin-top: .8125rem;
            margin-right: 1.875rem;
            margin-bottom: 0;
            overflow: overlay;
            white-space: pre;
            background-color: transparent;
            border: 0
        }

        .highlight pre code {
            font-size: inherit;
            color: var(--bs-body-color);
            word-wrap: normal
        }

        .bd-code-snippet {
            margin: 0 -1.5rem 1rem
        }

        .bd-code-snippet .highlight {
            margin-bottom: 0;
            border-top-left-radius: 0;
            border-top-right-radius: 0
        }

        .bd-code-snippet .bd-example {
            margin: 0;
            border: 0
        }

        @media (min-width: 768px) {
            .bd-code-snippet {
                margin-right: 0;
                margin-left: 0;
                border-radius: .375rem
            }
        }

        .search-form {
            border-radius: var(--bs-border-radius);
            align-items: center;
            /* background: var(--docsearch-searchbox-focus-background); */
            border-radius: 4px;
            box-shadow: var(--docsearch-searchbox-shadow);
            display: flex;
            height: var(--docsearch-searchbox-height);
            margin: 0;
            padding: 0 var(--docsearch-spacing);
            position: relative;
            width: 100%;
        }

        .search-magnifier-label {
            align-items: center;
            color: var(--docsearch-highlight-color);
            display: flex;
            justify-content: center;
        }

        .search-magnifier-label svg {
            height: 24px;
            width: 24px;
            stroke-width: 1.6;
        }

        .search-input {
            appearance: none;
            background: transparent;
            border: 0;
            color: var(--docsearch-text-color);
            flex: 1;
            font: inherit;
            font-size: inherit;
            font-size: 1.2em;
            height: 100%;
            outline: none;
            padding: 0 0 0 8px;
            width: 80%;
        }

        .spf-fail {
            color: #ec4848 !important;
        }

        .spf-softfail {
            color: #ecd948 !important;
        }

        /* .spf-neutral {} */

        .spf-pass {
            color: #48ec61 !important;
        }

        /**
        * Tooltip Styles
        */
        /*
        /* Add this attribute to the element that needs a tooltip /
        [data-bs-toggle="tooltip" data-bs-title] {
            position: relative;
            z-index: 2;
            cursor: pointer;
        }

        /* Hide the tooltip content by default /
        [data-bs-toggle="tooltip" data-bs-title]:before,
        [data-bs-toggle="tooltip" data-bs-title]:after {
            visibility: hidden;
            -ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=0)";
            filter: progid: DXImageTransform.Microsoft.Alpha(Opacity=0);
            opacity: 0;
            pointer-events: none;
        }

        /* Position tooltip above the element /
        [data-bs-toggle="tooltip" data-bs-title]:before {
            position: absolute;
            bottom: 150%;
            left: 50%;
            margin-bottom: 5px;
            margin-left: -80px;
            padding: 7px;
            min-width: 160px;
            -webkit-border-radius: 3px;
            -moz-border-radius: 3px;
            border-radius: 3px;
            background-color: #000;
            background-color: hsla(0, 0%, 20%, 0.9);
            color: #fff;
            content: attr(data-bs-toggle="tooltip" data-bs-title);
            text-align: center;
            font-size: 14px;
            line-height: 1.2;
            white-space: pre;
        }

        /* Triangle hack to make tooltip look like a speech bubble /
        [data-bs-toggle="tooltip" data-bs-title]:after {
            position: absolute;
            bottom: 150%;
            left: 50%;
            margin-left: -5px;
            width: 0;
            border-top: 5px solid #000;
            border-top: 5px solid hsla(0, 0%, 20%, 0.9);
            border-right: 5px solid transparent;
            border-left: 5px solid transparent;
            content: " ";
            font-size: 0;
            line-height: 0;
        }

        /* Show tooltip content on hover /
        [data-bs-toggle="tooltip" data-bs-title]:hover:before,
        [data-bs-toggle="tooltip" data-bs-title]:hover:after {
            visibility: visible;
            -ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=100)";
            filter: progid: DXImageTransform.Microsoft.Alpha(Opacity=100);
            opacity: 1;
        } */

        .google-map {
            width: 100%;
            height: 400px;
        }

        .google-map--tall {
            height: 700px;
        }

        .gm-style .gm-style-iw {
            color: #333;
        }

        .gm-style .gm-style-iw strong {
            font-weight: 700;
        }

        .error {
            color: red;
        }
    </style>
</head>

<body>
    <header class="navbar navbar-expand-lg bd-navbar">
        <nav class="container-xxl bd-gutter flex-wrap flex-lg-nowrap">
            <form method="get" id="search" class="search-form" action="">
                <label class="search-magnifier-label" for="search-input" id="search-label"><svg width="20" height="20" class="search-icon" viewBox="0 0 20 20">
                        <path d="M14.386 14.386l4.0877 4.0877-4.0877-4.0877c-2.9418 2.9419-7.7115 2.9419-10.6533 0-2.9419-2.9418-2.9419-7.7115 0-10.6533 2.9418-2.9419 7.7115-2.9419 10.6533 0 2.9419 2.9418 2.9419 7.7115 0 10.6533z" stroke="currentColor" fill="none" fill-rule="evenodd" stroke-linecap="round" stroke-linejoin="round"></path>
                    </svg></label>
                <input id="search-input" class="search-input" placeholder="Search domains" name="q" id="q" value="" type="text">
            </form>
        </nav>
    </header>
    <main class="container-xxl bd-gutter mt-3 my-md-4 bd-content">
        <h1 class="display-1 bd-title mb-5 text-center"><?= $domain ?></h1>

        <nav>
            <ul class="nav nav-pills mb-3 justify-content-center" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="home-tab" data-bs-toggle="tab" data-bs-target="#home-tab-pane" type="button" role="tab" aria-controls="home-tab-pane" aria-selected="true">General</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security-tab-pane" type="button" role="tab" aria-controls="security-tab-pane" aria-selected="false">Security</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="email-tab" data-bs-toggle="tab" data-bs-target="#email-tab-pane" type="button" role="tab" aria-controls="email-tab-pane" aria-selected="false">Email</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="map-tab" data-bs-toggle="tab" data-bs-target="#map-tab-pane" type="button" role="tab" aria-controls="map-tab-pane" aria-selected="false">Map</button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="whois-tab" data-bs-toggle="tab" data-bs-target="#whois-tab-pane" type="button" role="tab" aria-controls="whois-tab-pane" aria-selected="false">WhoIs</button>
                </li>
            </ul>
        </nav>

        <?php
        if (count($errors) > 0) {
            echo '<pre>';
            echo implode('<br>', $errors);
            echo '</pre>';
        }
        ?>

        <div class="tab-content" id="nav-tabContent">
            <section id="home-tab-pane" class="tab-pane fade show active" role="tabpanel" aria-labelledby="home-tab" tabindex="0">
                <div class="row">
                    <div class="col-8">
                        <?php
                        if ($domain_data['expiration'] !== 'Unknown') {
                            $domain_interval = date_diff($date_now, date_create(to_date_format($domain_data['expiration'])));
                            $domain_ttl = $domain_interval ? ' (' . seconds_to_time($domain_interval->format('%a') * 86400) . ')' : '';
                            $domain_expiration_datetime = strtotime($domain_data['expiration']);
                            $domain_expiration =
                                to_date_format($domain_data['expiration']) . ($domain_expiration_datetime < $now ? ' <span class="error">Expired</span>' : '');
                        } else {
                            $domain_interval = $domain_expiration_datetime = $domain_expiration = 'Unknown';
                            $domain_ttl = '';
                        }


                        ?>
                        <h2 class="display-5">General</h2>
                        <dl class="row mb-5">
                            <dt class="col-sm-3">Server IP</dt>
                            <dd class="col-sm-9"><?= $ip ?></dd>

                            <dt class="col-sm-3">Server Location</dt>
                            <dd class="col-sm-9"><?= get_location_address($location) ?></dd>

                            <dt class="col-sm-3">Host</dt>
                            <dd class="col-sm-9"><?= ($arin['customer_name'] ?? 'Unknown Customer Name') . ' (<a href="' . ($arin['customer_link'] ?? '#') . '" target="_blank">' . ($arin['customer_handle'] ?? 'Unknown Customer Handle') . '</a>)' ?></dd>

                            <dt class="col-sm-3">Host Net Blocks</dt>
                            <dd class="col-sm-9">
                                <table>
                                    <?php
                                    // Trying to access array offset on value of type bool on line 1667
                                    if (is_array($arin) === true) {
                                        foreach ($arin['net_block'] as $key => $netblock) {
                                            echo '<tr><td>' . $netblock['start_address'] . '-' . $netblock['end_address'] . '</td><td>(' . $netblock['start_address'] . '/' . $netblock['cidr_length'] . ')</td></tr>';
                                        }
                                    }
                                    ?>
                                </table>
                            </dd>

                            <dt class="col-sm-3">Domain Expiration Date</dt>
                            <dd class="col-sm-9"><?= $domain_expiration . $domain_ttl ?></dd>

                            <dt class="col-sm-3">Domain Contact</dt>
                            <dd class="col-sm-9"><?= $domain_data['contact'] ?></dd>
                        </dl>

                        <dl class="row mb-5">
                            <dt class="col-sm-3">Domain Registrar</dt>
                            <dd class="col-sm-9"><?= $domain_data['registrar'] ?></dd>

                            <dt class="col-sm-3">Name Server Provider</dt>
                            <dd class="col-sm-9"><?php
                                                    $email_host = array();
                                                    foreach ($dns_records['ns'] as $record) {
                                                        $uri = strtolower($record['target']);
                                                        // use unique index so we auto filter duplicates
                                                        if (strpos($uri, 'cloudflare.com') !== false) {
                                                            $email_host['cloudflare'] = 'Cloudflare';
                                                        } elseif (strpos($uri, 'domaincontrol.com') !== false) {
                                                            $email_host['GoDaddy'] = 'GoDaddy';
                                                        } elseif (strpos($uri, 'bluehost.com') !== false) {
                                                            $email_host['bluehost'] = 'BlueHost';
                                                        } elseif (strpos($uri, 'hostgator.com') !== false) {
                                                            $email_host['HostGator'] = 'HostGator';
                                                        } elseif (strpos($uri, 'websitewelcome.com') !== false) {
                                                            $email_host['HostGator'] = 'HostGator';
                                                        } elseif (strpos($uri, 'microsoftonline.com') !== false) {
                                                            $email_host['microsoft'] = 'Microsoft 365';
                                                        } elseif (strpos($uri, 'theplanet.com') !== false) {
                                                            $email_host['softlayer'] = 'SoftLayer';
                                                        } elseif (strpos($uri, 'mediatemple.net') !== false) {
                                                            $email_host['mediatemple'] = 'Media Temple';
                                                        } elseif (strpos($uri, 'dnszone') !== false) {
                                                            $email_host['coursevector'] = 'CourseVector';
                                                        } elseif (strpos($uri, 'nexcess') !== false) {
                                                            $email_host['nexcess'] = 'Nexcess (Liquid Web)';
                                                        } elseif (strpos($uri, 'awsdns') !== false) {
                                                            $email_host['amazon'] = 'AWS Route 53';
                                                        } elseif (strpos($uri, 'registeredsite.com') !== false) {
                                                            $email_host['netsol'] = 'Register.com';
                                                        } elseif (strpos($uri, 'register.com') !== false) {
                                                            $email_host['netsol'] = 'Register.com';
                                                        } elseif (strpos($uri, 'worldnic') !== false) {
                                                            $email_host['netsol'] = 'Network Solutions';
                                                        } elseif (strpos($uri, 'wordpress.com') !== false) {
                                                            $email_host['wordpress'] = 'WordPress.com';
                                                        } elseif (strpos($uri, 'name-services.com') !== false) {
                                                            $email_host['enom'] = 'eNom (Tucows)';
                                                        } elseif (strpos($uri, 'hover.com') !== false) {
                                                            $email_host['tucows'] = 'Tucows';
                                                        } elseif (strpos($uri, 'ui-dns.') !== false) {
                                                            $email_host['1and1'] = '1&1 Internet';
                                                        } elseif (strpos($uri, 'digitalocean.com') !== false) {
                                                            $email_host['digitalocean'] = 'DigitalOcean';
                                                        } elseif (strpos($uri, '.azure-dns.') !== false) {
                                                            $email_host['microsoft'] = 'Microsoft Azure';
                                                        } elseif (strpos($uri, 'squarespacedns.com') !== false) {
                                                            $email_host['squarespace'] = 'Squarespace';
                                                        } elseif (strpos($uri, 'nsone.net') !== false) {
                                                            $email_host['ns1'] = 'NS1.';
                                                        } elseif (strpos($uri, 'sgvps.net') !== false) {
                                                            $email_host['siteground'] = 'SiteGround';
                                                        } elseif (strpos($uri, 'savvis.net') !== false) {
                                                            $email_host['centurylink'] = 'CenturyLink Communications';
                                                        } else {
                                                            $email_host['Unknown/Host'] = 'Unknown/Host';
                                                        }
                                                    }
                                                    echo implode(', ', $email_host);
                                                    ?>
                            </dd>

                            <dt class="col-sm-3">Hosting Provider</dt>
                            <dd class="col-sm-9"><?php
                                                    foreach ($dns_records['a'] as $record) {
                                                        $ip = $record['ip'];
                                                        $ip_info = get_location($ip);
                                                        echo $ip_info ? translate_org($ip_info->org ?? '') : 'API Rate Limit';
                                                        break;
                                                    }
                                                    ?>
                            </dd>

                            <dt class="col-sm-3">Email Provider</dt>
                            <dd class="col-sm-9"><?php
                                                    $email_host = array();
                                                    $email_target = null;
                                                    $is_spam_filter = false;

                                                    foreach ($dns_records['mx'] as $record) {
                                                        $uri = strtolower($record['target']);
                                                        $ip = get_host_by_name($record['target']);
                                                        $email_target = $uri;


                                                        // use unique index so we auto filter duplicates
                                                        if (strpos($uri, 'mx25.net') !== false) {
                                                            $email_host['PostLayer'] = 'PostLayer';
                                                            $is_spam_filter = true;
                                                        } elseif (strpos($uri, 'protection.outlook.com') !== false) {
                                                            $email_host['Office365'] = 'Microsoft 365';
                                                        } elseif (strpos($uri, 'mail.eo.outlook.com') !== false) {
                                                            $email_host['Office365'] = 'Microsoft 365';
                                                        } elseif (strpos($uri, 'googlemail.com') !== false) {
                                                            $email_host['GMail'] = 'GMail';
                                                        } elseif (strpos($uri, 'aspmx.l.google.com') !== false) {
                                                            $email_host['GMail'] = 'GMail';
                                                        } elseif (strpos($uri, 'emailsrvr.com') !== false) {
                                                            $email_host['Rackspace'] = 'Rackspace Email Hosting';
                                                        } elseif (strpos($uri, 'ess.barracudanetworks.com') !== false) {
                                                            $email_host['Barracuda'] = 'Barracuda Essentials for Email Security';
                                                            $is_spam_filter = true;
                                                        } elseif (strpos($uri, 'hostedemail.com') !== false) {
                                                            $email_host['OpenSRS'] = 'Tucows OpenSRS Hosted Email';
                                                        } elseif (strpos($uri, 'secureserver.net') !== false) {
                                                            $email_host['GoDaddy'] = 'GoDaddy';
                                                        } elseif (strpos($uri, 'mailanyone.net') !== false) {
                                                            $email_host['fusemail'] = 'FuseMail';
                                                            $is_spam_filter = true;
                                                        } elseif (strpos($uri, 'hes.trendmicro.com') !== false) {
                                                            $email_host['trendmicro'] = 'TrendMicro Hosted Email Security';
                                                            $is_spam_filter = true;
                                                        } elseif (strpos($uri, 'ppe-hosted.com') !== false) {
                                                            $email_host['proofpoint'] = 'Proofpoint Essentials';
                                                            $is_spam_filter = true;
                                                        } elseif (strpos($uri, 'comcast.net') !== false) {
                                                            $email_host['comcast'] = 'Comcast';
                                                        } elseif (strpos($uri, 'sourcedns') !== false) {
                                                            $email_host['sourcedns'] = 'Liquid Web';
                                                        } elseif (strpos($uri, 'netsolmail.net') !== false) {
                                                            $email_host['netsol'] = 'Network Solutions Hosted Email';
                                                        } elseif (strpos($uri, 'zoho.com') !== false) {
                                                            $email_host['zoho'] = 'Zoho';
                                                        } elseif (strpos($uri, '1and1.com') !== false) {
                                                            $email_host['1and1'] = '1&1 Internet';
                                                        } elseif (strpos($uri, 'mxthunder.') !== false) {
                                                            $email_host['SpamHero'] = 'SpamHero';
                                                            $is_spam_filter = true;
                                                        } elseif (strpos($uri, 'hostingplatform.com') !== false) {
                                                            $email_host['netsol'] = 'Network Solutions Hosted Email';
                                                        } elseif (strpos($ip, '216.55') !== false) {
                                                            // 216.55.101.xx
                                                            // 216.55.102.xx
                                                            // 216.55.103.xx
                                                            $email_host['SpamWall'] = 'SpamWall';
                                                            $is_spam_filter = true;
                                                        } elseif (strpos($uri, 'reflexion.net') !== false) {
                                                            $email_host['reflexion'] = 'Reflexion Email Security';
                                                            $is_spam_filter = true;
                                                        } elseif (strpos($uri, 'mailspamprotection.com') !== false) {
                                                            $email_host['siteground'] = 'SiteGround';
                                                            $is_spam_filter = true;
                                                        } else {
                                                            $email_host['Unknown/Self'] = 'Unknown/Self';
                                                        }
                                                    }

                                                    echo implode(', ', $email_host);

                                                    // If behind a mail filter, try to find the origin
                                                    if ($is_spam_filter) {
                                                        $email_host = array();
                                                        foreach ($dns_records['a'] as $record) {
                                                            $uri = strtolower($record['host']);
                                                            $ip = $record['ip'];
                                                            $ip_info = get_location($ip);
                                                            //echo $uri . ' ' . $email_target;
                                                            if ($uri == $email_target) continue;

                                                            // use unique index so we auto filter duplicates
                                                            if (preg_match("/^mail\./i", $uri)) {
                                                                //echo $uri . ' a <br>';
                                                                $email_host['mail'] = $ip_info ? translate_org($ip_info->org ?? '') : 'API Rate Limit';
                                                            }
                                                            // override mail.
                                                            if (preg_match("/^autodiscover\./i", $uri)) {
                                                                //echo $uri . ' a <br>';
                                                                $email_host['mail'] = $ip_info ? translate_org($ip_info->org ?? '') : 'API Rate Limit';
                                                            }
                                                        }
                                                        foreach ($dns_records['cname'] as $record) {
                                                            $uri = strtolower($record['host']);

                                                            if ($uri == $email_target) continue;
                                                            $ip = get_host_by_name($record['target']);
                                                            $ip_info = get_location($ip);

                                                            // use unique index so we auto filter duplicates
                                                            if (preg_match("/^mail\./i", $uri)) {
                                                                //echo $uri . ' cname<br>';
                                                                if (strpos($record['target'], 'mail.office365.com') !== false) {
                                                                    $email_host['mail'] = 'Microsoft 365';
                                                                } else {
                                                                    $email_host['mail'] = $ip_info ? translate_org($ip_info->org ?? '') : 'API Rate Limit';
                                                                }
                                                            }

                                                            // override mail.
                                                            if (preg_match("/^autodiscover\./i", $uri)) {
                                                                //echo $uri . ' cname<br>';
                                                                if (strpos($record['target'], 'autodiscover.outlook.com') !== false) {
                                                                    $email_host['mail'] = 'Microsoft 365';
                                                                } else {
                                                                    $email_host['mail'] = $ip_info ? translate_org($ip_info->org ?? '') : 'API Rate Limit';
                                                                }
                                                            }
                                                        }
                                                        if (count($email_host) > 0) echo ' (via ' . implode(' ', $email_host) . ')';
                                                    }
                                                    ?>
                            </dd>

                            <dt class="col-sm-3">Hosting Provider</dt>
                            <dd class="col-sm-9"><?php
                                                    foreach ($dns_records['a'] as $record) {
                                                        $ip = $record['ip'];
                                                        $ip_info = get_location($ip);
                                                        echo $ip_info ? translate_org($ip_info->org ?? '') : 'API Rate Limit';
                                                        break;
                                                    }
                                                    ?>
                            </dd>
                        </dl>

                        <?php
                        if (isset($headers["Server"]) || isset($headers["X-Powered-By"]) || isset($headers["X-Amz-Cf-Id"])) {
                            // error_log(print_r($headers, true));
                            echo '<dl class="row">';
                            if (isset($headers["Server"])) {
                                echo '<dt class="col-sm-3">Server Software</dt>';
                                echo '<dd class="col-sm-9">' . val_to_string($headers["Server"]) . "</dd>";
                            }
                            if (isset($headers["X-Powered-By"])) {
                                echo '<dt class="col-sm-3">Powered By</dt>';
                                echo "<dd class=\"col-sm-9\">{$headers["X-Powered-By"]}</dd>";
                            }
                            if (isset($headers["X-Amz-Cf-Id"])) {
                                echo '<dt class="col-sm-3">Uses CloudFront</dt>';
                                echo '<dd class="col-sm-9">True</dd>';
                            }
                            echo '</dl>';
                        } ?>
                    </div>
                    <div class="col-4">
                        <div id="map_single" class="google-map" style="height:100%;"></div>
                    </div>
                </div>
                <div class="row">
                    <div class="col">
                        <h2 class="display-5">DNS</h2>
                        <table class="table table-dark table-striped records">
                            <?php
                            function getZoneHost($domain, $host)
                            {
                                if ($domain === $host) return "{$domain}.";
                                return str_replace(".{$domain}", '', $host);
                            }
                            $now = date("Y-m-d H:i:s");
                            $zoneExportRaw = "; Domain: {$domain}
; Exported (y-m-d hh:mm:ss): {$now}
;
; This file is intended for use for informational and archival
; purposes ONLY and MUST be edited before use on a production
; DNS server.
;
; In particular, you must update the SOA record with the correct
; authoritative name server and contact e-mail address information,
; and add the correct NS records for the name servers which will
; be authoritative for this domain.
;
; For further information, please consult the BIND documentation
; located on the following website:
;
; http://www.isc.org/
;
; And RFC 1035:
;
; http://www.ietf.org/rfc/rfc1035.txt
;
; Please note that we do NOT offer technical support for any use
; of this zone data, the BIND name server, or any other third-
; party DNS software.
;
; Use at your own risk.
\n";

                            /*
							array(11) {
								["host"]=> string(18) "birdkingdom.stream"
								["class"]=> string(2) "IN"
								["ttl"]=> int(7146)
								["type"]=> string(3) "SOA"
								["mname"]=> string(16) "ns4.alpnames.com"
								["rname"]=> string(23) "domainsserv31.gmail.com"
								["serial"]=> int(2017031112)
								["refresh"]=> int(7200)
								["retry"]=> int(7200)
								["expire"]=> int(172800)
								["minimum-ttl"]=> int(38400)
							}
							*/
                            $zoneExportRaw .= "; SOA Record\n";
                            foreach ($dns_records['soa'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['mname']}.\t{$record['rname']}.\t(\n\t\t\t\t\t\t{$record['serial']} ;Serial Number\n\t\t\t\t\t\t{$record['refresh']} ;refresh\n\t\t\t\t\t\t{$record['retry']} ;retry\n\t\t\t\t\t\t{$record['expire']} ;expire\n\t\t\t\t\t\t{$record['minimum-ttl']}\t)\n";
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Start of [a zone of] authority"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Primary nameserver"><?php echo $record['mname']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Hostmaster E-mail address"><?php echo $record['rname']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Serial #"><?php echo $record['serial']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Refresh - <?php echo seconds_to_time($record['refresh']); ?>"><?php echo $record['refresh']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Retry - <?php echo seconds_to_time($record['retry']); ?>"><?php echo $record['retry']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Expire - <?php echo seconds_to_time($record['expire']); ?>"><?php echo $record['expire']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Default TTL - <?php echo seconds_to_time($record['minimum-ttl']); ?>"><?php echo $record['minimum-ttl']; ?></td>
                                </tr>
                            <?php
                            }
                            $zoneExportRaw .= "\n";

                            /*
							array(5) {
							  ["host"]=> "smartmgmt.com"
							  ["class"]=> "IN"
							  ["ttl"]=> int(3418)
							  ["type"]=> "NS"
							  ["target"]=> "ns10.domaincontrol.com"
							}
							*/
                            if (count($dns_records['ns']) > 0) $zoneExportRaw .= "; NS Record\n";
                            foreach ($dns_records['ns'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['target']}.\n";

                                $ns = $record['target'];
                                $ip = get_host_by_name($ns);
                                $ip_info = get_location($ip);
                                if ($ip_info) {
                                    if (isset($server_locations[$ip_info->loc])) {
                                        $server_locations[$ip_info->loc][] = array('type' => 'Name Server', 'info' => $ip_info);
                                    } else {
                                        $server_locations[$ip_info->loc] = array(array('type' => 'Name Server', 'info' => $ip_info));
                                    }
                                }
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Namer Server"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $ip; ?>&#10;<?php echo ($ip_info ? $ip_info->org : ''); ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $record['target']; ?></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['ns']) > 0) $zoneExportRaw .= "\n";

                            /*
							array(5) {
							  ["host"]=> "smartmgmt.com"
							  ["class"]=> "IN"
							  ["ttl"]=> int(3095)
							  ["type"]=>  "A"
							  ["ip"]=> "72.52.145.252"
							}
							*/
                            if (count($dns_records['a']) > 0) $zoneExportRaw .= "; A Record\n";
                            foreach ($dns_records['a'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['ip']}\n";

                                $ip = $record['ip'];
                                $ip_info = get_location($ip);
                                if ($ip_info) {
                                    if (isset($server_locations[$ip_info->loc])) {
                                        $server_locations[$ip_info->loc][] = array('type' => 'Web Server', 'info' => $ip_info);
                                    } else {
                                        $server_locations[$ip_info->loc] = array(array('type' => 'Web Server', 'info' => $ip_info));
                                    }
                                }
                                $cname = '';
                                // https://superuser.com/questions/1762667/dns-why-does-the-server-return-a-cname-record-when-asked-for-an-mx
                                if (isset($record['cname'])) $cname = " <abbr title='CNAME'>&rarr; {$record['cname']}</abbr>";
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host'] . $cname; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Address"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $record['host']; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $ip; ?></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['a']) > 0) $zoneExportRaw .= "\n";

                            if (count($dns_records['aaaa']) > 0) $zoneExportRaw .= "; AAAA Record\n";
                            foreach ($dns_records['aaaa'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['ipv6']}\n";

                                $ip = $record['ipv6'];
                                $ip_info = get_location($ip);
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="IPv6 Address"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $record['host']; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $ip; ?></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['aaaa']) > 0) $zoneExportRaw .= "\n";

                            /*
							 array(5) {
								'host' => string(14) "www.cweiske.de"
								'class' => string(2) "IN"
								'ttl' => int(86400)
								'type' => string(5) "CNAME"
								'target' => string(10) "cweiske.de"
							  }
							*/
                            if (count($dns_records['cname']) > 0) $zoneExportRaw .= "; CNAME Record\n";
                            foreach ($dns_records['cname'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['target']}.\n";

                                $ip = get_host_by_name($record['target']);
                                $ip_info = get_location($ip);
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Canonical Name"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $record['target']; ?></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['cname']) > 0) $zoneExportRaw .= "\n";

                            if (count($dns_records['mx']) > 0) $zoneExportRaw .= "; MX Record\n";
                            foreach ($dns_records['mx'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['pri']}\t{$record['target']}.\n";

                                $ip = get_host_by_name($record['target']);
                                $ip_info = get_location($ip);
                                if ($ip_info) {
                                    if (isset($server_locations[$ip_info->loc])) {
                                        $server_locations[$ip_info->loc][] = array('type' => 'EMail Server', 'info' => $ip_info);
                                    } else {
                                        $server_locations[$ip_info->loc] = array(array('type' => 'EMail Server', 'info' => $ip_info));
                                    }
                                }
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Mail Exchange"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Priority"><?php echo $record['pri']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="6"><?php echo $record['target']; ?></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['mx']) > 0) $zoneExportRaw .= "\n";

                            if (count($dns_records['txt']) > 0) $zoneExportRaw .= "; TXT Record\n";
                            foreach ($dns_records['txt'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t\"{$record['txt']}\"\n";

                                $cname = '';
                                // https://superuser.com/questions/1762667/dns-why-does-the-server-return-a-cname-record-when-asked-for-an-mx
                                if (isset($record['cname'])) $cname = " <abbr title='CNAME'>&rarr; {$record['cname']}</abbr>";
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?= $record['host'] . $cname ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Text"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Value" colspan="7"><code><?php echo htmlspecialchars($record['txt']); ?></code></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['txt']) > 0) $zoneExportRaw .= "\n";

                            if (count($dns_records['dmarc']) > 0) $zoneExportRaw .= "; DMARC Record\n";
                            foreach ($dns_records['dmarc'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t\"{$record['txt']}\"\n";
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Text"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Value" colspan="7"><code><?php echo $record['txt']; ?></code></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['dmarc']) > 0) $zoneExportRaw .= "\n";

                            /*foreach( $dns_records['hinfo'] as $record ) {
								?>
								<tr>
									<td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
									<td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
									<td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time( $record['ttl'] ); ?>"><?php echo $record['ttl']; ?></td>
									<td data-bs-toggle="tooltip" data-bs-title="Host Information"><?php echo $record['type']; ?></td>
									<td data-bs-toggle="tooltip" data-bs-title="Hardware"><?php echo $record['hardware']; ?></td>
									<td data-bs-toggle="tooltip" data-bs-title="OS" colspan="6"><?php echo $record['os']; ?></td>
								</tr>
								<?php
							}*/

                            if (count($dns_records['srv']) > 0) $zoneExportRaw .= "; SRV Record\n";
                            foreach ($dns_records['srv'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['pri']}\t{$record['weight']}\t{$record['port']}\t{$record['target']}.\n";
                                $ip = get_host_by_name($record['target']);
                                $ip_info = get_location($ip);
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Service Location"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Priority"><?php echo $record['pri']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Weight"><?php echo $record['weight']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Port"><?php echo $record['port']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="4"><?php echo $record['target']; ?></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['srv']) > 0) $zoneExportRaw .= "\n";

                            if (count($dns_records['ptr']) > 0) $zoneExportRaw .= "; PTR Record\n";
                            foreach ($dns_records['ptr'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['txt']}\n";
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Pointer"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Value" colspan="7"><?php echo $record['txt']; ?></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['ptr']) > 0) $zoneExportRaw .= "\n";

                            if (count($dns_records['naptr']) > 0) $zoneExportRaw .= "; NAPTR Record\n";
                            foreach ($dns_records['naptr'] as $record) {
                                $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['order']}\t{$record['pref']}\t{$record['flags']}\t{$record['services']}\t{$record['regex']}\t{$record['replacement']}\n";
                            ?>
                                <tr>
                                    <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Naming Authority Pointer"><?php echo $record['type']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Order"><?php echo $record['order']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Preference"><?php echo $record['pref']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Flags"><?php echo $record['flags']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Service"><?php echo $record['services']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Regexp"><?php echo $record['regex']; ?></td>
                                    <td data-bs-toggle="tooltip" data-bs-title="Replacement"><?php echo $record['replacement']; ?></td>
                                </tr>
                            <?php
                            }
                            if (count($dns_records['naptr']) > 0) $zoneExportRaw .= "\n";
                            ?>
                        </table>
                        <button class="btn btn-primary download-dns">Download Zone File</button>
                    </div>
                </div>
            </section>

            <section id="security-tab-pane" class="tab-pane fade" role="tabpanel" aria-labelledby="security-tab" tabindex="0">

                <h2 class="display-5">DNS</h2>
                <table class="table table-dark table-striped">
                    <tr>
                        <th width=250>DNSSEC</th>
                        <td><?php echo $domain_data['dnssec']; ?></td>
                    </tr>
                </table>

                <h2 class="display-5">Headers</h2>
                <table class="table table-dark table-striped">
                    <?php
                    $hasAnyHeaders = false;
                    if (isset($headers["Content-Security-Policy"])) {
                        $hasAnyHeaders = true;
                        echo "<tr><th width=250>Content Security Policy (CSP)</th><td ><code>" . val_to_string($headers["Content-Security-Policy"]) . "</code></td></tr>";
                    }
                    if (isset($headers["Content-Security-Policy-Report-Only"])) {
                        $hasAnyHeaders = true;
                        echo "<tr><th width=250>Content Security Policy (CSP) Report Only</th><td ><code>" . val_to_string($headers["Content-Security-Policy-Report-Only"]) . "</code></td></tr>";
                    }
                    if (isset($headers["Public-Key-Pins"])) {
                        $hasAnyHeaders = true;
                        echo "<tr><th width=250>Public Key Pins (HPKP)</th><td ><code>" . val_to_string($headers["Public-Key-Pins"]) . "</code></td></tr>";
                    }
                    if (isset($headers["Strict-Transport-Security"])) {
                        $hasAnyHeaders = true;
                        echo "<tr><th width=250>Strict Transport Security (HSTS)</th><td ><code>" . val_to_string($headers["Strict-Transport-Security"]) . "</code></td></tr>";
                    }
                    if (isset($headers["X-Frame-Options"])) {
                        $hasAnyHeaders = true;
                        echo "<tr><th width=250>Frame Options</th><td ><code>" . val_to_string($headers["X-Frame-Options"]) . "</code></td></tr>";
                    }
                    if (isset($headers["X-Xss-Protection"])) {
                        $hasAnyHeaders = true;
                        echo "<tr><th width=250>XSS Protection</th><td ><code>" . val_to_string($headers["X-Xss-Protection"]) . "</code></td></tr>";
                    }
                    if (isset($headers["X-Content-Type-Options"])) {
                        $hasAnyHeaders = true;
                        echo "<tr><th width=250>Content Type Options</th><td ><code>" . val_to_string($headers["X-Content-Type-Options"]) . "</code></td></tr>";
                    }
                    if (!$hasAnyHeaders) {
                        echo "<tr><th width=250></th><td>No related headers found</td></tr>";
                    }
                    ?>
                </table>

                <h2 class="display-5">SSL Certificate</h2>
                <?php

                if ($ssl) {
                    /* CN=mariani.life
C=US, ST=TX, L=Houston, O=cPanel, Inc., CN=cPanel, Inc. Certification Authority
85a9a991b9ff002277b1c017c6c884e39267bfe9d7b39575d6e923b68bae6453
Trusted Leaf Certificate
parsed.names: mariani.life
parsed.extensions.subject_alt_name.dns_names: mariani.life*/
                    $cert = openssl_x509_parse($ssl);
                    $pub_key = openssl_pkey_get_public($ssl);
                    $keyData = openssl_pkey_get_details($pub_key);
                    $cert_interval = date_diff($date_now, date_create(gmdate("Y-m-d", $cert['validTo_time_t'])));
                    $cert_ttl = seconds_to_time($cert_interval->format('%a') * 86400);

                    //https://github.com/Wikinaut/MySimpleCertificateViewer/blob/master/index.php
                    // Decode the certificate to get fingerprints.
                    $cert_raw = '';
                    openssl_x509_export($ssl, $cert_raw);
                    $cleanedCert = preg_replace('/\-+(BEGIN|END) CERTIFICATE\-+/', '', $cert_raw);
                    $cleanedCert = str_replace(array("\n\r", "\n", "\r"), '', trim($cleanedCert));
                    $decCert = base64_decode($cleanedCert);
                    $sha1_fingerprint = sha1($decCert);
                    $md5_fingerprint = md5($decCert);
                    $sha256_fingerprint = hash('sha256', $decCert);

                    $alt_names = explode(', ', $cert['extensions']['subjectAltName']);
                    function strip_dns($name)
                    {
                        return str_replace('DNS:', '', $name);
                    }
                    $alt_names = array_map('strip_dns', $alt_names);

                    function addColonSeparators($str)
                    {
                        $ret = "";
                        for ($i = 0; $i < strlen($str); $i++) {
                            $ret .= substr($str, $i, 1) . (($i % 2 == 1) ? ":" : "");
                        }
                        return strtoupper(rtrim($ret, ":"));
                    }

                    function isHex(string $str): bool
                    {
                        if (str_starts_with(strtolower($str), '0x')) {
                            $str = substr($str, 2);
                        }

                        return ctype_xdigit($str);
                    }

                    // http://www.zedwood.com/article/php-parse-x509certificate
                    //src: http://php.net/manual/en/ref.bc.php
                    function bcdechex($dec)
                    {
                        // PHP 7
                        // https://www.designcise.com/web/tutorial/how-to-check-if-string-is-a-hexadecimal-value-in-php
                        if (isHex($dec)) {
                            if (str_starts_with(strtolower($dec), '0x')) {
                                $dec = substr($dec, 2);
                            }
                            return $dec;
                        }

                        $hex = '';
                        do {
                            $last = bcmod($dec, 16);
                            $hex = dechex($last) . $hex;
                            $dec = bcdiv(bcsub($dec, $last), 16);
                        } while ($dec > 0);

                        // Make sure it's an even length
                        if (strlen($hex) % 2 !== 0) $hex = '0' . $hex;
                        return $hex;
                    }
                ?>

                    <h3>Issued To</h3>
                    <table class="table table-dark table-striped">
                        <tr>
                            <th width=250>Common Name (CN)</th>
                            <td><?php echo $cert['subject']['CN']; ?></td>
                        </tr>
                        <tr>
                            <th>Alt Name(s)</th>
                            <td><?php echo implode('<br/>', $alt_names); ?></td>
                        </tr>
                        <tr>
                            <th>Organization (O)</th>
                            <td><?php echo isset($cert['subject']['O']) ? val_to_string($cert['subject']['O']) : '&lt;Not Part Of Certificate&gt;'; ?></td>
                        </tr>
                        <tr>
                            <th>Organizational Unit (OU)</th>
                            <td><?php echo isset($cert['subject']['OU']) ? val_to_string($cert['subject']['OU']) : '&lt;Not Part Of Certificate&gt;'; ?></td>
                        </tr>
                        <tr>
                            <th>Serial Number</th>
                            <td><?php echo addColonSeparators(bcdechex($cert['serialNumber'])); ?></td>
                            <!-- <td><?php echo $cert['serialNumber']; ?></td> -->
                        </tr>
                    </table>

                    <h3>Issued By</h3>
                    <table class="table table-dark table-striped">
                        <tr>
                            <th width=250>Common Name (CN)</th>
                            <td><?php echo $cert['issuer']['CN']; ?></td>
                        </tr>
                        <tr>
                            <th>Organization (O)</th>
                            <td><?php echo isset($cert['issuer']['O']) ? val_to_string($cert['issuer']['O']) : '&lt;Not Part Of Certificate&gt;'; ?></td>
                        </tr>
                        <tr>
                            <th>Organizational Unit (OU)</th>
                            <td><?php echo isset($cert['issuer']['OU']) ? val_to_string($cert['issuer']['OU']) : '&lt;Not Part Of Certificate&gt;'; ?></td>
                        </tr>
                    </table>

                    <h3>Period of Validity</h3>
                    <table class="table table-dark table-striped">
                        <tr>
                            <th width=250>Begins On</th>
                            <td><?php echo gmdate("l, F d, Y", $cert['validFrom_time_t']); ?></td>
                        </tr>
                        <tr>
                            <th>Expires On</th>
                            <td><?php echo gmdate("l, F d, Y", $cert['validTo_time_t']); ?></td>
                        </tr>
                        <tr>
                            <th>Expires in</th>
                            <td><?php echo $cert_ttl; ?></td>
                        </tr>
                    </table>

                    <h3>Details</h3>
                    <table class="table table-dark table-striped">
                        <tr>
                            <th width=250>SHA-256 Fingerprint</th>
                            <td><?php echo addColonSeparators($sha256_fingerprint); ?></td>
                        </tr>
                        <tr>
                            <th>SHA1 Fingerprint</th>
                            <td><?php echo addColonSeparators($sha1_fingerprint); ?></td>
                        </tr>
                        <tr>
                            <th>MD5 Fingerprint</th>
                            <td><?php echo addColonSeparators($md5_fingerprint); ?></td>
                        </tr>
                        <tr>
                            <th>Key Length (Bits)</th>
                            <td><?php echo $keyData['bits']; ?></td>
                        </tr>
                        <tr>
                            <th>Signature Algorithm</th>
                            <td><?php echo $cert['signatureTypeSN']; ?></td>
                        </tr>
                        <tr>
                            <th>Public Key</th>
                            <td>
                                <div class="bd-code-snippet">
                                    <div class="highlight">
                                        <pre><?= $keyData['key'] ?></pre>
                                    </div>
                                </div>
                            </td>
                        </tr>
                        <tr>
                            <th>Certificate</th>
                            <td>
                                <div class="bd-code-snippet">
                                    <div class="highlight">
                                        <pre><?= $cert_raw ?></pre>
                                    </div>
                                </div>
                            </td>
                        </tr>
                    </table>
                <?php
                } else {
                    echo '<p>No SSL/TLS certificate found</p>';
                }
                ?>
            </section>

            <section id="email-tab-pane" class="tab-pane fade" role="tabpanel" aria-labelledby="email-tab" tabindex="0">
                <h2 class="display-5"><abbr title="Sender Policy Framework">SPF</abbr> Records</h2>
                <?php
                if ($spf_records) {
                    $count = 1;
                ?>
                    <table class="table table-dark table-striped records">
                        <thead>
                            <tr>
                                <th>Action</th>
                                <th>Mechanism/Address</th>
                                <th>Host/IP/Value</th>
                                <th>Location</th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php
                        foreach ($spf_records as $spf) {
                            write_spf_table($domain, $ip, $location, $spf, 'pass');
                            write_spf_table($domain, $ip, $location, $spf, 'neutral');
                            write_spf_table($domain, $ip, $location, $spf, 'softfail');
                            write_spf_table($domain, $ip, $location, $spf, 'fail');
                            $count++;
                        }
                        echo '</tbody></table>';
                    } else {
                        echo '<p>None</p>';
                    }
                        ?>

                        <h2 class="display-5"><abbr title="DomainKeys Identified Mail">DKIM</abbr> Records</h2>
                        <?php
                        // https://protodave.com/tools/dkim-key-checker/
                        if ($dkim_records) {
                            echo "<p><em>Checks selectors: 'default' (cPanel), 'x' (MXRoute), 'smtp' (Mailgun), 'hs1, hs2' (HubSpot), 's1, s2, m1, smtpapi' (SendGrid), 'k1, k2, k3' (MailChimp), 'google, ga1' (Google), 'cm' (Campaign Monitor), 'selector1' & 'selector2' (Microsoft 365), 'turbo-smtp' (TurboSMTP)</em></p>";
                            echo '<table class="table table-dark table-striped">';
                            foreach ($dkim_records as $dkim) {
                                $alert = ($dkim['key_bits'] < 1024) ? ' INSECURE (<1024)' : '';
                                if (isset($dkim['cname'])) $cname = " <abbr title='CNAME'>&rarr; {$dkim['cname']}</abbr>";
                                echo "<tr><th>Selector</th><td>{$dkim['host']}{$cname}</td></tr>";
                        ?>
                                <tr>
                                    <th width="275px;">Key Length (Bits)</th>
                                    <td><?= $dkim['key_bits'] . $alert ?></td>
                                </tr>
                                <?php

                                if (isset($dkim['v'])) echo "<tr><th>Version</th><td>{$dkim['v']}</td></tr>";
                                if (isset($dkim['g'])) echo "<tr><th>Key Granularity</th><td>{$dkim['g']}</td></tr>";
                                if (isset($dkim['h'])) echo "<tr><th>Hash Algorithm</th><td>{$dkim['h']}</td></tr>";
                                if (isset($dkim['k'])) echo "<tr><th>Key Type</th><td>" . strtoupper($dkim['k']) . "</td></tr>";
                                if (isset($dkim['n'])) echo "<tr><th>Notes</th><td>{$dkim['n']}</td></tr>";
                                //if (isset($dkim['p'])) echo "<tr><th>Public Key Data</th><td>{$dkim['p']}</td></tr>";
                                if (isset($dkim['s'])) echo "<tr><th>Service Type</th><td>{$dkim['s']}</td></tr>";
                                if (isset($dkim['t'])) {
                                    // https://www.rfc-editor.org/rfc/rfc6376.html#section-3.6.1
                                    $flags = explode(';', $dkim['t']);
                                    $flagsLabelArray = [];
                                    foreach ($flags as $flag) {
                                        $explanation = '';
                                        $flag = strtolower($flag);
                                        if ($flag === 's') $explanation = "Any DKIM-Signature header fields using the 'i=' tag MUST have the same domain value on the right-hand side of the '@' in the 'i=' tag and the value of the 'd=' tag.  That is, the 'i=' domain MUST NOT be a subdomain of 'd='. Use of this flag is RECOMMENDED unless subdomaining is required.";
                                        if ($flag === 'y') $explanation = "This domain is testing DKIM. Verifiers MUST NOT treat messages
                                from Signers in testing mode differently from unsigned email, even should the signature fail to verify. Verifiers MAY wish to track testing mode results to assist the Signer.";
                                        $flagsLabelArray[] = "<abbr title=\"{$explanation}\">{$flag}</abbr> ";
                                    }
                                    $flagsLabel = implode(' ', $flagsLabelArray);
                                    echo "<tr><th>Flags</th><td>{$flagsLabel}</td></tr>";
                                }
                                ?>
                                <tr>
                                    <th>Public Key</th>
                                    <td>
                                        <div class="bd-code-snippet">
                                            <div class="highlight">
                                                <pre><?= $dkim['public_key'] . $alert ?></pre>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                                <tr>
                                    <th>Raw</th>
                                    <td>
                                        <div class="bd-code-snippet">
                                            <div class="highlight">
                                                <pre style="max-width: 100%;word-break: break-all;white-space: break-spaces;"><?= $dkim['raw']['txt'] ?></pre>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                        <?php
                            }
                            echo '</table>';
                        } else {
                            echo '<p>None</p>';
                        }
                        ?>

                        <h2 class="display-5"><abbr title="Domain-based Message Authentication, Reporting & Conformance">DMARC</abbr> Records</h2>
                        <?php
                        // https://protodave.com/tools/dkim-key-checker/
                        if ($dmarc_records) {
                            echo '<table class="table table-dark table-striped">';
                            foreach ($dmarc_records as $dmarc) {
                                if (isset($dmarc['v'])) echo "<tr><th width=\"275px;\">Version</th><td>{$dmarc['v']}</td></tr>";
                                if (isset($dmarc['pct'])) echo "<tr><th>Messages subject to filtering</th><td>{$dmarc['pct']}%</td></tr>";
                                if (isset($dmarc['rf'])) echo "<tr><th>Failure Reports</th><td>{$dmarc['rf']}</td></tr>";
                                if (isset($dmarc['ri'])) echo "<tr><th>Interval between Aggregate Reports</th><td>{$dmarc['ri']} seconds</td></tr>";
                                if (isset($dmarc['ruf'])) echo "<tr><th>Send forensic reports to</th><td>{$dmarc['ruf']}</td></tr>";
                                if (isset($dmarc['rua'])) echo "<tr><th>Send aggregate reports to</th><td>{$dmarc['rua']}</td></tr>";
                                if (isset($dmarc['p'])) echo "<tr><th>Policy for domain</th><td>{$dmarc['p']}</td></tr>";
                                if (isset($dmarc['sp'])) echo "<tr><th>Policy for subdomains</th><td>{$dmarc['sp']}</td></tr>";
                                if (isset($dmarc['adkim'])) echo "<tr><th>Alignment mode for DKIM</th><td>{$dmarc['adkim']}</td></tr>";
                                if (isset($dmarc['aspf'])) echo "<tr><th>Alignment mode for SPF</th><td>{$dmarc['aspf']}</td></tr>";
                            }
                            echo '</table>';
                        } else {
                            echo '<p>None</p>';
                        }
                        ?>
            </section>

            <section id="map-tab-pane" class="tab-pane fade" role="tabpanel" aria-labelledby="map-tab" tabindex="0">
                <div id="map_all" class="google-map google-map--tall"></div>
            </section>

            <section id="whois-tab-pane" class="tab-pane fade" role="tabpanel" aria-labelledby="map-tab" tabindex="0">
                <div class="bd-code-snippet">
                    <div class="highlight">
                        <pre><?= $whois ?></pre>
                    </div>
                </div>
            </section>
        </div>
    </main>
    <footer class="bd-footer py-2 py-md-3 mt-5 bg-body-tertiary">
        <div class="container py-2 py-md-3 px-4 px-md-3 text-body-secondary text-center">
            <?php
            /*
			<h5>IP Cache</h5>
			<pre><?php var_dump($ip_cache); ?></pre>
			<h5>Host Cache</h5>
			<pre><?php var_dump($host_cache); ?></pre>
			<h5>DNS Cache</h5>
			<pre><?php var_dump($dns_cache); ?></pre>
			*/
            ?>
            <small>IP Location provided by: <a href="https://tools.keycdn.com/geo">KeyCDN</a> <?= "({$keycdn_count} queries)" ?> | <a href="https://ipinfo.io/">ipinfo.io</a> <?= "({$ipinfo_count} queries)" ?> | <a href="https://ip-api.com/">ip-api</a> <?= "({$ipapi_count} queries)" ?></small><br>
            <small><a href="https://www.arin.net/">ARIN</a> <?= "({$arin_count} queries)" ?> | <a href="https://www.php.net/manual/en/function.gethostbyaddr.php">DNS</a> <?= "({$dns_count} queries)" ?></small>
        </div>
    </footer>

    <script>
        <?php
        $zoneExport = [
            'zone' => $domain,
            'text_b64' => base64_encode($zoneExportRaw)
        ];
        ?>
        const zoneFile = JSON.parse('<?= JSON_encode($zoneExport) ?>');
    </script>
    <script>
        let map, mapAll, host;

        function exportToZone(filename, data) {
            const blob = new Blob([data], {
                type: 'text/plain;charset=utf-8;',
            });
            if (navigator.msSaveBlob) {
                // IE 10+
                navigator.msSaveBlob(blob, filename);
            } else {
                const link = document.createElement('a');
                if (link.download !== undefined) {
                    // feature detection
                    // Browsers that support HTML5 download attribute
                    const url = URL.createObjectURL(blob);
                    link.setAttribute('href', url);
                    link.setAttribute('download', filename);
                    link.style.visibility = 'hidden';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                }
            }
        }

        function initMapAll() {
            const servers = [<?php
                                $js_servers = array();
                                // error_log(print_r($server_locations, true));
                                foreach ($server_locations as $location => $items) {
                                    $geoCoord = explode(',', $location);
                                    $title = array();
                                    $content = array();
                                    foreach ($items as $server) {
                                        $content[] = '<strong>' . $server['info']->org . '</strong> - <em>' . $server['type'] . '</em><br><strong>Host Name:</strong> ' . $server['info']->hostname . '<br><strong>IP:</strong> ' . $server['info']->ip;
                                        $title[] = $server['type'];
                                    }
                                    $title = implode(', ', $title);
                                    $content = implode('<br><br>', $content);

                                    // Sometimes Cloudflare comes in with no coords
                                    if ($geoCoord[0] && $geoCoord[1]) {
                                        $js_servers[] = "[ { lat: {$geoCoord[0]}, lng: {$geoCoord[1]} }, '{$title}', '{$content}' ]";
                                    }
                                }
                                echo implode(",\n", $js_servers);
                                ?>];
            mapAll = new google.maps.Map(document.getElementById('map_all'), {
                center: host,
                zoom: 5
            });

            for (let i = 0; i < servers.length; i++) {
                const marker = new google.maps.Marker({
                    position: servers[i][0],
                    title: servers[i][1],
                    windowContent: servers[i][2],
                    map: mapAll
                });

                marker.addListener('click', function() {
                    const infowindow = new google.maps.InfoWindow({
                        content: this.windowContent
                    });
                    infowindow.open(mapAll, this);
                });
            }

            mapAll.setCenter(host);
        }

        function initMap() {
            host = new google.maps.LatLng(<?= $geo[0] ?>, <?= $geo[1] ?>); //{ lat: <?= $geo[0] ?>, lng: <?= $geo[1] ?> };

            // Single server location
            map = new google.maps.Map(document.getElementById('map_single'), {
                center: host,
                zoom: 10
            });
            <?php if ($location) { ?>const marker = new google.maps.Marker({
                position: host,
                title: "Host Server",
                map: map
            });
            marker.addListener('click', function() {
                var infowindow = new google.maps.InfoWindow({
                    content: "<?= '<strong>' . $location->org . '</strong> - <em>Web Server</em><br><strong>Host Name:</strong> ' . $location->hostname . '<br><strong>IP:</strong> ' . $location->ip; ?>"
                });
                infowindow.open(map, this);
            });
        <?php } ?>

        // All servers
        initMapAll();
        }

        document.addEventListener('DOMContentLoaded', function() {
            const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]')
            const tooltipList = [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

            const tabMap = document.querySelector('#map-tab');
            tabMap.addEventListener('shown.bs.tab', event => {
                // event.target // newly activated tab
                // event.relatedTarget // previous active tab
                console.log(map, mapAll, host);
                // Refresh Google maps when switching between tabs
                if (map) {
                    google.maps.event.trigger(map, 'resize');
                    // Recenter
                    map.setCenter(host);
                }
                console.log('tab shown', mapAll);
                if (mapAll) {
                    console.log('resize!');
                    google.maps.event.trigger(mapAll, 'resize');
                    // Recenter
                    mapAll.setCenter(host);
                }
            })

            const downloadBtn = document.querySelector('.download-dns');
            downloadBtn.addEventListener('click', event => {
                console.log(event);
                exportToZone(zoneFile.zone + '.db', atob(zoneFile.text_b64));
            });
        });
    </script>
    <script async defer src="https://maps.googleapis.com/maps/api/js?key=AIzaSyDVLQb71FZZWez5fgLsKSz1ZGfgQYxrPk4&callback=initMap"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ENjdO4Dr2bkBIFxQpeoTz1HIcje39Wm4jDKdf19U8gI4ddQ3GYNS7NTKfAdVQSZe" crossorigin="anonymous"></script>
</body>

</html>