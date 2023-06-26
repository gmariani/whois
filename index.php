<?php

require __DIR__ . '/vendor/autoload.php';
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

error_reporting(E_ALL ^ E_WARNING);
set_time_limit(20);
$host_cache = [];
$ip_cache = [];
$dns_cache = [];
$ipinfo_cache = [];
$ipinfo_count = 0;
$ipapi_count = 0;
$keycdn_count = 0;
$arin_count = 0;
$dns_count = 0;
$server_locations = [];
$errors = [];

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

        $ip_cache[$domain] = $result;
        $host_cache[$ip_cache[$domain]] = $domain;
        $dns_count++;
    }
    return $ip_cache[$domain];
}

function dns_type_to_string(int $type)
{
    $type_string = '';
    switch ($type) {
        case DNS_A:
            $type_string = 'A';
            break;
        case DNS_CNAME:
            $type_string = 'CNAME';
            break;
        case DNS_HINFO:
            $type_string = 'HINFO';
            break;
        case DNS_CAA:
            $type_string = 'CAA';
            break;
        case DNS_MX:
            $type_string = 'MX';
            break;
        case DNS_NS:
            $type_string = 'NS';
            break;
        case DNS_PTR:
            $type_string = 'PTR';
            break;
        case DNS_SOA:
            $type_string = 'SOA';
            break;
        case DNS_TXT:
            $type_string = 'TXT';
            break;
        case DNS_AAAA:
            $type_string = 'AAAA';
            break;
        case DNS_SRV:
            $type_string = 'SRV';
            break;
        case DNS_NAPTR:
            $type_string = 'NAPTR';
            break;
        case DNS_A6:
            $type_string = 'A6';
            break;
        case DNS_DNSKEY:
            $type_string = 'DNSKEY';
            break;
        case DNS_DS:
            $type_string = 'DS';
            break;
        default:
            $type_string = '?';
    }
    return $type_string;
}

function netdns2_to_native(Net_DNS2_Packet_Response $query_response, int $type)
{
    global $dns_resolver;

    $result = [];
    foreach ($query_response->answer as $rr) {
        // Hide/drop the binary as this messes up var_dump
        $rr->rdata = '';

        // if ($type_string != $rr->type) {
        // error_log($type_string . ' != ' . $rr->type);
        // error_log(print_r($rr, true));
        // $test = dns_get_record($host, $type);
        // error_log(print_r($test, true));
        // }

        $rr_data = [
            'host' => $rr->name,
            'class' => $rr->class,
            'ttl' => $rr->ttl,
            'type' => $rr->type,
        ];
        if ($type === DNS_A) {
            $rr_data['ip'] = $rr->address;
        }
        if ($type === DNS_CNAME) {
            $rr_data['target'] = $rr->cname;
        }
        if ($type === DNS_CAA) {
            $rr_data['flags'] = $rr->flags;
            $rr_data['tag'] = $rr->tag;
            $rr_data['value'] = $rr->value;
        }
        if ($type === DNS_MX) {
            // When response is a CNAME
            // error_log(print_r($rr, true));
            if (property_exists($rr, 'preference')) {
                $rr_data['pri'] = $rr->preference;
                $rr_data['target'] = $rr->exchange;
            } else {
                // MX records have to point directly to a server's A record or AAAA record. Pointing to a CNAME is forbidden by the RFC documents that define how MX records function.
                break;
            }
        }
        if ($type === DNS_NS) {
            $rr_data['target'] = $rr->nsdname;
        }
        if ($type === DNS_PTR) {
            $rr_data['target'] = $rr->ptrdname;
        }
        if ($type === DNS_SOA) {
            $rr_data['mname'] = $rr->mname;
            $rr_data['rname'] = $rr->rname;
            $rr_data['serial'] = $rr->serial;
            $rr_data['refresh'] = $rr->refresh;
            $rr_data['retry'] = $rr->retry;
            $rr_data['expire'] = $rr->expire;
            $rr_data['minimum-ttl'] = $rr->minimum;
        }
        if ($type === DNS_TXT) {
            // When response is a CNAME
            if (property_exists($rr, 'text')) {
                $rr_data['txt'] = implode("", $rr->text);
                $rr_data['entries'] = $rr->text;
            } else {
                // Return a CNAME instead
                $rr_data['target'] = $rr->cname;

                // Switch to the native since it recurses better,
                // but save the corrected TTL
                $temp = dns_get_record($rr->cname, $type);
                // error_log('asdfasdf');
                // error_log(print_r($temp, true));

                // $query_response2 = $dns_resolver->query($rr->cname, dns_type_to_string($type));
                // $temp2 = netdns2_to_native($query_response2, $type);
                // error_log(print_r($temp2, true));

                if (count($temp)) {
                    // $rr_data = $temp[0];
                    $rr_data['txt'] = $temp[0]['txt'];
                    $rr_data['entries'] = $temp[0]['entries'];
                    // $rr_data['ttl'] = $rr->ttl;
                } else {
                    // Sometimes it won't give a response for whatever reason (_acme-challenge.nsone.net)
                    // $rr_data['host'] = $rr->cname;
                    $rr_data['txt'] = '';
                    // $rr_data['type'] = 'TXT';
                    $rr_data['entries'] = [];
                }
            }
        }
        if ($type === DNS_AAAA) {
            // When response is a CNAME
            if (property_exists($rr, 'address')) {
                $rr_data['ipv6'] = $rr->address;
            } else {
                // Can't find evidence where this is allowed
                break;
            }
        }
        if ($type === DNS_SRV) {
            $rr_data['pri'] = $rr->priority;
            $rr_data['weight'] = $rr->weight;
            $rr_data['port'] = $rr->port;
            $rr_data['target'] = $rr->target;
        }
        if ($type === DNS_NAPTR) {
            $rr_data['order'] = $rr->order;
            $rr_data['pref'] = $rr->preference;
            $rr_data['flags'] = $rr->flags;
            $rr_data['services'] = $rr->services;
            $rr_data['regex'] = $rr->regexp;
            $rr_data['replacement'] = $rr->replacement;
        }
        if ($type === DNS_DNSKEY) {
            $rr_data['flags'] = $rr->flags;
            $rr_data['protocol'] = $rr->protocol;
            $rr_data['algorithm'] = $rr->algorithm;
            $rr_data['key'] = $rr->key;
        }
        if ($type === DNS_DS) {
            $rr_data['keytag'] = $rr->keytag;
            $rr_data['algorithm'] = $rr->algorithm;
            $rr_data['digesttype'] = $rr->digesttype;
            $rr_data['digest'] = $rr->digest;
        }
        $result[] = $rr_data;
    }

    return $result;
}

function get_dns_record($host, $type)
{
    global $dns_cache, $dns_count, $tld_dns_resolver, $arpa_dns_resolver, $dns_resolver;
    if (!isset($dns_cache[$host])) {
        $dns_cache[$host] = [];
    }

    if (!isset($dns_cache[$host][$type])) {

        // error_log("dns_get_record {$host} - {$type}");
        // BUG: There is no timeout for dns_get_record and it can wait minutes for a reply
        // https://github.com/hostinger/php-dig
        // composer require hostinger/php-dig

        $type_string = dns_type_to_string($type);

        // Save some time if we're only doing a rDNS
        // error_log($host . ' ' . $type_string);
        if ((str_ends_with($host, '.in-addr.arpa') || str_ends_with($host, '.ip6.arpa')) && $type !== DNS_PTR) {
            $result = false;
        } else if ($host === '' || $host === false) {
            $result = false;
        } else {
            try {
                $resolver = $dns_resolver;
                // Use different resolvers forced to use different nameservers
                if ($type === DNS_DS) $resolver = $tld_dns_resolver;
                if ($type === DNS_PTR) $resolver = $arpa_dns_resolver;

                $query_response = $resolver->query($host, $type_string);
                $result = netdns2_to_native($query_response, $type);
            } catch (Net_DNS2_Exception $e) {
                // Skip
                $error_message = $e->getMessage();
                if (str_contains($error_message, 'The name server refuses to perform the specified operation for policy reasons.')) {
                    // Try again, wait 50ms
                    // usleep(50 * 1000);
                    sleep(1);

                    try {
                        $query_response = $resolver->query($host, $type_string);
                        $result = netdns2_to_native($query_response, $type);
                    } catch (Net_DNS2_Exception $e) {
                        // Skip
                        $error_message2 = $e->getMessage();
                        error_log("get_dns_record()3: " . $host . ', ' . $type_string);
                        error_log("get_dns_record()4: " . $error_message2);
                        // Bail, just use built-in and kill the erroneous TTL
                        $result = dns_get_record($host, $type);
                    }
                } else if (!str_contains($error_message, 'The domain name referenced in the query does not exist')) {
                    error_log("get_dns_record()1: " . $host . ', ' . $type_string);
                    error_log("get_dns_record()2: " . $error_message);
                    // Bail, just use built-in and kill the erroneous TTL
                    $result = dns_get_record($host, $type);
                    if (isset($result[0])) $result[0]['ttl'] = 999;
                } else {
                    $result = false;
                }
            }
        }
        // error_log(print_r($result, true));

        // TXT maps to CNAME, fix it
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

    // return '.' . $parts[count($parts) - 1];
    return $parts[count($parts) - 1] . '.';
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
            if ($spf === false) $spf = [];
            $result = [];
            $result['raw'] = trim($record['txt']);
            $parts = explode(' ', $result['raw']);
            $result['pass'] = [];
            $result['fail'] = [];
            $result['softfail'] = [];
            $result['neutral'] = [];

            array_shift($parts); // remove v=spf1
            foreach ($parts as $part) {
                if (str_starts_with($part, '+') !== false) {
                    $result['pass'][] = $part;
                } elseif (str_starts_with($part, '-') !== false) {
                    $result['fail'][] = $part;
                } elseif (str_starts_with($part, '~') !== false) {
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
        // Did we get a CNAME instead?
        // if (isset($record['target'])) {
        //     $txt_records = get_dns_record($record['target'], DNS_TXT);
        // }

        if (isset($record['entries'])) $record['txt'] = implode('', $record['entries']);

        // Sometimes they don't have v=DKIM
        if (strpos($record['txt'] ?? '', 'v=DKIM') !== false || strpos($record['txt'] ?? '', 'k=rsa') !== false) {
            if ($dkim === false) $dkim = [];

            $result = [];
            $result['host'] = $host;
            // Some services like SendGrid will return a CNAME if you ask for TXT in order
            // to map it dynamically
            if (isset($record['target'])) $result['cname'] = $record['target'];
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
            $key = $keyres ? openssl_pkey_get_details($keyres) : false;
            $result['key_bits'] = $key ? ($key['bits'] ?? '?') : '?';
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
        get_dkim_single('smt', $domain),
        get_dkim_single('smt2', $domain),
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
    }

    // No SSL
    // error_log("has_ssl()1: Error {$domain}, code {$error_code}");
    // error_log("has_ssl()2: " . print_r($error_message, true));
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
            if ($dmarc === false) $dmarc = [];
            $result = [];
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
    $result = [];

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

    $result['net_block'] = [];
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

        $streetAddress = [];
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
        error_log("geo_lookup_ip_api(): Rate Limit " . print_r($body, true));
        return false;
    }

    $json_result = json_decode($body);
    if ($json_result->status === 'fail') {
        /*echo '<pre>';
		var_dump($body);
		echo '</pre>';*/
        // $errors[] = "GeoLocate: Error<br><pre>" . print_r($body, true) . '</pre>';
        if (!empty($body)) error_log("geo_lookup_ip_api(): Error - " . print_r($body, true));
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
        error_log("geo_lookup_ipinfo(): Rate Limit " . print_r($body, true));
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
        error_log("geo_lookup_keycdn(): Rate Limit " . print_r($body, true));
        return false;
    }

    $json_result = json_decode($body);
    if ($json_result->status !== 'success') {
        if (!empty($result)) error_log("geo_lookup_keycdn(): Error - " . print_r($result, true));
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
            $spf_item = preg_replace('/^(\+|\-|\~|\")/', '', $spf_item);

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
    $result = [];
    if ($year > 0) $result[] = $year . 'y';
    if ($day > 0) $result[] = $day . 'd';
    if ($hours > 0) $result[] = $hours . 'h';
    if ($mins > 0) $result[] = $mins . 'm';
    if ($secs > 0) $result[] = $secs . 's';

    //$timeFormat = sprintf('%02d:%02d:%02d', $hours, $mins, $secs);
    return implode(' ', $result);
}

function get_nameservers_ip($host)
{
    if (false === $host) return [];

    $response = dns_get_record($host, DNS_NS);
    if (count($response)) {
        return array_map(function ($record) {
            return ['host' => $record['target'], 'ip' => get_host_by_name($record['target'])];
        }, $response);
    }
    return [];
}

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
    $index = [];
    $result = [];
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

// START //
/*
API Limitations

Google Maps - https://developers.google.com/maps/pricing-and-plans/#details
Free up to 25,000 map loads per day.3
$0.50 USD / 1,000 additional map loads, up to 100,000 daily, if billing is enabled.
*/

// New servers are set to deny DNS_ALL and DNS_ANY
//$dns_records = get_dns_record( $domain, DNS_ALL );
// hinfo - deprecated along with ANY
// A6 - prototype for ipv6, deprecated

// https://en.wikipedia.org/wiki/List_of_DNS_record_types
// TXT -> CNAME pipershores.org
// AAAA jplcreative.com
// NAPTR kutchy.com
// PTR 139.149.87.209.in-addr.arpa. (coursevector.com rDNS)
// PTR IPv6 .ip6.arpa (jplcreative.com rDNS)
// 2606:4700:3034:0:0:0:ac43:acf3 -> 3.f.c.a.3.4.c.a.0.0.0.4.3.0.3.0.0.7.4.6.0.6.2.ip6.arpa
// CAA caatest.co.uk
// DNSKEY cloudflare.com
// DS cloudflare.com must ask parent zone nameserver
// wildcards everything accuaudits.com
$domain = isset($_GET['q']) ? strtolower(trim($_GET['q'])) : 'google.com';
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
$nameservers_hosts = get_nameservers_ip($domain);
$nameservers = array_map(function ($ns) {
    return $ns['ip'];
}, $nameservers_hosts);
if (count($nameservers) <= 0) {
    $nameservers = ['1.1.1.1', '9.9.9.9'];
}

// For PTR lookup
$arpa_host = $ip ? implode('.', array_reverse(explode('.', $ip))) . ".in-addr.arpa" : false;
// error_log($arpa_host);
$arpa_nameservers_hosts = get_nameservers_ip($arpa_host);
$arpa_nameservers = array_map(function ($ns) {
    return $ns['ip'];
}, $arpa_nameservers_hosts);
if (count($arpa_nameservers) <= 0) {
    $arpa_nameservers = ['1.1.1.1', '9.9.9.9'];
}
// TODO fail gracefully when given an arpa address directly

// For DS lookup
$tld = get_tld($domain);
$tld_nameservers_hosts = get_nameservers_ip($tld);
$tld_nameservers = array_map(function ($ns) {
    return $ns['ip'];
}, $tld_nameservers_hosts);
if (count($tld_nameservers) <= 0) {
    $tld_nameservers = ['1.1.1.1', '9.9.9.9'];
}

// error_log(print_r($nameservers, true));
$dns_resolver = new Net_DNS2_Resolver(['nameservers' => $nameservers]);
$tld_dns_resolver = new Net_DNS2_Resolver(['nameservers' => $tld_nameservers]);
$arpa_dns_resolver = new Net_DNS2_Resolver(['nameservers' => $arpa_nameservers]);

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

// Windows PHP bug https://bugs.php.net/bug.php?id=75909
if (!defined('DNS_CAA')) define('DNS_CAA', 8192);
define('DNS_DNSKEY', 1000);
define('DNS_DS', 1001);

$dns_records = array(
    'a' => get_dns_record($domain, DNS_A),
    'cname' => get_dns_record($domain, DNS_CNAME),
    //'hinfo' => get_dns_record( $domain, DNS_HINFO ),
    'dnskey' => get_dns_record($domain, DNS_DNSKEY),
    'ds' => get_dns_record($domain, DNS_DS),
    // 'caa' => get_dns_record($domain, DNS_CAA), // PHP 7.1.2+
    'mx' => get_dns_record($domain, DNS_MX),
    'ns' => get_dns_record($domain, DNS_NS),
    'ptr' => get_dns_record($arpa_host, DNS_PTR),
    'soa' => get_dns_record($domain, DNS_SOA),
    'txt' => get_dns_record($domain, DNS_TXT),
    'aaaa' => get_dns_record($domain, DNS_AAAA),
    'srv' => get_dns_record($domain, DNS_SRV),
    'naptr' => get_dns_record($domain, DNS_NAPTR)
);

function merge_unique_ip(bool $is_wildcard, array $wildcard_ips, array  &$dns_records, array $a_record)
{
    if ($is_wildcard) {
        if (!in_array($a_record[0]['ip'], $wildcard_ips)) {
            $dns_records['a'] = array_merge_unique($dns_records['a'], $a_record);
        }
    } else {
        $dns_records['a'] = array_merge_unique($dns_records['a'], $a_record);
    }
}

function merge_unique_cname(bool $is_wildcard, array $wildcard_targets, array  &$dns_records, array $cname_record)
{
    if ($is_wildcard) {
        if (!in_array($cname_record[0]['target'], $wildcard_targets)) {
            $dns_records['cname'] = array_merge_unique($dns_records['cname'], $cname_record);
        }
    } else {
        $dns_records['cname'] = array_merge_unique($dns_records['cname'], $cname_record);
    }
}

function merge_unique_txt(bool $is_wildcard, array $wildcard_targets, array  &$dns_records, array $txt_record)
{
    if ($txt_record[0]['type'] === 'CNAME') {
        merge_unique_cname($is_wildcard, $wildcard_targets, $dns_records, $txt_record);
    } else {
        if ($is_wildcard) {
            if (!in_array($txt_record[0]['cname'], $wildcard_targets)) {
                $dns_records['txt'] = array_merge_unique($dns_records['txt'], $txt_record);
            }
        } else {
            $dns_records['txt'] = array_merge_unique($dns_records['txt'], $txt_record);
        }
    }
}

function check_default_records(&$dns_records, $domain)
{
    $default_subdomains = [
        // Default cPanel
        'ftp', 'www', 'mail', 'webmail', 'webdisk', 'whm', 'cpanel', 'cpcalendars', 'cpcontacts', 'autoconfig',
        // Default MS Exchange
        'autodiscover', 'sip', 'lyncdiscover', 'msoid', 'enterpriseregistration', 'enterpriseenrollment',
        // Common
        '_cf-custom-hostname', '_domainconnect', '_dmarc', 'www.dev', 'dev', 'www.staging', 'staging',
        'stagingwww', 'calendar', 'www.calendar', 'docs', 'sites', 'start', 'email', 'fax', 'files', 'imap',
        'pop', 'smtp', 'mobileemail', 'remote', 'course', 'blog', 'server', 'ns1', 'ns2', 'secure',
        'vpn', 'm', 'shop', 'test', 'portal', 'host', 'ww1', 'support', 'web', 'bbs', 'mx', 'cloud',
        'forum', 'owa', 'www2', 'admin', 'cdn', 'api', 'app', 'exchange', 'gov', 'news', 'vps', 'ns',
        'mail2', 'mx0', 'mx1', 'mailserver', 'server', 'r.1', 'r.2', 'r.3', 'spam', 'auth', 'sso',
        'webapps', 'securemail', 'online', 'signin', 'account', 'myonline', 'myaccount', 'origin',
        'www.account', 'staff', 'training', 'terminal', 'pay', 'watch', 'www.webmail',
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
            merge_unique_ip($is_wildcard, $wildcard_ips, $dns_records, $a_record);
        } else {
            // sometimes a CNAME will return nothing
            //error_log("${subdomain}.${domain}");
            //error_log(print_r($a_record, true));
        }
    }

    // Check CNAME record wildcard
    $wildcard_records = get_dns_record("mariani-is-cool.{$domain}", DNS_CNAME);
    $is_wildcard = count($wildcard_records) > 0 ? true : false;
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
            merge_unique_cname($is_wildcard, $wildcard_targets, $dns_records, $cname_record);
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

    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('_caldav._tcp.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('_caldavs._tcp.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('_carddav._tcp.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('_carddavs._tcp.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('default._domainkey.' . $domain, DNS_TXT));
    // cPanel
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('_cpanel-dcv-test-record.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('_acme-challenge.' . $domain, DNS_TXT));
    // Google
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('google._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('ga1._domainkey.' . $domain, DNS_TXT));
    // MS 365
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('selector1._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('selector2._domainkey.' . $domain, DNS_TXT));
    // Mailchimp
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('k1._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('k2._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('k3._domainkey.' . $domain, DNS_TXT));
    // Cloudflare
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('_cf-custom-hostname.' . $domain, DNS_TXT));
    // Campaign Monitor
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('cm._domainkey.' . $domain, DNS_TXT));
    // MXRoute
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('x._domainkey.' . $domain, DNS_TXT));
    // Mailgun
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('smtp._domainkey.' . $domain, DNS_TXT));
    // turboSMTP
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('turbo-smtp._domainkey.' . $domain, DNS_TXT));
    // SendGrid
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('s1._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('s2._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('smt._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('smt2._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('m1._domainkey.' . $domain, DNS_TXT));
    merge_unique_txt($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('smtpapi._domainkey.' . $domain, DNS_TXT));
    // HubSpot
    merge_unique_cname($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('hs1._domainkey.' . $domain, DNS_CNAME));
    merge_unique_cname($is_wildcard, $wildcard_targets, $dns_records, get_dns_record('hs2._domainkey.' . $domain, DNS_CNAME));

    // If a CNAME exists for a matching A or TXT record, remove them as only the CNAME should exist
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
$country_tlds = ['co.uk'];

// Check any default subdomains
check_default_records($dns_records, $domain);
// If we are working with a subdomain, merge in the parent/root domains records
if (!$is_root_domain && !in_array($root_domain, $country_tlds)) {
    check_default_records($dns_records, $root_domain);
}

// Sort A records by host
function sortByHost($a, $b)
{
    return strcmp($a["host"], $b["host"]);
}
usort($dns_records['a'], 'sortByHost');

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
$dns_records['dkim'] = [];
foreach ($dkim_records as $dkim) {
    $dns_records['dkim'][] = $dkim['raw'];
}
// error_log('get_dmarc');
$dmarc_records = get_dmarc($domain);
$dns_records['dmarc'] = [];
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

        /* @font-face {
            font-family: 'Menlo Regular';
            font-style: normal;
            font-weight: normal;
            src: local('Menlo Regular'), url('fonts/Menlo-Regular.woff') format('woff');
        } */

        body {
            font-family: 'Lato', Helvetica, Arial, sans-serif;
            text-rendering: optimizeLegibility;
        }

        code.test,
        pre.test {
            font-family: 'Menlo Regular', Consolas, Monaco, monospace;
            /*font-family: "PT Mono", monospace;*/
            tab-size: 4;
        }

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

        /* .bd-content dl>dt, */
        .bd-content>.table th,
        .bd-content>.table-responsive .table th {
            color: var(--bs-emphasis-color);
        }

        .bd-content dl>dt {
            text-align: end;
            font-weight: 600;
            margin-inline-end: 0;
        }

        .bd-content dl>dd {
            color: rgb(251, 251, 254);
            margin-bottom: .25rem;
        }

        .bd-group {
            padding: 1.75em 30px;
            border-top: 1px solid rgba(249, 249, 250, 0.2);
        }

        .bd-group-title {
            border-bottom: 2px solid white;
            padding-bottom: 8px;
            margin-bottom: 0;
            display: inline-block;
        }

        .bg-group-section-title {
            text-align: end;
            font-weight: 700;
            color: rgb(251, 251, 254);
            font-size: 1em;
            vertical-align: middle;
            transform: translateX(-5px);
        }

        .bd-navbar {
            padding: .75rem 0;
            /* background-color: transparent; */
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15), inset 0 -1px 0 rgba(255, 255, 255, 0.15);
            /* background-color: #1e293b; */
            /* background-image: linear-gradient(rgba(var(--bd-violet-rgb), 1), rgba(var(--bd-violet-rgb), 0.95)); */
            background-image: linear-gradient(90deg, rgba(33, 62, 111, 1) 0%, rgba(33, 62, 111, 0.95) 100%);
            ;
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

        .google-map {
            width: 100%;
            height: 400px;
            border-radius: 5px;
            box-shadow: 0 14px 28px rgba(0, 0, 0, 0.25), 0 10px 10px rgba(0, 0, 0, 0.22);
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
                        <h2 class="display-5 bd-group-title">General</h2>
                        <div class="bd-group row">
                            <dl class="row">
                                <dt class="col-sm-4">Server IP</dt>
                                <dd class="col-sm-8"><?= $ip ?></dd>

                                <dt class="col-sm-4">Server Location</dt>
                                <dd class="col-sm-8"><?= $ip === false ? 'Unknown' : get_location_address($location) ?></dd>

                                <dt class="col-sm-4">Host</dt>
                                <dd class="col-sm-8"><?= ($arin['customer_name'] ?? 'Unknown Customer Name') . ' (<a href="' . ($arin['customer_link'] ?? '#') . '" target="_blank">' . ($arin['customer_handle'] ?? 'Unknown Customer Handle') . '</a>)' ?></dd>

                                <dt class="col-sm-4">Host Net Blocks</dt>
                                <dd class="col-sm-8">
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

                                <dt class="col-sm-4">Domain Expiration Date</dt>
                                <dd class="col-sm-8"><?= $domain_expiration . $domain_ttl ?></dd>

                                <dt class="col-sm-4">Domain Contact</dt>
                                <dd class="col-sm-8"><?= $domain_data['contact'] ?></dd>
                            </dl>
                        </div>

                        <div class="bd-group row">
                            <dl class="row">
                                <dt class="col-sm-4">Domain Registrar</dt>
                                <dd class="col-sm-8"><?= $domain_data['registrar'] ?></dd>

                                <dt class="col-sm-4">Name Server Provider</dt>
                                <dd class="col-sm-8"><?php
                                                        $email_host = [];
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

                                <dt class="col-sm-4">Hosting Provider</dt>
                                <dd class="col-sm-8"><?php
                                                        foreach ($dns_records['a'] as $record) {
                                                            $ip = $record['ip'];
                                                            $ip_info = get_location($ip);
                                                            echo $ip_info ? translate_org($ip_info->org ?? '') : 'API Rate Limit';
                                                            break;
                                                        }
                                                        ?>
                                </dd>

                                <dt class="col-sm-4">Email Provider</dt>
                                <dd class="col-sm-8"><?php
                                                        $email_host = [];
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
                                                            $email_host = [];
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

                                <dt class="col-sm-4">Hosting Provider</dt>
                                <dd class="col-sm-8"><?php
                                                        foreach ($dns_records['a'] as $record) {
                                                            $ip = $record['ip'];
                                                            $ip_info = get_location($ip);
                                                            echo $ip_info ? translate_org($ip_info->org ?? '') : 'API Rate Limit';
                                                            break;
                                                        }
                                                        ?>
                                </dd>
                            </dl>
                        </div>

                        <?php
                        if (isset($headers["Server"]) || isset($headers["X-Powered-By"]) || isset($headers["X-Amz-Cf-Id"])) {
                            // error_log(print_r($headers, true));
                            echo "<div class=\"bd-group row\">";
                            echo '<dl class="row">';
                            if (isset($headers["Server"])) {
                                echo '<dt class="col-sm-4">Server Software</dt>';
                                echo '<dd class="col-sm-8">' . val_to_string($headers["Server"]) . "</dd>";
                            }
                            if (isset($headers["X-Powered-By"])) {
                                echo '<dt class="col-sm-4">Powered By</dt>';
                                echo "<dd class=\"col-sm-8\">{$headers["X-Powered-By"]}</dd>";
                            }
                            if (isset($headers["X-Amz-Cf-Id"])) {
                                echo '<dt class="col-sm-4">Uses CloudFront</dt>';
                                echo '<dd class="col-sm-8">True</dd>';
                            }
                            echo '</dl>';
                            echo '</div>';
                        } ?>
                    </div>
                    <div class="col-4">
                        <div id="map_single" class="google-map" style="height:100%;"></div>
                    </div>
                </div>
                <div class="row">
                    <div class="col">
                        <?php
                        if (count($dns_records['ptr']) > 0) { ?>
                            <h2 class="display-5 bd-group-title">Reverse <abbr title="Domain Name System">DNS</abbr> Record</h2>
                            <div class="bd-group row">
                                <table class="table table-dark table-striped records">
                                    <?php
                                    foreach ($dns_records['ptr'] as $record) {
                                        $ip = get_host_by_name($record['target']);
                                        $ip_info = get_location($ip);
                                    ?>
                                        <tr>
                                            <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="Pointer"><?php echo $record['type']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $ip; ?>&#10;<?php echo ($ip_info ? $ip_info->org : ''); ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $record['target']; ?></td>
                                        </tr>
                                    <?php
                                    }
                                    ?>
                                </table>
                            </div>
                        <?php } ?>

                        <h2 class="display-5 bd-group-title"><abbr title="Domain Name System">DNS</abbr> Records</h2>
                        <div class="bd-group row">
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
; Finally, these records may not be completely accurate
; due to the nature of how they were acquired. DNS does not allow
; access to all DNS records of a particular domain. Instead they
; must be requested by name. This website attempts many known
; combinations but ultimately will never be 100% accurate.
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

                                $zoneExportRaw .= "; SOA Record\n";
                                foreach ($dns_records['soa'] as $record) {
                                    $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['mname']}.\t{$record['rname']}.\t(\n\t\t\t\t\t\t{$record['serial']} ;Serial Number\n\t\t\t\t\t\t{$record['refresh']} ;refresh\n\t\t\t\t\t\t{$record['retry']} ;retry\n\t\t\t\t\t\t{$record['expire']} ;expire\n\t\t\t\t\t\t{$record['minimum-ttl']}\t)\n";
                                ?>
                                    <tr>
                                        <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
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
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Namer Server"><?php echo $record['type']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $ip; ?>&#10;<?php echo ($ip_info ? $ip_info->org : ''); ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $record['target']; ?></td>
                                    </tr>
                                <?php
                                }
                                if (count($dns_records['ns']) > 0) $zoneExportRaw .= "\n";

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
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
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
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="IPv6 Address"><?php echo $record['type']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $record['host']; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $ip; ?></td>
                                    </tr>
                                <?php
                                }
                                if (count($dns_records['aaaa']) > 0) $zoneExportRaw .= "\n";

                                if (count($dns_records['cname']) > 0) $zoneExportRaw .= "; CNAME Record\n";
                                foreach ($dns_records['cname'] as $record) {
                                    $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['target']}.\n";

                                    $ip = get_host_by_name($record['target']);
                                    // error_log($ip . ' - ' . $record['target']);
                                    $ip_info = get_location($ip);
                                ?>
                                    <tr>
                                        <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Canonical Name"><?php echo $record['type']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $record['target']; ?></td>
                                    </tr>
                                <?php
                                }
                                if (count($dns_records['cname']) > 0) $zoneExportRaw .= "\n";

                                if (count($dns_records['dnskey']) > 0) $zoneExportRaw .= "; DNSKEY Record\n";
                                foreach ($dns_records['dnskey'] as $record) {
                                    // flags, protocol, algorithm, key
                                    $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['flags']}\t{$record['protocol']}\t{$record['algorithm']}\t{$record['key']}\n";

                                    // Flags lookup
                                    $flags_label = '';
                                    // If bit 7 has value 1, then the DNSKEY record holds a DNS zone key
                                    if (intval($record['flags']) & (1 << 8)) {
                                        $flags_label .= "Holds DNS Zone Key: True - ";
                                    } else {
                                        $flags_label .= "Holds DNS Zone Key: False - ";
                                    }
                                    // If bit 15 has value 1, then the DNSKEY record holds a key intended for use as a secure entry point.
                                    if (intval($record['flags']) & 1) {
                                        $flags_label .= 'Secure Entry Point: True';
                                    } else {
                                        $flags_label .= 'Secure Entry Point: False';
                                    }

                                    // Algorithm lookup
                                    $algo_label = '?';
                                    switch ($record['algorithm']) {
                                        case 1:
                                            $algo_label = "RSA/MD5";
                                            break;
                                        case 2:
                                            $algo_label = "Diffie-Hellman";
                                            break;
                                        case 3:
                                            $algo_label = "DSA/SHA-1";
                                            break;
                                        case 4:
                                            $algo_label = "Elliptic Curve";
                                            break;
                                        case 5:
                                            $algo_label = "RSA/SHA-1";
                                            break;
                                        case 6:
                                            $algo_label = "DSA-NSEC3-SHA1";
                                            break;
                                        case 7:
                                            $algo_label = "RSASHA1-NSEC3-SHA1";
                                            break;
                                        case 8:
                                            $algo_label = "RSA/SHA-256";
                                            break;
                                        case 10:
                                            $algo_label = "RSA/SHA-512";
                                            break;
                                        case 12:
                                            $algo_label = "GOST R 34.10-2001";
                                            break;
                                        case 13:
                                            $algo_label = "ECDSA/SHA-256";
                                            break;
                                        case 14:
                                            $algo_label = "ECDSA/SHA-384";
                                            break;
                                        case 15:
                                            $algo_label = "Ed25519";
                                            break;
                                        case 16:
                                            $algo_label = "Ed448";
                                            break;
                                        case 252:
                                            $algo_label = "Indirect";
                                            break;
                                        case 253:
                                            $algo_label = "Private";
                                            break;
                                        case 254:
                                            $algo_label = "Private OID";
                                            break;
                                    }
                                ?>
                                    <tr>
                                        <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="DNS Key"><?php echo $record['type']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Flags - <?= $flags_label ?>"><?php echo $record['flags']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Protocol"><?php echo $record['protocol']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Algorithm - <?= $algo_label ?>"><?php echo $record['algorithm']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Public Key" colspan="4"><code><?php echo $record['key']; ?></code></td>
                                    </tr>
                                    <?php
                                }
                                if (count($dns_records['dnskey']) > 0) $zoneExportRaw .= "\n";

                                if (isset($dns_records['caa'])) {
                                    if (count($dns_records['caa']) > 0) $zoneExportRaw .= "; CAA Record\n";
                                    foreach ($dns_records['caa'] as $record) {
                                        $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['flags']}\t{$record['tag']}\t\"{$record['value']}\"\n";
                                    ?>
                                        <tr>
                                            <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="Certification Authority Authorization"><?php echo $record['type']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="Flags"><?php echo $record['flags']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="Tag"><?php echo $record['tag']; ?></td>
                                            <td data-bs-toggle="tooltip" data-bs-title="Value" colspan="5"><code><?php echo $record['value']; ?></code></td>
                                        </tr>
                                    <?php
                                    }
                                    if (count($dns_records['caa']) > 0) $zoneExportRaw .= "\n";
                                }

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
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
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
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
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
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
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
									<td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time( $record['ttl'] ); ?>"><?php echo $record['ttl']; ?></td>
									<td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
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
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Service Location"><?php echo $record['type']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Priority"><?php echo $record['pri']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Weight"><?php echo $record['weight']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Port"><?php echo $record['port']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="4"><?php echo $record['target']; ?></td>
                                    </tr>
                                <?php
                                }
                                if (count($dns_records['srv']) > 0) $zoneExportRaw .= "\n";

                                if (count($dns_records['naptr']) > 0) $zoneExportRaw .= "; NAPTR Record\n";
                                foreach ($dns_records['naptr'] as $record) {
                                    $zoneExportRaw .= getZoneHost($domain, $record['host']) . "\t{$record['ttl']}\t{$record['class']}\t{$record['type']}\t{$record['order']}\t{$record['pref']}\t{$record['flags']}\t{$record['services']}\t{$record['regex']}\t{$record['replacement']}\n";
                                ?>
                                    <tr>
                                        <td data-bs-toggle="tooltip" data-bs-title="Host"><?php echo $record['host']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Internet"><?php echo $record['class']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Naming Authority Pointer"><?php echo $record['type']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Order"><?php echo $record['order']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Preference"><?php echo $record['pref']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Flags"><?php echo $record['flags']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Service"><?php echo $record['services']; ?></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Regexp"><code><?php echo $record['regex']; ?></code></td>
                                        <td data-bs-toggle="tooltip" data-bs-title="Replacement"><?php echo $record['replacement']; ?></td>
                                    </tr>
                                <?php
                                }
                                if (count($dns_records['naptr']) > 0) $zoneExportRaw .= "\n";

                                ?>
                            </table>
                        </div>
                        <button class="btn btn-primary download-dns"><i class="bi bi-download"></i>&nbsp;Download Zone File</button>
                    </div>
                </div>
            </section>

            <section id="security-tab-pane" class="tab-pane fade" role="tabpanel" aria-labelledby="security-tab" tabindex="0">

                <h2 class="display-5 bd-group-title">DNS Security</h2>

                <?php
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

                foreach ($dns_records['dnskey'] as $key => $record) {
                    echo "<div class=\"bd-group row\">";
                    echo "<h3 class=\"bg-group-section-title col-sm-3\">DNS Key</h3>";
                    echo "<dl class=\"row\">";
                    // Flags lookup
                    $flags_label = '';
                    // If bit 7 has value 1, then the DNSKEY record holds a DNS zone key
                    echo "<dt class=\"col-sm-3\">Holds DNS Zone Key</dt>";
                    if (intval($record['flags']) & (1 << 8)) {
                        echo "<dd class=\"col-sm-9\">True</dd>";
                    } else {
                        echo "<dd class=\"col-sm-9\">False</dd>";
                    }

                    // If bit 15 has value 1, then the DNSKEY record holds a key intended for use as a secure entry point.
                    echo "<dt class=\"col-sm-3\">Secure Entry Point</dt>";
                    if (intval($record['flags']) & 1) {
                        echo "<dd class=\"col-sm-9\">True</dd>";
                    } else {
                        echo "<dd class=\"col-sm-9\">False</dd>";
                    }

                    // Algorithm lookup
                    $algo_label = '?';
                    switch ($record['algorithm']) {
                        case 1:
                            $algo_label = "RSA/MD5";
                            break;
                        case 2:
                            $algo_label = "Diffie-Hellman";
                            break;
                        case 3:
                            $algo_label = "DSA/SHA-1";
                            break;
                        case 4:
                            $algo_label = "Elliptic Curve";
                            break;
                        case 5:
                            $algo_label = "RSA/SHA-1";
                            break;
                        case 6:
                            $algo_label = "DSA-NSEC3-SHA1";
                            break;
                        case 7:
                            $algo_label = "RSASHA1-NSEC3-SHA1";
                            break;
                        case 8:
                            $algo_label = "RSA/SHA-256";
                            break;
                        case 10:
                            $algo_label = "RSA/SHA-512";
                            break;
                        case 12:
                            $algo_label = "GOST R 34.10-2001";
                            break;
                        case 13:
                            $algo_label = "ECDSA/SHA-256";
                            break;
                        case 14:
                            $algo_label = "ECDSA/SHA-384";
                            break;
                        case 15:
                            $algo_label = "Ed25519";
                            break;
                        case 16:
                            $algo_label = "Ed448";
                            break;
                        case 252:
                            $algo_label = "Indirect";
                            break;
                        case 253:
                            $algo_label = "Private";
                            break;
                        case 254:
                            $algo_label = "Private OID";
                            break;
                    }

                    echo "<dt class=\"col-sm-3\">Algorithm</dt>";
                    echo "<dd class=\"col-sm-9\">{$algo_label}</dd>";

                    echo "<dt class=\"col-sm-3\">Protocol</dt>";
                    echo "<dd class=\"col-sm-9\">{$record['protocol']}</dd>";

                    echo "<dt class=\"col-sm-3\">Public Key</dt>";
                    echo "<dd class=\"col-sm-9\"><code>" . addColonSeparators(bin2hex(base64_decode($record['key']))) . "</code></dd>";

                    echo "</dl>";
                    echo "</div>";
                }

                foreach ($dns_records['ds'] as $record) {
                    // DS records are reported by the parent zone
                    $lookup_host = count($tld_nameservers_hosts) ? $tld_nameservers_hosts[0]['host'] : '?';
                    $lookup = " <abbr title='Report by'>&rarr; {$lookup_host}</abbr>";

                    echo "<div class=\"bd-group row\">";
                    echo "<h3 class=\"bg-group-section-title col-sm-3\">Delegation Signer via {$lookup_host}</h3>";
                    echo "<dl class=\"row\">";

                    // Algorithm lookup
                    $algo_label = '?';
                    switch ($record['algorithm']) {
                        case 1:
                            $algo_label = "RSA/MD5";
                            break;
                        case 2:
                            $algo_label = "Diffie-Hellman";
                            break;
                        case 3:
                            $algo_label = "DSA/SHA-1";
                            break;
                        case 4:
                            $algo_label = "Elliptic Curve";
                            break;
                        case 5:
                            $algo_label = "RSA/SHA-1";
                            break;
                        case 6:
                            $algo_label = "DSA-NSEC3-SHA1";
                            break;
                        case 7:
                            $algo_label = "RSASHA1-NSEC3-SHA1";
                            break;
                        case 8:
                            $algo_label = "RSA/SHA-256";
                            break;
                        case 10:
                            $algo_label = "RSA/SHA-512";
                            break;
                        case 12:
                            $algo_label = "GOST R 34.10-2001";
                            break;
                        case 13:
                            $algo_label = "ECDSA/SHA-256";
                            break;
                        case 14:
                            $algo_label = "ECDSA/SHA-384";
                            break;
                        case 15:
                            $algo_label = "Ed25519";
                            break;
                        case 16:
                            $algo_label = "Ed448";
                            break;
                        case 252:
                            $algo_label = "Indirect";
                            break;
                        case 253:
                            $algo_label = "Private";
                            break;
                        case 254:
                            $algo_label = "Private OID";
                            break;
                    }

                    // Digest lookup
                    $digest_label = '?';
                    switch ($record['digesttype']) {
                        case 1:
                            $digest_label = "SHA-1";
                            break;
                        case 2:
                            $digest_label = "SHA-256";
                            break;
                        case 3:
                            $digest_label = "GOST R 34.10-2001";
                            break;
                        case 4:
                            $digest_label = "SHA-384";
                            break;
                    }

                    echo "<dt class=\"col-sm-3\">Key Tag</dt>";
                    echo "<dd class=\"col-sm-9\">{$record['keytag']}</dd>";

                    echo "<dt class=\"col-sm-3\">Algorithm</dt>";
                    echo "<dd class=\"col-sm-9\">{$algo_label}</dd>";

                    echo "<dt class=\"col-sm-3\">Digest Type</dt>";
                    echo "<dd class=\"col-sm-9\">{$digest_label}</dd>";

                    echo "<dt class=\"col-sm-3\">Digest</dt>";
                    echo "<dd class=\"col-sm-9\"><code>" . addColonSeparators($record['digest']) . "</code></dd>";

                    echo "</dl>";
                    echo "</div>";
                }

                if (count($dns_records['dnskey']) === 0 && count($dns_records['ds']) === 0) {
                    echo "<div class=\"bd-group row\">";
                    // echo "<h3 class=\"bg-group-section-title col-sm-3\">Delegation Signer via {$lookup_host}</h3>";
                    echo "<dl class=\"row\">";
                    echo "<dt class=\"col-sm-3\"></dt>";
                    echo "<dd class=\"col-sm-9\">No DNSSEC records found</dd>";

                    echo "</dl>";
                    echo "</div>";
                }
                ?>

                <h2 class="display-5 mt-5 bd-group-title">HTTP Security Headers</h2>
                <div class="bd-group row">
                    <dl class="row">
                        <?php
                        $hasAnyHeaders = false;
                        if (isset($headers["Content-Security-Policy"])) {
                            $hasAnyHeaders = true;
                            echo "<dt class=\"col-sm-3\"><abbr title=\"Content Security Policy\">CSP</abbr></dt><dd class=\"col-sm-9\">" . val_to_string($headers["Content-Security-Policy"]) . "</dd>";
                        }
                        if (isset($headers["Content-Security-Policy-Report-Only"])) {
                            $hasAnyHeaders = true;
                            echo "<dt class=\"col-sm-3\"><abbr title=\"Content Security Policy\">CSP</abbr> Report Only</dt><dd class=\"col-sm-9\">" . val_to_string($headers["Content-Security-Policy-Report-Only"]) . "</dd>";
                        }
                        if (isset($headers["Public-Key-Pins"])) {
                            $hasAnyHeaders = true;
                            echo "<dt class=\"col-sm-3\"><abbr title=\"HTTP Public Key Pinning\">HPKP</abbr></dt><dd class=\"col-sm-9\">" . val_to_string($headers["Public-Key-Pins"]) . "</dd>";
                        }
                        if (isset($headers["Strict-Transport-Security"])) {
                            $hasAnyHeaders = true;
                            echo "<dt class=\"col-sm-3\"><abbr title=\"HTTP Strict Transport Security\">HSTS</abbr></dt><dd class=\"col-sm-9\">" . val_to_string($headers["Strict-Transport-Security"]) . "</dd>";
                        }
                        if (isset($headers["X-Frame-Options"])) {
                            $hasAnyHeaders = true;
                            echo "<dt class=\"col-sm-3\">Frame Options</dt><dd class=\"col-sm-9\">" . val_to_string($headers["X-Frame-Options"]) . "</dd>";
                        }
                        if (isset($headers["X-Xss-Protection"])) {
                            $hasAnyHeaders = true;
                            echo "<dt class=\"col-sm-3\">XSS Protection</dt><dd class=\"col-sm-9\">" . val_to_string($headers["X-Xss-Protection"]) . "</dd>";
                        }
                        if (isset($headers["X-Content-Type-Options"])) {
                            $hasAnyHeaders = true;
                            echo "<dt class=\"col-sm-3\">Content Type Options</dt><dd class=\"col-sm-9\">" . val_to_string($headers["X-Content-Type-Options"]) . "</dd>";
                        }
                        if (!$hasAnyHeaders) {
                            echo "<dt class=\"col-sm-3\"></dt><dd class=\"col-sm-9\">No security related headers found</dd>";
                        }
                        ?>
                    </dl>
                </div>

                <h2 class="display-5 mt-5 bd-group-title">SSL/TLS Certificate</h2>
                <?php

                if ($ssl) {
                    /* CN=mariani.life
C=US, ST=TX, L=Houston, O=cPanel, Inc., CN=cPanel, Inc. Certification Authority
85a9a991b9ff002277b1c017c6c884e39267bfe9d7b39575d6e923b68bae6453
Trusted Leaf Certificate
parsed.names: mariani.life
parsed.extensions.subject_alt_name.dns_names: mariani.life*/
                    $cert = openssl_x509_parse($ssl);
                    $pub_key_raw = openssl_pkey_get_public($ssl);
                    $pub_key = openssl_pkey_get_details($pub_key_raw);
                    $cert_interval = date_diff($date_now, date_create(gmdate("Y-m-d", $cert['validTo_time_t'])));
                    $cert_ttl = seconds_to_time($cert_interval->format('%a') * 86400);
                    $pub_key_bin = base64_decode($pub_key['key']);
                    $pub_key_type = '';
                    switch ($pub_key['type']) {
                        case 0:
                            $pub_key_type = 'RSA';
                            break;
                        case 1:
                            $pub_key_type = 'DSA';
                            break;
                        case 2:
                            $pub_key_type = 'Diffie-Hellman';
                            break;
                        case 3:
                            $pub_key_type = 'Elliptic Curve';
                            break;
                    }

                    //https://github.com/Wikinaut/MySimpleCertificateViewer/blob/master/index.php
                    // Decode the certificate to get fingerprints.
                    $cert_raw = '';
                    openssl_x509_export($ssl, $cert_raw);
                    $cleanedCert = preg_replace('/\-+(BEGIN|END) CERTIFICATE\-+/', '', $cert_raw);
                    $cleanedCert = str_replace(array("\n\r", "\n", "\r"), '', trim($cleanedCert));
                    $decCert = base64_decode($cleanedCert);
                    $sha1_fingerprint = hash('sha1', $decCert);
                    $md5_fingerprint = hash('md5', $decCert);
                    $sha256_fingerprint = hash('sha256', $decCert);

                    // https://stackoverflow.com/questions/54779875/how-to-get-ssl-certificate-hash-algorithm-oid-using-phps-openssl-x509-parse
                    $cert_version = 1;
                    switch ($cert['version']) {
                        case 1:
                            $cert_version = 2;
                        case 2:
                            $cert_version = 3;
                    }

                    $alt_names = explode(', ', $cert['extensions']['subjectAltName']);
                    function strip_dns($name)
                    {
                        return str_replace('DNS:', '', $name);
                    }
                    $alt_names = array_map('strip_dns', $alt_names);
                ?>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Subject Name</h3>
                        <dl class="row">
                            <?php if (isset($cert['subject']['C'])) { ?>
                                <dt class="col-sm-3">Country</dt>
                                <dd class="col-sm-9"><?= $cert['subject']['C'] ?></dd>
                            <?php } ?>

                            <?php if (isset($cert['subject']['ST'])) { ?>
                                <dt class="col-sm-3">State/Province</dt>
                                <dd class="col-sm-9"><?= $cert['subject']['ST'] ?></dd>
                            <?php } ?>

                            <?php if (isset($cert['subject']['L'])) { ?>
                                <dt class="col-sm-3">Locality</dt>
                                <dd class="col-sm-9"><?= $cert['subject']['L'] ?></dd>
                            <?php } ?>

                            <?php if (isset($cert['subject']['O'])) { ?>
                                <dt class="col-sm-3">Organization</dt>
                                <dd class="col-sm-9"><?= $cert['subject']['O'] ?></dd>
                            <?php } ?>

                            <dt class="col-sm-3">Common Name</dt>
                            <dd class="col-sm-9"><?= $cert['subject']['CN'] ?></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Issuer Name</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Country</dt>
                            <dd class="col-sm-9"><?= val_to_string($cert['issuer']['C']) ?></dd>

                            <?php if (isset($cert['issuer']['O'])) { ?>
                                <dt class="col-sm-3">Organization</dt>
                                <dd class="col-sm-9"><?= val_to_string($cert['issuer']['O']) ?></dd>
                            <?php } ?>

                            <?php if (isset($cert['issuer']['OU'])) { ?>
                                <dt class="col-sm-3">Organizational Unit</dt>
                                <dd class="col-sm-9"><?= val_to_string($cert['issuer']['OU']) ?></dd>
                            <?php } ?>

                            <dt class="col-sm-3">Common Name</dt>
                            <dd class="col-sm-9"><?= $cert['issuer']['CN'] ?></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Validity</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Valid From</dt>
                            <dd class="col-sm-9"><?= gmdate("D, d M Y H:i:s", $cert['validFrom_time_t']) ?> GMT</dd>

                            <dt class="col-sm-3">Valid Until</dt>
                            <dd class="col-sm-9"><?= gmdate("D, d M Y H:i:s", $cert['validTo_time_t']) ?> GMT</dd>

                            <dt class="col-sm-3">Expires in</dt>
                            <dd class="col-sm-9"><?= $cert_ttl ?></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Subject Alt Names</h3>
                        <dl class="row">
                            <?php
                            foreach ($alt_names as $alt_name) {
                                echo "<dt class=\"col-sm-3\">DNS Name</dt>";
                                echo "<dd class=\"col-sm-9\">{$alt_name}</dd>";
                            }
                            ?>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Public Key Info</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Algorithm</dt>
                            <dd class="col-sm-9"><?= $pub_key_type ?></dd>

                            <dt class="col-sm-3">Key Size</dt>
                            <dd class="col-sm-9"><?= $pub_key['bits'] ?> Bits</dd>

                            <!--<dt class="col-sm-3">Public Value</dt>
                            <dd class="col-sm-9"><code><?= addColonSeparators(bin2hex($pub_key_bin)) ?></code></dd>-->

                            <dt class="col-sm-3">Raw Public Value</dt>
                            <dd class="col-sm-9">
                                <div class="bd-code-snippet">
                                    <div class="highlight">
                                        <pre><?= $pub_key['key'] ?></pre>
                                    </div>
                                </div>
                            </dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Miscellaneous</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Serial Number</dt>
                            <dd class="col-sm-9"><code><?= addColonSeparators(bcdechex($cert['serialNumber'])) ?></code></dd>
                            <?php //<dd class="col-sm-9"> $cert['serialNumber'] ></dd>
                            ?>

                            <dt class="col-sm-3">Signature Algorithm</dt>
                            <dd class="col-sm-9"><?= $cert['signatureTypeSN'] ?></dd>

                            <dt class="col-sm-3">Version</dt>
                            <dd class="col-sm-9"><?= $cert_version ?></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Fingerprints</h3>
                        <dl class="row">
                            <dt class="col-sm-3">SHA-256</dt>
                            <dd class="col-sm-9"><code><?= addColonSeparators($sha256_fingerprint) ?></code></dd>

                            <dt class="col-sm-3">SHA-1</dt>
                            <dd class="col-sm-9"><code><?= addColonSeparators($sha1_fingerprint) ?></code></dd>

                            <dt class="col-sm-3">MD5</dt>
                            <dd class="col-sm-9"><code><?= addColonSeparators($md5_fingerprint) ?></code></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Key Usages</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Purposes</dt>
                            <dd class="col-sm-9"><?= $cert['extensions']['keyUsage'] ?></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Extended Key Usages</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Purposes</dt>
                            <dd class="col-sm-9"><?= $cert['extensions']['extendedKeyUsage'] ?></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Subject Key ID</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Key ID</dt>
                            <dd class="col-sm-9"><code><?= $cert['extensions']['subjectKeyIdentifier'] ?></code></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Authority Key ID</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Key ID</dt>
                            <dd class="col-sm-9"><code><?= str_replace('keyid:', '', $cert['extensions']['authorityKeyIdentifier']) ?></code></dd>
                        </dl>
                    </div>

                    <div class="bd-group row">
                        <h3 class="bg-group-section-title col-sm-3">Certificate</h3>
                        <dl class="row">
                            <dt class="col-sm-3">Raw Certificate</dt>
                            <dd class="col-sm-9">
                                <div class="bd-code-snippet">
                                    <div class="highlight">
                                        <pre><?= $cert_raw ?></pre>
                                    </div>
                                </div>
                            </dd>
                        </dl>
                    </div>
                <?php
                } else {
                    echo '<div class="bd-group row"><dl class="row">';
                    echo "<dt class=\"col-sm-3\"></dt><dd class=\"col-sm-9\">No SSL/TLS certificate found</dd>";
                    echo '</dl></div>';
                }
                ?>
            </section>

            <section id="email-tab-pane" class="tab-pane fade" role="tabpanel" aria-labelledby="email-tab" tabindex="0">
                <h2 class="display-5 mt-5 bd-group-title"><abbr title="Sender Policy Framework">SPF</abbr> Records</h2>
                <div class="bd-group row">
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
                </div>

                <h2 class="display-5 mt-5 bd-group-title"><abbr title="DomainKeys Identified Mail">DKIM</abbr> Records</h2>

                <div class="bd-group row">
                    <p><em>Checks selectors: 'default' (cPanel), 'x' (MXRoute), 'smtp' (Mailgun), 'hs1, hs2' (HubSpot), 's1, s2, m1, smtpapi' (SendGrid), 'k1, k2, k3' (MailChimp), 'google, ga1' (Google), 'cm' (Campaign Monitor), 'selector1' & 'selector2' (Microsoft 365), 'turbo-smtp' (TurboSMTP)</em></p>
                    <dl class="row">
                        <?php
                        // https://protodave.com/tools/dkim-key-checker/
                        if ($dkim_records) {
                            foreach ($dkim_records as $dkim) {
                                $alert = ($dkim['key_bits'] < 1024) ? ' INSECURE (<1024)' : '';
                                if (isset($dkim['cname'])) $cname = " <abbr title='CNAME'>&rarr; {$dkim['cname']}</abbr>";
                                echo "<dt class=\"col-sm-3\">Selector</dt>";
                                echo "<dd class=\"col-sm-9\">{$dkim['host']}{$cname}</dd>";

                                echo "<dt class=\"col-sm-3\">Key Size</dt>";
                                echo "<dd class=\"col-sm-9\">{$dkim['key_bits']}{$alert} Bits</dd>";

                                if (isset($dkim['v'])) {
                                    echo "<dt class=\"col-sm-3\">Version</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dkim['v']}</dd>";
                                }

                                if (isset($dkim['g'])) {
                                    echo "<dt class=\"col-sm-3\">Key Granularity</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dkim['g']}</dd>";
                                }

                                if (isset($dkim['h'])) {
                                    echo "<dt class=\"col-sm-3\">Hash Algorithm</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dkim['h']}</dd>";
                                }

                                if (isset($dkim['k'])) {
                                    echo "<dt class=\"col-sm-3\">Key Type</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dkim['k']}</dd>";
                                }

                                if (isset($dkim['n'])) {
                                    echo "<dt class=\"col-sm-3\">Notes</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dkim['n']}</dd>";
                                }

                                // if (isset($dkim['p'])) {
                                //     echo "<dt class=\"col-sm-3\">Public Key Data</dt>";
                                //     echo "<dd class=\"col-sm-9\">{$dkim['p']}</dd>";
                                // }

                                if (isset($dkim['s'])) {
                                    echo "<dt class=\"col-sm-3\">Service Type</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dkim['s']}</dd>";
                                }

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

                                    echo "<dt class=\"col-sm-3\">Flags</dt>";
                                    echo "<dd class=\"col-sm-9\">{$flagsLabel}</dd>";
                                }

                                echo "<dt class=\"col-sm-3\">Public Key</dt>";
                                echo "<dd class=\"col-sm-9\"><div class=\"bd-code-snippet\"><div class=\"highlight\"><pre>{$dkim['public_key']}{$alert}</pre></div></div></dd>";

                                echo "<dt class=\"col-sm-3\">Raw</dt>";
                                echo "<dd class=\"col-sm-9\"><div class=\"bd-code-snippet\"><div class=\"highlight\"><pre>{$dkim['raw']['txt']}</pre></div></div></dd>";
                            }
                        } else {
                            echo "<dt class=\"col-sm-3\"></dt><dd class=\"col-sm-9\">None</dd>";
                        }

                        ?>
                    </dl>
                </div>

                <h2 class="display-5 mt-5 bd-group-title"><abbr title="Domain-based Message Authentication, Reporting & Conformance">DMARC</abbr> Records</h2>
                <div class="bd-group row">
                    <dl class="row">
                        <?php
                        // https://protodave.com/tools/dkim-key-checker/
                        if ($dmarc_records) {
                            foreach ($dmarc_records as $dmarc) {
                                if (isset($dmarc['v'])) {
                                    echo "<dt class=\"col-sm-3\">Version</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['v']}</dd>";
                                }

                                if (isset($dmarc['pct'])) {
                                    echo "<dt class=\"col-sm-3\">Messages subject to filtering</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['pct']}</dd>";
                                }

                                if (isset($dmarc['rf'])) {
                                    echo "<dt class=\"col-sm-3\">Failure Reports</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['rf']}</dd>";
                                }

                                if (isset($dmarc['ri'])) {
                                    echo "<dt class=\"col-sm-3\">Interval between Aggregate Reports</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['ri']}</dd>";
                                }

                                if (isset($dmarc['ruf'])) {
                                    echo "<dt class=\"col-sm-3\">Send forensic reports to</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['ruf']}</dd>";
                                }

                                if (isset($dmarc['rua'])) {
                                    echo "<dt class=\"col-sm-3\">Send aggregate reports to</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['rua']}</dd>";
                                }

                                if (isset($dmarc['p'])) {
                                    echo "<dt class=\"col-sm-3\">Policy for domain</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['p']}</dd>";
                                }

                                if (isset($dmarc['sp'])) {
                                    echo "<dt class=\"col-sm-3\">Policy for subdomains</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['sp']}</dd>";
                                }

                                if (isset($dmarc['adkim'])) {
                                    echo "<dt class=\"col-sm-3\">Alignment mode for DKIM</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['adkim']}</dd>";
                                }

                                if (isset($dmarc['aspf'])) {
                                    echo "<dt class=\"col-sm-3\">Alignment mode for SPF</dt>";
                                    echo "<dd class=\"col-sm-9\">{$dmarc['aspf']}</dd>";
                                }
                            }
                        } else {
                            echo "<dt class=\"col-sm-3\"></dt><dd class=\"col-sm-9\">None</dd>";
                        }
                        ?>
                    </dl>
                </div>
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
            <script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-4393629565174725" crossorigin="anonymous"></script>
            <!-- DNS Lookup Footer -->
            <ins class="adsbygoogle" style="display:block" data-ad-client="ca-pub-4393629565174725" data-ad-slot="4188568892" data-ad-format="auto" data-full-width-responsive="true"></ins>
            <script>
                (adsbygoogle = window.adsbygoogle || []).push({});
            </script>
            <small class="mb-3 d-block mt-3">The records displayed may not be completely accurate due to the nature of how they were acquired. DNS does not allow access to all DNS records of a particular domain. Instead they must be requested by name. This website attempts many known combinations but ultimately will never be 100% accurate.</small>
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
                                $js_servers = [];
                                // error_log(print_r($server_locations, true));
                                foreach ($server_locations as $location => $items) {
                                    $geoCoord = explode(',', $location);
                                    $title = [];
                                    $content = [];
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