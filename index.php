<?php
error_reporting(E_ALL ^ E_WARNING);

$host_cache = array();
$ip_cache = array();
$dns_cache = array();
$ipinfo_cache = array();
$ipinfo_count = 0;
$ipapi_count = 0;
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
        $result = dns_get_record($host, $type);
        // If the result for an A record lookup returns CNAME targets, ignore them
        // it just clutters up the results
        if (is_bool($result) || (count($result) > 0 && 1 === $type && $host !== $result[0]['host'])) {
            $result = [];
        }
        $dns_cache[$host][$type] = $result;
        $dns_count++;
    }

    return $dns_cache[$host][$type];
}

function get_clean_domain($url)
{
    if (strlen($url) <= 0) die("get_clean_domain - Invalid URL passed");

    if (substr($url, 0, 4) === 'http') {
        $parts = parse_url($url);
        return $parts['host'];
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

function get_whois($domain, $verified = false)
{
    global $errors;

    $tld = get_tld($domain);
    $debug = false;

    // http://www.iana.org/domains/root/db
    $whois_servers = array(
        '.org' => "whois.pir.org",
        '.info' => "whois.afilias.net",
        '.buzz' => "whois.nic.buzz",
        '.edu' => "whois.educause.edu",
        '.li' => "whois.nic.li",
        '.io' => "whois.nic.io",
        '.ni' => "whois.nic.io",
        '.services' => "whois.donuts.co",
        '.life' => "whois.donuts.co",
        '.today' => "whois.donuts.co",
        '.biz' => "whois.biz",
        '.us' => "whois.nic.us",
        '.uk' => "whois.nic.uk",
        '.co' => "whois.nic.co",
        '.work' => "whois.nic.work",
        '.net' => "whois.verisign-grs.com",
        //'.net' => "whois.networksolutions.com",
        '.com' => "whois.verisign-grs.com",
        //'.com' => "whois.networksolutions.com",
        //'.com' => "whois.godaddy.com",
        // '.com' => 'whois.google.com',
        '.stream' => "whois.nic.stream"
    ); // whois.godaddy.com

    // Open a Socket connection to our WHOIS server
    if ($verified !== false) {
        if ($debug) $errors[] = "WhoIs: " . $verified;
        $fp = fsockopen($verified, 43, $errno, $errstr, 10);
    } elseif (isset($whois_servers[$tld])) {
        if ($debug) $errors[] = "WhoIs: " . $whois_servers[$tld];
        $fp = fsockopen($whois_servers[$tld], 43, $errno, $errstr, 10);
    } else {
        $errors[] = "WhoIs: " . $tld . ' not found';
        return '';
    }

    // Connection refused
    if (!$fp) {
        $errstr = str_replace(array("\r", "\n"), "", $errstr);
        $errors[] = "WhoIs: $errstr ($errno)";
        return '';
    }

    // The data we're sending
    if (($tld === '.com' || $tld === '.net') && !$verified) {
        // SO far only verisign uses this command, others fail to work
        $out = "={$domain}\r\n";
    } else {
        /*
		This domain cannot be registered because it contravenes the Nominet UK naming rules.
		The reason is: Domain names may only comprise the characters A-Z, a-z, 0-9, hyphen (-) and dot (.)..
		*/
        $out = "{$domain}\r\n";
    }
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

    if (!$verified) {
        $whois_truncated = $whois;

        // To clean up multiple matches on sites like google.com or yahoo.com
        if (
            preg_match_all("/^\s*Aborting search/m", $whois, $matches) == true ||
            substr_count($whois, 'Server Name') > 1
        ) {
            $whois_truncated = substr($whois, strpos($whois, 'Domain Name:'));
        }

        // PUll whois server url and ask that whois server
        $whois_server = get_whois_server($whois_truncated, $whois_servers[$tld]);
        if ($whois_server) {
            if ($debug) $errors[] = "WhoIs: <pre>" . print_r($whois, true) . '</pre>';
            $whois = get_whois($domain, $whois_server);
        }
    }

    return $whois;
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

function get_whois_server($whois, $used)
{
    $result = false;

    // Verisign
    if (preg_match_all("/^\s*Whois Server: (.+)$/m", $whois, $matches) == true) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Registrar WHOIS Server (.+)$/m", $whois, $matches) == true) {
        $result = $matches[1][0];
    }

    if ($result === $used) return false;
    return $result;
}

function get_expiration($whois)
{
    $line_breaks = array("\r", "\n");
    $result = 'Unknown';

    if (preg_match_all("/^\s*Registry Expiry Date: (.+)$/m", $whois, $matches) == true) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Expiration Date: (.+)$/m", $whois, $matches) == true) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Domain expires: (.+)$/m", $whois, $matches) == true) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Domain Expiration Date: (.+)$/m", $whois, $matches) == true) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Registrar Registration Expiration Date: (.+)$/m", $whois, $matches) == true) {
        $result = $matches[1][0];
    }

    if (preg_match_all("/^\s*Expiry date: (.+)$/m", $whois, $matches) == true) {
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

    if (preg_match_all("/^\s*Registrant Name: (.+)$/m", $whois, $matches) == true) {
        $result = $name = $matches[1][0];
    }

    // UK format
    // Registrant:
    //     C Henson
    if ($name === 'Unknown' && preg_match_all("/^\s+Registrant:\r\n\s+([^\r\n]+)\r\n/m", $whois, $matches) == true) {
        $result = $name = $matches[1][0];
    }

    if (preg_match_all("/^\s*Registrant Email: (.+)$/m", $whois, $matches) == true) {
        $result = '<a href="mailto:' . $matches[1][0] . '" >' . $name . '</a>';
    }

    return $result;
}

function get_dnssec($whois)
{
    if (preg_match_all("/^\s*DNSSEC: (.+)$/m", $whois, $matches) == true) {
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
        if (strpos($record['txt'], 'v=spf') !== false) {
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
    $records = get_dns_record($host, DNS_TXT);

    if ($records === false) {
        return false;
    }

    $dkim = false;
    foreach ($records as $record) {
        if (isset($record['entries'])) $record['txt'] = implode('', $record['entries']);

        if (strpos($record['txt'], 'v=DKIM') !== false) {
            if ($dkim === false) $dkim = array();
            $result = array();
            $result['host'] = $host;
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
            $result['key_bits'] = $key['bits'];
            // If RSA http://php.net/manual/en/function.openssl-pkey-get-details.php
            //$result['key_modulus'] = $key['n'];
            //$result['key_public_exponent'] = $key['e'];
            $dkim[] = $result;
        }
    }

    return $dkim;
}

function get_dkim($domain)
{
    $dkims = [
        get_dkim_single('default', $domain),
        get_dkim_single('google', $domain),
        get_dkim_single('selector1', $domain),
        get_dkim_single('selector2', $domain),
        get_dkim_single('smtp', $domain),
        get_dkim_single('k2', $domain),
        get_dkim_single('k3', $domain),
        get_dkim_single('s1', $domain),
        get_dkim_single('s2', $domain),
        get_dkim_single('x', $domain),
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
    $res = false;
    $stream = @stream_context_create(array('ssl' => array('capture_peer_cert' => true)));
    $socket = @stream_socket_client('ssl://' . $domain . ':443', $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $stream);

    // If we got a ssl certificate we check here, if the certificate domain
    // matches the website domain.
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
    }

    return $res;
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

// Free usage of our API is limited to 1,000 API requests per day. If you exceed 1,000 requests in a 24 hour period we'll return a 429 HTTP status code to you.
function get_location($ip)
{
    global $ipinfo_cache, $ipinfo_count, $ipapi_count, $errors;

    // Invalid IP
    if (false === $ip) return false;

    // Return cached value
    if (isset($ipinfo_cache[$ip])) {
        return $ipinfo_cache[$ip];
    }

    $ipinfo_url = "http://ip-api.com/json/{$ip}";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $ipinfo_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15); //timeout in seconds
    $result = curl_exec($ch);

    $ipapi_count++;
    curl_close($ch);
    // error_log($result);
    $json_result = json_decode($result);
    if ($json_result->status === 'fail') {
        /*echo '<pre>';
		var_dump($result);
		echo '</pre>';*/
        $errors[] = "GeoLocate: Error<br><pre>" . print_r($result, true) . '</pre>';
        error_log("GeoLocate: Error - " . print_r($result, true));
        return false;
    } else {
        $json_result->ip = $json_result->query;
        $json_result->loc = $json_result->lat . ',' . $json_result->lon;
        $json_result->hostname = get_host_by_ip($ip); //'Unknown (' . $json_result->isp . ')';
    }

    /*$ipinfo_url = "http://ipinfo.io/{$ip}/json";
	//$load = file_get_contents( $ipinfo_url );
	$ch = curl_init();
	curl_setopt( $ch, CURLOPT_URL, $ipinfo_url );
	curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
	$result = curl_exec( $ch );
	$ipinfo_count++;
	curl_close( $ch );*/

    // ipinfo.io rate limit
    if (strpos($result, 'Rate limit exceeded') !== false) {
        $ipinfo_url = "http://ip-api.com/json/{$ip}";
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $ipinfo_url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
        curl_setopt($ch, CURLOPT_TIMEOUT, 15); //timeout in seconds
        $result = curl_exec($ch);
        $ipapi_count++;
        curl_close($ch);
        // error_log($result);
        $json_result = json_decode($result);
        $json_result->loc = $json_result->lat . ',' . $json_result->lon;
        $json_result->hostname = get_host_by_ip($ip); //'Unknown (' . $json_result->isp . ')';
    } else {
        //$json_result = json_decode( $result );
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
    $year = floor($seconds / 3.154e+7);
    $day = floor($seconds / 86400 % 365.2422);
    $hours = floor($seconds / 3600 % 24);
    $mins = floor($seconds / 60 % 60);
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
$domain = isset($_GET['q']) ? trim($_GET['q']) : 'google.com';
//$domain ='boroughs.org';
$line_breaks = array("\r", "\n");
$domain = get_clean_domain($domain);
$root_domain = get_root_domain($domain);
$is_root_domain = $domain === $root_domain ? true : false;
$whois = get_whois($root_domain);
$ip = get_host_by_name($domain);
$location = get_location($ip);
$ssl = has_ssl($domain);
$http = $ssl ? 'https://' : 'http://';
$headers = get_headers($http . $domain, 1);
// Follow one redirect to account for WWW vs non-WWW
if ($headers && $headers[0] === 'HTTP/1.1 301 Moved Permanently') {
    $headers = get_headers($headers['Location'], 1);
}

$geo = $location ? explode(',', $location->loc) : array(0, 0);
$now = time();
$date_now = new DateTime();
$date_now->setTimestamp($now);

function get_location_address($location)
{
    if (false === $location) return 'API Rate Limit';

    $address = '';
    if (strlen($location->country) > 0) {
        $address = $location->country;
    }
    if (strlen($location->region) > 0) {
        $address = $location->region . ' ' . $address;
    }
    if (strlen($location->city) > 0) {
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

// New servers are set to deny DNS_ALL and DNS_ANY
//$dns_records = get_dns_record( $domain, DNS_ALL );
$dns_records = array(
    'a' => get_dns_record($domain, DNS_A),
    'cname' => get_dns_record($domain, DNS_CNAME),
    //'hinfo' => get_dns_record( $domain, DNS_HINFO ),
    //'caa' => get_dns_record( $domain, DNS_CAA ), // PHP 7.1.0+
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
        '_dmarc', 'dev', 'staging', 'stagingwww', 'calendar', 'email', 'fax', 'files', 'imap', 'pop', 'smtp', 'mobileemail',
        'remote', 'course', 'blog', 'server', 'ns1', 'ns2', 'secure', 'vpn', 'm', 'shop', 'test', 'portal', 'host',
        'ww1', 'support', 'web', 'bbs', 'mx', 'cloud', 'forum', 'owa', 'www2', 'admin', 'cdn', 'api', 'app',
        'exchange', 'gov', 'news', 'vps', 'ns', 'mail2', 'mx0', 'mx1', 'mailserver', 'server', 'r.1', 'r.2', 'r.3',
        'spam', 'auth', 'sso', 'webapps', 'securemail', 'online', 'signin', 'account', 'myonline', 'myaccount'
    ];
    // sanity check
    $default_subdomains = array_unique($default_subdomains);

    // Check A record wildcard
    $wildcard_record = get_dns_record("mariani-is-cool.${domain}", DNS_A);
    $is_wildcard = count($wildcard_record) > 0 ? true : false;
    if ($is_wildcard) {
	$wildcard_record[0]['host'] = "*.${domain}";
        $dns_records['a'] = array_merge_unique($dns_records['a'], $wildcard_record);
    }

    // Common subdomains to test/guess
    foreach ($default_subdomains as $subdomain) {
        $a_record = get_dns_record("${subdomain}.${domain}", DNS_A);
        if (isset($a_record[0])) {
            if ($is_wildcard) {
                if ($a_record[0]['ip'] !== $wildcard_record[0]['ip']) {
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
    $autodiscover = get_dns_record('autodiscover.' . $domain, DNS_A);
    if ($autodiscover && strpos($autodiscover[0]['host'], 'autodiscover.' . $domain) !== false) {
        $a_record = get_dns_record('autodiscover.' . $domain, DNS_A);
        if (isset($a_record[0])) {
            if ($is_wildcard) {
                if ($a_record[0]['ip'] != $wildcard_record[0]['ip']) {
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

    // Check CNAME record wildcard
    $wildcard_record = get_dns_record("mariani-is-cool.${domain}", DNS_CNAME);
    $is_wildcard = count($wildcard_record) > 0 ? true : false;
    if ($is_wildcard) {
        $wildcard_record[0]['host'] = "*.${domain}";
        $dns_records['cname'] = array_merge_unique($dns_records['cname'], $wildcard_record);
    }

    // foreach ($default_subdomains as $subdomain) {
    //     $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record("${subdomain}.${domain}", DNS_CNAME));
    // }
    // Common subdomains to test/guess
    foreach ($default_subdomains as $subdomain) {
        $cname_record = get_dns_record("${subdomain}.${domain}", DNS_CNAME);
        if (isset($cname_record[0])) {
            if ($is_wildcard) {
                if ($cname_record[0]['target'] !== $wildcard_record[0]['target']) {
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

    // If this is a c_name, it will return a lot of junk we don't want, so we check if it's related to the domain
    $autodiscover = get_dns_record('autodiscover.' . $domain, DNS_CNAME);
    if ($autodiscover && strpos($autodiscover[0]['host'], 'autodiscover.' . $domain) !== false) {
        if ($is_wildcard) {
            if ($cname_record[0]['target'] !== $wildcard_record[0]['target']) {
                $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('autodiscover.' . $domain, DNS_CNAME));
            }
        } else {
            $dns_records['cname'] = array_merge_unique($dns_records['cname'], get_dns_record('autodiscover.' . $domain, DNS_CNAME));
        }
    }

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
    // MS 365
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('selector1._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('selector2._domainkey.' . $domain, DNS_TXT));
    // Mailchimp
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('k2._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('k3._domainkey.' . $domain, DNS_TXT));
    // MXRoute
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('x._domainkey.' . $domain, DNS_TXT));
    // Mailgun
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('smtp._domainkey.' . $domain, DNS_TXT));
    // SendGrid
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('s1._domainkey.' . $domain, DNS_TXT));
    $dns_records['txt'] = array_merge_unique($dns_records['txt'], get_dns_record('s2._domainkey.' . $domain, DNS_TXT));
}

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

$spf_records = get_spf($dns_records['txt']);

$dkim_records = get_dkim($domain);
// error_log(print_r($dkim_records, true));
$dns_records['dkim'] = array();
foreach ($dkim_records as $dkim) {
    $dns_records['dkim'][] = $dkim['raw'];
}

$dmarc_records = get_dmarc($domain);
$dns_records['dmarc'] = array();
foreach ($dmarc_records as $dmarc) {
    $dns_records['dmarc'][] = $dmarc['raw'];
}

$arin = get_arin($ip);

$domain_data = array(
    'registrar' => get_registrar($whois),
    'expiration' => get_expiration($whois),
    'contact' => get_contact($whois),
    'dnssec' => get_dnssec($whois),
    'nameservers' => get_nameservers($whois)
);

function translate_org($org)
{
    $lower_org = strtolower($org);
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
    }
    return !empty($org) ? $org : 'Unknown/Self';
}

?>
<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Domain Inspector</title>
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
            -webkit-font-smoothing: antialiased;
            -moz-font-smoothing: antialiased;
            -o-font-smoothing: antialiased;
            font-smoothing: antialiased;
            text-rendering: optimizeLegibility;
            background-color: #363636;
            color: #dedede;
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
            background-color: #f9f9f9;
            border: 1px solid #333;
            margin-top: 1rem;
            padding: 1rem;
            -moz-tab-size: 4;
            tab-size: 4;
            overflow-x: auto;
            border-radius: 3px;
            color: #333;
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
            color: #0076B8;
            webkit-transition: opacity 1s linear;
            moz-transition: opacity 1s linear;
            o-transition: opacity 1s linear;
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
            padding-top: 1rem;
            background-color: #F1F1F1;
            padding-bottom: 1rem;
            margin-bottom: 1rem;
            border-bottom: 1px solid #e5e5e5;
            display: flex;
            align-content: center;
            justify-content: center;
            width: 100%;
        }

        .search-bar form {
            width: 100%;
            max-width: 1170px;
            display: flex;
        }

        .search-bar input {
            display: flex;
            flex: 1;
            margin-right: 0.3rem;

            height: 34px;
            padding: 6px 12px;
            font-size: 0.8rem;
            line-height: 1.42857143;
            color: #555;
            background-color: #fff;
            background-image: none;
            border: 1px solid #ccc;
            border-radius: 4px;
            -webkit-box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
            box-shadow: inset 0 1px 1px rgba(0, 0, 0, .075);
            -webkit-transition: border-color ease-in-out .15s, -webkit-box-shadow ease-in-out .15s;
            -o-transition: border-color ease-in-out .15s, box-shadow ease-in-out .15s;
            transition: border-color ease-in-out .15s, box-shadow ease-in-out .15s;
        }

        .records {}

        .records td,
        .records th,
        .records__col {
            padding: 0.3rem 0.7rem;
        }

        .records tr:nth-child(odd),
        .records__row:nth-child(odd) {
            /*background: #CCC;*/
        }

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

        .spf-fail {
            color: #ec4848;
        }

        .spf-softfail {
            color: #ecd948;
        }

        .spf-neutral {}

        .spf-pass {
            color: #48ec61;
        }

        /**
			 * Tooltip Styles
			 */

        /* Add this attribute to the element that needs a tooltip */
        [data-tooltip] {
            position: relative;
            z-index: 2;
            cursor: pointer;
        }

        /* Hide the tooltip content by default */
        [data-tooltip]:before,
        [data-tooltip]:after {
            visibility: hidden;
            -ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=0)";
            filter: progid: DXImageTransform.Microsoft.Alpha(Opacity=0);
            opacity: 0;
            pointer-events: none;
        }

        /* Position tooltip above the element */
        [data-tooltip]:before {
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
            content: attr(data-tooltip);
            text-align: center;
            font-size: 14px;
            line-height: 1.2;
            white-space: pre;
        }

        /* Triangle hack to make tooltip look like a speech bubble */
        [data-tooltip]:after {
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

        /* Show tooltip content on hover */
        [data-tooltip]:hover:before,
        [data-tooltip]:hover:after {
            visibility: visible;
            -ms-filter: "progid:DXImageTransform.Microsoft.Alpha(Opacity=100)";
            filter: progid: DXImageTransform.Microsoft.Alpha(Opacity=100);
            opacity: 1;
        }
    </style>
</head>

<body>
    <header class="search-bar">
        <form method="get" id="search" action="">
            <input placeholder="Search" name="q" id="q" value="" type="text">
            <button>Search</button>
        </form>
    </header>
    <main>
        <nav>
            <ul class="tabs">
                <li class="tabs__tab tabs__tab--active" data-tab="host">General</li>
                <li class="tabs__tab" data-tab="certificates">Security</li>
                <li class="tabs__tab" data-tab="email">Email</li>
                <li class="tabs__tab" data-tab="map">View on Map</li>
                <li class="tabs__tab" data-tab="whois">WhoIs</li>
            </ul>
        </nav>

        <h1><?php echo $domain; ?></h1>

        <?php
        if (count($errors) > 0) {
            echo '<pre>';
            echo implode('<br>', $errors);
            echo '</pre>';
        }
        ?>
        <section id="host" class="tab-content tab-content--active">
            <div class="row">
                <div class="col" style="padding-right:30px;">
                    <?php
                    $domain_interval = date_diff($date_now, date_create(to_date_format($domain_data['expiration'])));
                    $domain_ttl = $domain_interval ? ' (' . seconds_to_time($domain_interval->format('%a') * 86400) . ')' : '';
                    $domain_expiration_datetime = strtotime($domain_data['expiration']);
                    $domain_expiration = $domain_data['expiration'] !== 'Unknown' ?
                        to_date_format($domain_data['expiration']) . ($domain_expiration_datetime < $now ? ' <span class="error">Expired</span>' : '')
                        : $domain_data['expiration'];
                    ?>
                    <h2>General</h2>
                    <table class="values-list">
                        <tr>
                            <th width="200px">Server IP</th>
                            <td><?php echo $ip; ?></td>
                        </tr>
                        <tr>
                            <th>Server Location</th>
                            <td><?php echo get_location_address($location); ?></td>
                        </tr>
                        <tr>
                            <th>Host (via Arin)</th>
                            <td><?php echo ($arin['customer_name'] ?? 'Unknown Customer Name') . ' (<a href="' . ($arin['customer_link'] ?? '#') . '" target="_blank">' . ($arin['customer_handle'] ?? 'Unknown Customer Handle') . '</a>)'; ?></td>
                        </tr>
                        <tr>
                            <th>Host Net Blocks</th>
                            <td>
                                <table style="margin-top: 0;">
                                    <?php
                                    // Trying to access array offset on value of type bool on line 1667
                                    if (is_array($arin) === true) {
                                        foreach ($arin['net_block'] as $key => $netblock) {
                                            echo '<tr><td>' . $netblock['start_address'] . '-' . $netblock['end_address'] . '</td><td>(' . $netblock['start_address'] . '/' . $netblock['cidr_length'] . ')</td></tr>';
                                        }
                                    }
                                    ?>
                                </table>
                            </td>
                        </tr>
                        <tr>
                            <th>Domain Expiration Date</th>
                            <td><?php echo $domain_expiration . $domain_ttl; ?></td>
                        </tr>
                        <tr>
                            <th>Domain Contact</th>
                            <td><?php echo $domain_data['contact']; ?></td>
                        </tr>
                        <tr>
                            <th>&nbsp;</th>
                            <td>&nbsp;</td>
                        </tr>
                        <tr>
                            <th>Domain Registrar</th>
                            <td><?php
                                echo $domain_data['registrar'];
                                ?></td>
                        </tr>
                        <tr>
                            <th>Name Server Provider</th>
                            <td><?php
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
                                ?></td>
                        </tr>
                        <tr>
                            <th>Hosting Provider</th>
                            <td><?php
                                foreach ($dns_records['a'] as $record) {
                                    $ip = $record['ip'];
                                    $ip_info = get_location($ip);
                                    echo $ip_info ? translate_org($ip_info->org) : 'API Rate Limit';
                                    break;
                                }
                                ?></td>
                        </tr>
                        <tr>
                            <th>Email Provider</th>
                            <td><?php
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
                                            $email_host['mail'] = $ip_info ? translate_org($ip_info->org) : 'API Rate Limit';
                                        }
                                        // override mail.
                                        if (preg_match("/^autodiscover\./i", $uri)) {
                                            //echo $uri . ' a <br>';
                                            $email_host['mail'] = $ip_info ? translate_org($ip_info->org) : 'API Rate Limit';
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
                                                $email_host['mail'] = $ip_info ? translate_org($ip_info->org) : 'API Rate Limit';
                                            }
                                        }

                                        // override mail.
                                        if (preg_match("/^autodiscover\./i", $uri)) {
                                            //echo $uri . ' cname<br>';
                                            if (strpos($record['target'], 'autodiscover.outlook.com') !== false) {
                                                $email_host['mail'] = 'Microsoft 365';
                                            } else {
                                                $email_host['mail'] = $ip_info ? translate_org($ip_info->org) : 'API Rate Limit';
                                            }
                                        }
                                    }
                                    if (count($email_host) > 0) echo ' (via ' . implode(' ', $email_host) . ')';
                                }
                                ?></td>
                        </tr>
                        <tr>
                            <th>&nbsp;</th>
                            <td>&nbsp;</td>
                        </tr>
                        <?php
                        if (isset($headers["Server"])) {
                            echo "<tr><th width=250>Server Software</th><td >" . val_to_string($headers["Server"]) . "</td></tr>";
                        }
                        if (isset($headers["X-Powered-By"])) {
                            echo "<tr><th width=250>Powered By</th><td >{$headers["X-Powered-By"]}</td></tr>";
                        }
                        if (isset($headers["X-Amz-Cf-Id"])) {
                            echo "<tr><th width=250>Uses CloudFront</th><td >True</td></tr>";
                        }
                        ?>
                    </table>
                </div>
                <div class="col-third">
                    <div id="map_single" class="google-map" style="height:100%;"></div>
                </div>
            </div>
            <div class="row">
                <div class="col">
                    <h2>DNS</h2>
                    <table class="records">
                        <?php
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
                        foreach ($dns_records['soa'] as $record) {
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Start of [a zone of] authority"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Primary nameserver"><?php echo $record['mname']; ?></td>
                                <td data-tooltip="Hostmaster E-mail address"><?php echo $record['rname']; ?></td>
                                <td data-tooltip="Serial #"><?php echo $record['serial']; ?></td>
                                <td data-tooltip="Refresh - <?php echo seconds_to_time($record['refresh']); ?>"><?php echo $record['refresh']; ?></td>
                                <td data-tooltip="Retry - <?php echo seconds_to_time($record['retry']); ?>"><?php echo $record['retry']; ?></td>
                                <td data-tooltip="Expire - <?php echo seconds_to_time($record['expire']); ?>"><?php echo $record['expire']; ?></td>
                                <td data-tooltip="Default TTL - <?php echo seconds_to_time($record['minimum-ttl']); ?>"><?php echo $record['minimum-ttl']; ?></td>
                            </tr>
                        <?php
                        }

                        /*
							array(5) {
							  ["host"]=> "smartmgmt.com"
							  ["class"]=> "IN"
							  ["ttl"]=> int(3418)
							  ["type"]=> "NS"
							  ["target"]=> "ns10.domaincontrol.com"
							}
							*/
                        foreach ($dns_records['ns'] as $record) {
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
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Namer Server"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info->org; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $record['target']; ?></td>
                            </tr>
                        <?php
                        }

                        /*
							array(5) {
							  ["host"]=> "smartmgmt.com"
							  ["class"]=> "IN"
							  ["ttl"]=> int(3095)
							  ["type"]=>  "A"
							  ["ip"]=> "72.52.145.252"
							}
							*/
                        foreach ($dns_records['a'] as $record) {
                            $ip = $record['ip'];
                            $ip_info = get_location($ip);
                            if ($ip_info) {
                                if (isset($server_locations[$ip_info->loc])) {
                                    $server_locations[$ip_info->loc][] = array('type' => 'Web Server', 'info' => $ip_info);
                                } else {
                                    $server_locations[$ip_info->loc] = array(array('type' => 'Web Server', 'info' => $ip_info));
                                }
                            }
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Address"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Target - <?php echo $record['host']; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $ip; ?></td>
                            </tr>
                        <?php
                        }

                        foreach ($dns_records['aaaa'] as $record) {
                            $ip = $record['ipv6'];
                            $ip_info = get_location($ip);
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="IPv6 Address"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Target - <?php echo $record['host']; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $ip; ?></td>
                            </tr>
                        <?php
                        }

                        /*
							 array(5) {
								'host' => string(14) "www.cweiske.de"
								'class' => string(2) "IN"
								'ttl' => int(86400)
								'type' => string(5) "CNAME"
								'target' => string(10) "cweiske.de"
							  }
							*/
                        foreach ($dns_records['cname'] as $record) {
                            $ip = get_host_by_name($record['target']);
                            $ip_info = get_location($ip);
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Canonical Name"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="7"><?php echo $record['target']; ?></td>
                            </tr>
                        <?php
                        }

                        foreach ($dns_records['mx'] as $record) {
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
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Mail Exchange"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Priority"><?php echo $record['pri']; ?></td>
                                <td data-tooltip="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="6"><?php echo $record['target']; ?></td>
                            </tr>
                        <?php
                        }

                        foreach ($dns_records['txt'] as $record) {
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Text"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Value" colspan="7"><code><?php echo $record['txt']; ?></code></td>
                            </tr>
                        <?php
                        }

                        foreach ($dns_records['dmarc'] as $record) {
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Text"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Value" colspan="7"><code><?php echo $record['txt']; ?></code></td>
                            </tr>
                        <?php
                        }

                        /*foreach( $dns_records['hinfo'] as $record ) {
								?>
								<tr>
									<td data-tooltip="Host"><?php echo $record['host']; ?></td>
									<td data-tooltip="Internet"><?php echo $record['class']; ?></td>
									<td data-tooltip="TTL - <?php echo seconds_to_time( $record['ttl'] ); ?>"><?php echo $record['ttl']; ?></td>
									<td data-tooltip="Host Information"><?php echo $record['type']; ?></td>
									<td data-tooltip="Hardware"><?php echo $record['hardware']; ?></td>
									<td data-tooltip="OS" colspan="6"><?php echo $record['os']; ?></td>
								</tr>
								<?php
							}*/

                        foreach ($dns_records['srv'] as $record) {
                            $ip = get_host_by_name($record['target']);
                            $ip_info = get_location($ip);
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Service Location"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Priority"><?php echo $record['pri']; ?></td>
                                <td data-tooltip="Weight"><?php echo $record['weight']; ?></td>
                                <td data-tooltip="Port"><?php echo $record['port']; ?></td>
                                <td data-tooltip="Target - <?php echo $ip; ?>&#10;<?php echo $ip_info ? $ip_info->org : 'API Rate Limit'; ?>&#10;<?php echo get_location_address($ip_info); ?>" colspan="4"><?php echo $record['target']; ?></td>
                            </tr>
                        <?php
                        }

                        foreach ($dns_records['ptr'] as $record) {
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Pointer"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Value" colspan="7"><?php echo $record['txt']; ?></td>
                            </tr>
                        <?php
                        }

                        foreach ($dns_records['naptr'] as $record) {
                        ?>
                            <tr>
                                <td data-tooltip="Host"><?php echo $record['host']; ?></td>
                                <td data-tooltip="Internet"><?php echo $record['class']; ?></td>
                                <td data-tooltip="TTL - <?php echo seconds_to_time($record['ttl']); ?>"><?php echo $record['ttl']; ?></td>
                                <td data-tooltip="Naming Authority Pointer"><?php echo $record['type']; ?></td>
                                <td data-tooltip="Order"><?php echo $record['order']; ?></td>
                                <td data-tooltip="Preference"><?php echo $record['pref']; ?></td>
                                <td data-tooltip="Flags"><?php echo $record['flags']; ?></td>
                                <td data-tooltip="Service"><?php echo $record['services']; ?></td>
                                <td data-tooltip="Regexp"><?php echo $record['regex']; ?></td>
                                <td data-tooltip="Replacement"><?php echo $record['replacement']; ?></td>
                            </tr>
                        <?php
                        }
                        ?>
                    </table>
                </div>
            </div>
        </section>

        <section id="certificates" class="tab-content">

            <h2>DNS</h2>
            <table>
                <tr>
                    <th width=250>DNSSEC</th>
                    <td><?php echo $domain_data['dnssec']; ?></td>
                </tr>
            </table>

            <h2>Headers</h2>
            <table class="values-list">
                <?php
                if (isset($headers["Content-Security-Policy"])) {
                    echo "<tr><th width=250>Content Security Policy (CSP)</th><td ><code>" . val_to_string($headers["Content-Security-Policy"]) . "</code></td></tr>";
                }
                if (isset($headers["Content-Security-Policy-Report-Only"])) {
                    echo "<tr><th width=250>Content Security Policy (CSP) Report Only</th><td ><code>" . val_to_string($headers["Content-Security-Policy-Report-Only"]) . "</code></td></tr>";
                }
                if (isset($headers["Public-Key-Pins"])) {
                    echo "<tr><th width=250>Public Key Pins (HPKP)</th><td ><code>" . val_to_string($headers["Public-Key-Pins"]) . "</code></td></tr>";
                }
                if (isset($headers["Strict-Transport-Security"])) {
                    echo "<tr><th width=250>Strict Transport Security (HSTS)</th><td ><code>" . val_to_string($headers["Strict-Transport-Security"]) . "</code></td></tr>";
                }
                if (isset($headers["X-Frame-Options"])) {
                    echo "<tr><th width=250>Frame Options</th><td ><code>" . val_to_string($headers["X-Frame-Options"]) . "</code></td></tr>";
                }
                if (isset($headers["X-Xss-Protection"])) {
                    echo "<tr><th width=250>XSS Protection</th><td ><code>" . val_to_string($headers["X-Xss-Protection"]) . "</code></td></tr>";
                }
                if (isset($headers["X-Content-Type-Options"])) {
                    echo "<tr><th width=250>Content Type Options</th><td ><code>" . val_to_string($headers["X-Content-Type-Options"]) . "</code></td></tr>";
                }
                ?>
            </table>

            <h2>SSL Certificate</h2>
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

                // http://www.zedwood.com/article/php-parse-x509certificate
                //src: http://php.net/manual/en/ref.bc.php
                function bcdechex($dec)
                {
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
                <table class="values-list">
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
                    </tr>
                </table>

                <h3>Issued By</h3>
                <table class="values-list">
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
                <table class="values-list">
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
                <table class="values-list">
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
                            <pre><?php echo $keyData['key']; ?></pre>
                        </td>
                    </tr>
                    <tr>
                        <th>Certificate</th>
                        <td>
                            <pre><?php echo $cert_raw; ?></pre>
                        </td>
                    </tr>
                </table>
            <?php
            } else {
                echo '<p>No SSL/TLS certificate found</p>';
            }
            ?>
        </section>

        <section id="email" class="tab-content">
            <h2><abbr title="Sender Policy Framework">SPF</abbr> Records</h2>
            <?php
            if ($spf_records) {
                $count = 1;
            ?>
                <table class="records">
                    <tr>
                        <th>Action</th>
                        <th>Mechanism/Address</th>
                        <th>Host/IP/Value</th>
                        <th>Location</th>
                    </tr>
                <?php
                foreach ($spf_records as $spf) {
                    write_spf_table($domain, $ip, $location, $spf, 'pass');
                    write_spf_table($domain, $ip, $location, $spf, 'neutral');
                    write_spf_table($domain, $ip, $location, $spf, 'softfail');
                    write_spf_table($domain, $ip, $location, $spf, 'fail');
                    $count++;
                }
                echo '</table>';
            } else {
                echo '<p>None</p>';
            }
                ?>

                <h2>DKIM Records</h2>
                <?php
                // https://protodave.com/tools/dkim-key-checker/
                if ($dkim_records) {
                    echo "<p><em>Checks selectors: 'default' (cPanel), 'x' (MXRoute), 'smtp' (Mailgun), 's1, s2' (SendGrid), 'k2, k3' (MailChimp), 'google' (Google), 'selector1' & 'selector2' (Microsoft 365)</em></p>";
                    echo '<table>';
                    foreach ($dkim_records as $dkim) {
                        $alert = ($dkim['key_bits'] < 1024) ? ' INSECURE (<1024)' : '';

                        echo "<tr><th>Selector</th><td>{$dkim['host']}</td></tr>";
                ?>
                        <tr>
                            <th width="275px;">Key Length (Bits)</th>
                            <td><?php echo $dkim['key_bits'] . $alert; ?></td>
                        </tr>
                        <?php

                        if (isset($dkim['v'])) echo "<tr><th>Version</th><td>{$dkim['v']}</td></tr>";
                        if (isset($dkim['g'])) echo "<tr><th>Key Granularity</th><td>{$dkim['g']}</td></tr>";
                        if (isset($dkim['h'])) echo "<tr><th>Hash Algorithm</th><td>{$dkim['h']}</td></tr>";
                        if (isset($dkim['k'])) echo "<tr><th>Key Type</th><td>" . strtoupper($dkim['k']) . "</td></tr>";
                        if (isset($dkim['n'])) echo "<tr><th>Notes</th><td>{$dkim['n']}</td></tr>";
                        //if (isset($dkim['p'])) echo "<tr><th>Public Key Data</th><td>{$dkim['p']}</td></tr>";
                        if (isset($dkim['s'])) echo "<tr><th>Service Type</th><td>{$dkim['s']}</td></tr>";
                        if (isset($dkim['t'])) echo "<tr><th>Flags</th><td>{$dkim['t']}</td></tr>";
                        ?>
                        <tr>
                            <th>Public Key</th>
                            <td>
                                <pre><?php echo $dkim['public_key'] . $alert; ?></pre>
                            </td>
                        </tr>
                <?php
                    }
                    echo '</table>';
                } else {
                    echo '<p>None</p>';
                }
                ?>

                <h2>DMARC Records</h2>
                <?php
                // https://protodave.com/tools/dkim-key-checker/
                if ($dmarc_records) {
                    echo '<table>';
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

        <section id="map" class="tab-content">
            <div id="map_all" class="google-map google-map--tall"></div>
        </section>

        <section id="whois" class="tab-content">
            <pre><?php echo $whois; ?></pre>
        </section>
    </main>
    <footer>
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
        <?php echo $ipapi_count . ' ip-api.com queries'; ?> | <?php echo $ipinfo_count . ' ipinfo.io queries'; ?> | <?php echo $arin_count . ' ARIN queries'; ?> | <?php echo $dns_count . ' DNS queries'; ?>
    </footer>

    <script>
        var map, mapAll, host;

        function initMap() {
            var servers, i, marker;

            // Single server location
            host = new google.maps.LatLng(<?php echo $geo[0]; ?>, <?php echo $geo[1]; ?>); //{ lat: <?php echo $geo[0]; ?>, lng: <?php echo $geo[1]; ?> };
            map = new google.maps.Map(document.getElementById('map_single'), {
                center: host,
                zoom: 10
            });
            <?php
            if ($location) {
            ?>
                marker = new google.maps.Marker({
                    position: host,
                    title: "Host Server",
                    map: map
                });
                marker.addListener('click', function() {
                    var infowindow = new google.maps.InfoWindow({
                        content: "<?php echo '<strong>' . $location->org . '</strong> - <em>Web Server</em><br><strong>Host Name:</strong> ' . $location->hostname . '<br><strong>IP:</strong> ' . $location->ip; ?>"
                    });
                    infowindow.open(map, this);
                });
            <?php
            }
            ?>

            // All servers
            servers = [<?php
                        $js_servers = array();
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

                            $js_servers[] = "[ { lat: {$geoCoord[0]}, lng: {$geoCoord[1]} }, '{$title}', '{$content}' ]";
                        }
                        echo implode(",\n", $js_servers);
                        ?>];
            mapAll = new google.maps.Map(document.getElementById('map_all'), {
                center: host,
                zoom: 5
            });

            for (i = 0; i < servers.length; i++) {
                marker = new google.maps.Marker({
                    position: servers[i][0],
                    title: servers[i][1],
                    windowContent: servers[i][2],
                    map: mapAll
                });

                marker.addListener('click', function() {
                    var infowindow = new google.maps.InfoWindow({
                        content: this.windowContent
                    });
                    infowindow.open(mapAll, this);
                });
            }

            mapAll.setCenter(host);
        }

        function selectTab(evt) {
            var tabContent = document.getElementById(evt.target.dataset.tab),
                navButtons = document.querySelectorAll('.tabs__tab'),
                i, tabContents;

            // Highlight current tab
            for (i = 0; i < navButtons.length; ++i) {
                navButtons[i].classList.remove('tabs__tab--active');
            }
            evt.target.classList.add('tabs__tab--active');

            // Show current content
            tabContents = document.querySelectorAll('.tab-content'), i;
            for (i = 0; i < tabContents.length; ++i) {
                tabContents[i].classList.remove('tab-content--active');
            }
            tabContent.classList.add('tab-content--active');

            // Refresh GOogle maps when switching between tabs
            if (map) {
                google.maps.event.trigger(map, 'resize');
                // Recenter
                map.setCenter(host);
            }
            if (mapAll) {
                google.maps.event.trigger(mapAll, 'resize');
                // Recenter
                mapAll.setCenter(host);
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            var navButtons = document.querySelectorAll('.tabs__tab'),
                i;
            for (i = 0; i < navButtons.length; ++i) {
                navButtons[i].addEventListener('click', selectTab, false);
            }
        });
    </script>
    <script async defer src="https://maps.googleapis.com/maps/api/js?key=AIzaSyDVLQb71FZZWez5fgLsKSz1ZGfgQYxrPk4&callback=initMap"></script>
</body>

</html>