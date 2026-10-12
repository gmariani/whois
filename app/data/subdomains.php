<?php

/*
 * Names probed under every looked-up domain. DNS can't list a zone's records,
 * so these are educated guesses. Each entry costs one DNS query (all sent in
 * parallel), so favour names that are actually common.
 *
 * Add a name to the right group and run `composer test`; it checks for typos
 * and duplicates. DKIM selectors live in dkim-selectors.php and are probed
 * automatically.
 */

return [
    // Looked up as A records; a CNAME answer is recorded as a CNAME.
    'hosts' => [
        // Web
        'www', 'www2', 'ww1', 'm', 'mobile', 'blog', 'news', 'shop', 'store', 'pay', 'secure',
        'app', 'api', 'portal', 'dashboard', 'admin', 'login', 'auth', 'sso', 'id', 'account', 'accounts',
        'my', 'myaccount', 'signin', 'online', 'myonline', 'www.account', 'origin', 'cdn', 'static', 'assets',
        'img', 'images', 'media', 'files', 'download', 'downloads', 'docs', 'help', 'support', 'kb', 'wiki',
        'status', 'forum', 'community', 'events', 'careers', 'jobs', 'go', 'links', 'click', 'track', 'info',

        // Environments
        'dev', 'www.dev', 'staging', 'www.staging', 'stagingwww', 'test', 'qa', 'uat', 'beta', 'demo',
        'sandbox', 'old', 'new', 'legacy',

        // Email & collaboration
        'mail', 'mail2', 'email', 'webmail', 'www.webmail', 'smtp', 'imap', 'pop', 'pop3', 'mx', 'mx0', 'mx1',
        'mailserver', 'securemail', 'mobilemail', 'mobileemail', 'bounce', 'newsletter', 'autoconfig', 'mta-sts',
        'calendar', 'www.calendar', 'meet', 'chat', 'fax',

        // Microsoft 365 / Exchange
        'autodiscover', 'owa', 'exchange', 'sip', 'lyncdiscover', 'msoid', 'enterpriseregistration', 'enterpriseenrollment',

        // Google Workspace
        'sites', 'start', 'drive',

        // cPanel / hosting
        'cpanel', 'whm', 'webdisk', 'cpcalendars', 'cpcontacts', 'ftp', 'sftp', 'server', 'host', 'vps', 'cloud',
        'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'dns',

        // Internal / remote access
        'vpn', 'remote', 'gateway', 'intranet', 'extranet', 'terminal', 'staff', 'hr', 'crm', 'training', 'course',
        'git', 'gitlab', 'jira', 'confluence', 'jenkins', 'ci', 'grafana', 'monitor',

        // Miscellaneous names from the original list
        'bbs', 'gov', 'spam', 'watch', 'e', 'pda', 'web', 'webapps', 'r.1', 'r.2', 'r.3',
        '_cf-custom-hostname', '_domainconnect',
    ],

    // Looked up as MX records. Bulk senders (Amazon SES, Resend, Mailgun…) often need an
    // MX on a sending subdomain for bounces, e.g. send.example.com.
    'mx' => [
        'send', 'bounce', 'bounces', 'mail', 'email', 'em', 'mg', 'mailgun', 'sendgrid', 'smtp',
        'newsletter', 'news', 'marketing', 'notifications', 'notify', 'reply', 'return',
    ],

    // Looked up as HTTPS records (the apex is always checked). One query each, so keep it short.
    'https' => ['www'],

    // Looked up as TXT records (verification and policy records).
    'txt' => [
        '_dmarc', '_mta-sts', '_smtp._tls', '_bimi', 'default._bimi',
        '_acme-challenge', '_cpanel-dcv-test-record', '_cf-custom-hostname', '_domainconnect',
        '_caldav._tcp', '_caldavs._tcp', '_carddav._tcp', '_carddavs._tcp',
        '_amazonses', '_github-challenge', '_github-pages-challenge', '_atproto', '_vercel', '_dnsauth', 'asuid',
    ],

    // Looked up as SRV records.
    'srv' => [
        '_sip._tls', '_sip._tcp', '_sip._udp', '_sipfederationtls._tcp', '_autodiscover._tcp',
        '_caldav._tcp', '_caldavs._tcp', '_carddav._tcp', '_carddavs._tcp',
        '_imap._tcp', '_imaps._tcp', '_pop3s._tcp', '_submission._tcp', '_submissions._tcp',
        '_xmpp-client._tcp', '_xmpp-server._tcp', '_matrix._tcp', '_ldap._tcp', '_kerberos._tcp', '_minecraft._tcp',
    ],
];
