<?php

/*
 * DKIM selectors checked at <selector>._domainkey.<domain>, and the service
 * that usually uses each one. Used by the Email tab and the DNS record probe.
 *
 * Some senders (Amazon SES, SparkPost, Postmark…) use random per-customer
 * selectors that can't be guessed, so they'll only show up here when the
 * domain uses one of the common names below.
 */

return [
    'default' => 'cPanel',
    'dkim' => 'Generic',
    'mail' => 'Generic',
    'key1' => 'Generic',
    'key2' => 'Generic',
    'google' => 'Google Workspace',
    'ga1' => 'Google Workspace',
    'selector1' => 'Microsoft 365',
    'selector2' => 'Microsoft 365',
    'k1' => 'Mailchimp',
    'k2' => 'Mailchimp',
    'k3' => 'Mailchimp',
    'mte1' => 'Mailchimp Transactional',
    'mte2' => 'Mailchimp Transactional',
    'mandrill' => 'Mandrill',
    'cm' => 'Campaign Monitor',
    'x' => 'MXroute',
    'smtp' => 'Mailgun',
    'mx' => 'Mailgun',
    'pic' => 'Mailgun',
    'turbo-smtp' => 'turboSMTP',
    's1' => 'SendGrid',
    's2' => 'SendGrid',
    'smt' => 'SendGrid',
    'smt2' => 'SendGrid',
    'm1' => 'SendGrid',
    'smtpapi' => 'SendGrid',
    'hs1' => 'HubSpot',
    'hs2' => 'HubSpot',
    'pm' => 'Postmark',
    'zoho' => 'Zoho Mail',
    'zmail' => 'Zoho Mail',
    'protonmail' => 'Proton Mail',
    'protonmail2' => 'Proton Mail',
    'protonmail3' => 'Proton Mail',
    'fm1' => 'Fastmail',
    'fm2' => 'Fastmail',
    'fm3' => 'Fastmail',
    'sig1' => 'iCloud Mail',
    'mailjet' => 'Mailjet',
    'everlytickey1' => 'Everlytic',
    'everlytickey2' => 'Everlytic',
    'titan1' => 'Titan Email',
    'kl' => 'Klaviyo',
    'kl2' => 'Klaviyo',
    'zendesk1' => 'Zendesk',
    'zendesk2' => 'Zendesk',
    'sf1' => 'Salesforce',
    'sf2' => 'Salesforce',
];
