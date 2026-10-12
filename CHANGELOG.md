# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [20261012]
### Changed
- Split the single `index.php` into PHP classes (`app/`), a JSON API (`api.php`) and a React front-end (`frontend/`). `npm run package` builds `dist/`, the exact set of files to upload. Each section of the results page now loads independently and in parallel.
- Registration data now comes from RDAP (registry, then registrar) located via IANA's bootstrap files; WHOIS is only used for TLDs without RDAP.
- IP network data now comes from each Regional Internet Registry's RDAP server instead of ARIN's REST API only.
- DNS queries go to the zone's authoritative servers in parallel (with TCP fallback for large answers) instead of one at a time. Replaced the abandoned `pear/net_dns2` (and its local patches) with `mikepultz/netdns2` v2.
- Geolocation tries ipinfo.io first (when `IP_INFO` is set), switches to a local DB-IP database (`app/bin/update-geoip.php`) once ipinfo's quota runs out, and uses ip-api.com only if that database isn't installed. KeyCDN was removed.
- SPF terms without a qualifier are now shown as "pass" (RFC 7208); previously they were listed as "neutral".
- Root domain detection uses the Public Suffix List (fixes `.co.uk` and similar).

### Fixed
- A WHOIS server that didn't answer was cached as "no registration data" for an hour; temporary failures are no longer cached.
- Bare IPv6 addresses were mangled by port stripping and reported as invalid domains.
- `.uk` WHOIS name-server lists picked up stray words after the block.

### Added
- New record types: HTTPS/SVCB (HTTP/3, encrypted ClientHello), TLSA/DANE for the website and for each mail server, and CDS/CDNSKEY (automated DNSSEC key updates, including the "remove DNSSEC" signal). The subdomain probe now also checks IPv6 (AAAA), MX on email-sending subdomains, and HTTPS on `www`.
- Editable lists in `app/data/` (subdomains, DKIM selectors, providers), checked by `composer test`. The subdomain probe grew from 145 to 242 names, and more DNS, email and hosting providers are recognised.
- Clean lookup URLs: `/projects/dns/google.com/` (also accepts `/https://example.com/...`). Old `?q=` links redirect.
- API protection: per-page tokens bound to the session and domain, same-origin checks, per-IP and per-token rate limits.
- SPF DNS-lookup count with warnings, expandable `include:` chains; CAA records; TLS chain and hostname check; DNSSEC status; registrar abuse contact and EPP status codes.
- Outbound requests to user-supplied domains refuse private/internal addresses.
- `app/bin/lookup.php` to run lookups from the command line.
- Tests: PHPUnit unit tests (`composer test`), live checks of the original example domains (`composer test:live`) and front-end tests (`npm test`).

## [20231205]
- Patched vendor/pear/net_dns2/Net/DNS2.php:generateError() to better handle errors
- Patched vendor/pear/net_dns2/Net/DNS2/Exception.php:__construct() to better handle errors

## [20230628]
### Added
- Revised dashboard to simplify general items
- Moved records to separate tab
- Clipboard icon to easily copy TXT record data

## [1.1.0] - 5/21/2022
### Added
- Current live version finally added to a repository.

## [1.0.0] - 1/1/2014
### Added
- Initial version was made around 2014, I didn't really version or track changes to it.
