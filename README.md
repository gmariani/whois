# Domain Inspector

Look up a domain's registration, DNS records, email authentication (SPF/DKIM/DMARC), TLS certificate, HTTP security headers and hosting, going to the source for each.

Type the domain after the site's address: `/projects/dns/google.com/`. Full URLs work too (`/projects/dns/https://example.com/page`) and redirect to the clean form, as do old `?q=` links.

Sources:

| Data | Source |
| --- | --- |
| Registration | The registry's RDAP server (found via [IANA's bootstrap registry](https://data.iana.org/rdap/)), then the registrar's RDAP server; port-43 WHOIS only for TLDs without RDAP |
| IP networks | The Regional Internet Registry's RDAP server (ARIN, RIPE, APNIC, LACNIC, AFRINIC) |
| DNS | The zone's own authoritative name servers, queried in parallel; DS records from the parent zone |
| Geolocation | [ipinfo.io](https://ipinfo.io) while its quota lasts (`IP_INFO` token), then the local [DB-IP Lite](https://db-ip.com/db/lite.php) database; ip-api.com only if that isn't installed |

## Layout

```
index.php  api.php   web entry points (page shell, JSON API)
app/                 everything server-side: PHP classes (namespace Whois\), bootstrap.php,
                     vendor/ (Composer) and bin/ (CLI tools). Not web-accessible.
  data/              editable lists: subdomains to probe, DKIM selectors, provider names
  Sections/          one class per independently-loaded part of the page
  Dns/ Rdap/ Whois/  lookups; Http/ = API, abuse guard, URL routing
  bin/lookup.php     run sections from the CLI: php app/bin/lookup.php example.com dns
  bin/update-geoip.php  download the DB-IP databases (run monthly)
tests/               PHPUnit: Unit/ (offline) and Live/ (real domains); not deployed
frontend/            React + TypeScript source; compiled into build/
storage/             caches, rate-limit counters, GeoIP databases (created at runtime)
scripts/package.mjs  builds dist/, the folder you upload
```

Rule of thumb: `app/` and the two entry points run on the server; `frontend/` is source that only exists to be compiled.

## Requirements

Server: PHP 8.1+ with curl, openssl and json (intl recommended for internationalized domains), Apache with `mod_rewrite`. Outbound UDP/TCP 53, TCP 43 and HTTPS must be allowed.

Your machine: PHP + Composer and Node 20+, to build.

## Deploy

```sh
npm run package
```

This builds the front-end, installs production-only PHP dependencies and puts exactly the deployable files in `dist/`:

```
dist/
  index.php  api.php  .htaccess  .user.ini
  build/     app/     storage/   (storage/ holds only its .htaccess)
```

Upload the **contents** of `dist/` to the site folder (e.g. `public_html/projects/dns/`) by FTP. It never contains `.env` or any `storage/` data, so uploading over the live site doesn't clobber anything. Old files from previous versions that no longer exist can be left or deleted; they're never loaded.

### First deploy only

1. On the server, create `.env` next to `index.php` from `.env-sample` and fill in at least `GOOGLE_MAPS`, `IP_INFO` and `APP_URL`. Behind Cloudflare, also set `CLIENT_IP_HEADER=CF-Connecting-IP`.
2. Make sure `storage/` is writable by PHP (normal on cPanel; otherwise `chmod 775 storage`).
3. Delete the old `style.css` and `fonts/` if they're still there.
4. Add a monthly cron job (cPanel → Cron Jobs) to download/refresh the GeoIP databases. They're ~130 MB, so the server fetches them itself instead of you uploading them:
   ```
   0 4 3 * * /usr/local/bin/php /home/<user>/public_html/projects/dns/app/bin/update-geoip.php > /dev/null
   ```
   To get them immediately, temporarily set the schedule to a few minutes from now (or run the command over SSH). The PHP path varies by host and must be 8.1+.

### Check it works

- `https://<site>/projects/dns/google.com/` loads and the tabs fill in. A 404 means `mod_rewrite`/`AllowOverride` isn't enabled.
- `https://<site>/projects/dns/.env`, `.../app/bootstrap.php` and `.../storage/` return 403. If they don't, the `.htaccess` rules aren't being applied: fix that before going live.

If a change alters a section's data shape, bump `CACHE_VERSION` in `app/Lookup/SectionRunner.php` so old cached results aren't served.

## Development

In `.env` set `APP_ENV=development` and `VITE_DEV_SERVER=http://localhost:5173`, then run both:

```sh
npm run serve   # PHP on http://localhost:8000 (multiple workers so sections load in parallel)
npm run dev     # Vite with hot reload
```

## Updating the lists

The things the site recognises are plain PHP arrays in `app/data/`, with comments explaining each:

- `subdomains.php`: names probed for A/CNAME, TXT and SRV records
- `dkim-selectors.php`: DKIM selectors and the service that usually uses each
- `providers.php`: registrar, web host, DNS host and email host names (first match wins)

After editing, run `composer test`: it flags invalid names, duplicates, upper-case needles and provider entries that can never match.

## Tests

```sh
composer test        # PHP unit tests: offline, ~1 second
npm test             # front-end helpers (record merging, zone file, formatting)
composer test:live   # the example domains from the original index.php, looked up for real (~30 s)
```

Unit tests run parsers against real registry responses saved in `tests/fixtures/`. The live suite checks what each example domain was originally there to exercise (TXT via CNAME, AAAA, NAPTR, CAA on `.co.uk`, DNSKEY/DS, wildcards, hosting detection…). Live failures can mean a domain changed its setup rather than a bug, so check which before changing code.

## API protection

The API only answers this site's own pages: `index.php` hands each page an HMAC token tied to the domain and to a random secret in the visitor's session (HttpOnly, SameSite=Strict cookie). Requests must also be same-origin and carry custom headers, so other websites can't call it from a browser. Lookups and API calls are rate limited per IP and per token; see `.env-sample`.
