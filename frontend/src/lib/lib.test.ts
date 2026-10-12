import { describe, expect, it } from 'vitest';
import type { DnsSection, SubdomainsSection } from '../types';
import { base64ToHex, colonHex, eppCode, locationLabel, secondsToTime } from './format';
import { mergeRecords } from './records';
import { buildZoneFile } from './zoneFile';

const records = (overrides: Partial<DnsSection['records']>): DnsSection['records'] => ({
    soa: [], ns: [], a: [], aaaa: [], cname: [], mx: [], txt: [], caa: [], naptr: [], https: [], tlsa: [],
    dnskey: [], cdnskey: [], ds: [], cds: [], dmarc: [], ptr: [],
    ...overrides,
});

const dns = (r: Partial<DnsSection['records']>): DnsSection => ({
    zone: 'example.com',
    delegated: true,
    nameservers: [],
    records: records(r),
    targets: {},
    dsServer: null,
    dnsHosts: [],
    stats: { queries: 0, elapsedMs: 0 },
});

const base = { ttl: 300, class: 'IN' };

describe('mergeRecords', () => {
    it('combines apex and subdomain records, de-duplicating by value (ignoring TTL)', () => {
        const apex = dns({ a: [{ ...base, host: 'www.example.com', type: 'A', ip: '192.0.2.1' }] });
        const subs: SubdomainsSection = {
            domains: ['example.com'],
            wildcard: false,
            checked: 1,
            records: { a: [{ ...base, ttl: 299, host: 'www.example.com', type: 'A', ip: '192.0.2.1' }], aaaa: [], cname: [], mx: [], txt: [], srv: [], https: [] },
            stats: { queries: 0, elapsedMs: 0 },
        };
        expect(mergeRecords(apex, subs)).toHaveLength(1);
    });

    it('orders by type like the original page, MX by priority', () => {
        const merged = mergeRecords(
            dns({
                mx: [
                    { ...base, host: 'example.com', type: 'MX', pri: 20, target: 'mx2.example.com' },
                    { ...base, host: 'example.com', type: 'MX', pri: 10, target: 'mx1.example.com' },
                ],
                ns: [{ ...base, host: 'example.com', type: 'NS', target: 'ns1.example.net' }],
                dmarc: [{ ...base, host: '_dmarc.example.com', type: 'TXT', txt: 'v=DMARC1; p=none', entries: ['v=DMARC1; p=none'] }],
            }),
            null,
        );
        expect(merged.map((r) => r.display)).toEqual(['NS', 'MX', 'MX', 'DMARC']);
        expect(merged.filter((r) => r.type === 'MX').map((r) => (r.type === 'MX' ? r.pri : 0))).toEqual([10, 20]);
    });

    it('drops other records for a name that is an alias', () => {
        const merged = mergeRecords(
            dns({
                cname: [{ ...base, host: 'mail.example.com', type: 'CNAME', target: 'ghs.google.com' }],
                a: [{ ...base, host: 'mail.example.com', type: 'A', ip: '192.0.2.9' }],
            }),
            null,
        );
        expect(merged.map((r) => r.type)).toEqual(['CNAME']);
    });
});

describe('buildZoneFile', () => {
    const zone = buildZoneFile(
        'example.com',
        mergeRecords(
            dns({
                ns: [{ ...base, host: 'example.com', type: 'NS', target: 'ns1.example.net' }],
                a: [{ ...base, host: 'www.example.com', type: 'A', ip: '192.0.2.1' }],
                txt: [{ ...base, host: 'example.com', type: 'TXT', txt: 'say "hi"part2', entries: ['say "hi"', 'part2'] }],
                ds: [{ ...base, host: 'example.com', type: 'DS', keytag: 1, algorithm: 13, digesttype: 2, digest: 'AB' }],
            }),
            null,
        ),
    );

    it('uses relative owner names and absolute targets', () => {
        expect(zone).toContain('example.com.\t300\tIN\tNS\tns1.example.net.\n');
        expect(zone).toContain('www\t300\tIN\tA\t192.0.2.1\n');
    });

    it('keeps TXT strings split and escapes quotes', () => {
        expect(zone).toContain('TXT\t"say \\"hi\\"" "part2"');
    });

    it('writes HTTPS and TLSA records in zone-file syntax', () => {
        const extra = buildZoneFile(
            'example.com',
            mergeRecords(
                dns({
                    https: [{ ...base, host: 'example.com', type: 'HTTPS', priority: 1, target: '', params: { alpn: 'h3,h2', ipv4hint: '192.0.2.1' } }],
                    tlsa: [{ ...base, host: '_443._tcp.example.com', type: 'TLSA', usage: 3, selector: 1, matchingType: 1, data: 'ABCD' }],
                }),
                null,
            ),
        );
        expect(extra).toContain('example.com.\t300\tIN\tHTTPS\t1 . alpn="h3,h2" ipv4hint=192.0.2.1\n');
        expect(extra).toContain('_443._tcp\t300\tIN\tTLSA\t3\t1\t1\tABCD\n');
    });

    it('leaves out DS records, which belong to the parent zone', () => {
        expect(zone).not.toContain('\tDS\t');
    });
});

describe('format helpers', () => {
    it('secondsToTime', () => {
        expect(secondsToTime(90061)).toBe('1d 1h 1m 1s');
        expect(secondsToTime(0)).toBe('0s');
    });

    it('hex helpers', () => {
        expect(colonHex('ab12cd')).toBe('AB:12:CD');
        expect(base64ToHex('AQI=')).toBe('0102');
    });

    it('eppCode links RDAP status to ICANN codes', () => {
        expect(eppCode('client transfer prohibited')).toBe('clientTransferProhibited');
    });

    it('locationLabel marks anycast addresses', () => {
        const loc = { city: 'Lansing', region: 'Michigan', country: 'United States', countryCode: 'US', lat: 0, lon: 0, asn: 1, org: 'x' };
        expect(locationLabel(loc)).toBe('Lansing, Michigan United States');
        expect(locationLabel({ ...loc, anycast: true })).toContain('anycast');
        expect(locationLabel(null)).toBe('Unknown');
    });
});
