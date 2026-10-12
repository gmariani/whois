import type { DnsRecord, DnsSection, SubdomainsSection } from '../types';

export type DisplayType = DnsRecord['type'] | 'DMARC';
export type DisplayRecord = DnsRecord & { display: DisplayType };

/** Table order, matching the original page. */
const ORDER: DisplayType[] = ['SOA', 'NS', 'A', 'AAAA', 'CNAME', 'HTTPS', 'SVCB', 'DNSKEY', 'CDNSKEY', 'DS', 'CDS', 'CAA', 'TLSA', 'MX', 'TXT', 'DMARC', 'SRV', 'NAPTR'];

export const TYPE_LABELS: Record<string, string> = {
    SOA: 'Start of Authority',
    NS: 'Name Server',
    A: 'IPv4 Address',
    AAAA: 'IPv6 Address',
    CNAME: 'Canonical Name (alias)',
    DNSKEY: 'DNS Key',
    CDNSKEY: 'Child DNS Key (asks the parent to update DNSSEC)',
    DS: 'Delegation Signer',
    CDS: 'Child Delegation Signer (asks the parent to update DNSSEC)',
    HTTPS: 'HTTPS service binding (protocols, IP hints, ECH)',
    SVCB: 'Service binding',
    TLSA: 'TLS certificate pin (DANE)',
    CAA: 'Certification Authority Authorization',
    MX: 'Mail Exchange',
    TXT: 'Text',
    DMARC: 'DMARC policy (TXT)',
    SRV: 'Service Location',
    NAPTR: 'Naming Authority Pointer',
    PTR: 'Pointer (reverse DNS)',
};

/** Apex records plus whatever subdomain probing found, de-duplicated and ordered. */
export function mergeRecords(dns: DnsSection, subdomains: SubdomainsSection | null): DisplayRecord[] {
    const r = dns.records;
    const all: DisplayRecord[] = [
        ...[
            ...r.soa, ...r.ns, ...r.a, ...r.aaaa, ...r.cname, ...r.https, ...r.dnskey, ...r.cdnskey, ...r.cds,
            ...r.caa, ...r.tlsa, ...r.mx, ...r.txt, ...r.naptr,
        ].map(
            (rec) => ({ ...rec, display: rec.type }) as DisplayRecord,
        ),
        ...r.dmarc.map((rec) => ({ ...rec, display: 'DMARC' as const })),
    ];
    if (subdomains) {
        const s = subdomains.records;
        for (const rec of [...s.a, ...s.aaaa, ...s.cname, ...s.https, ...s.mx, ...s.txt, ...s.srv]) {
            // DMARC/DKIM TXT found by probing go in the TXT group like the rest.
            all.push({ ...rec, display: rec.type } as DisplayRecord);
        }
    }

    const seen = new Set<string>();
    const unique = all.filter((rec) => {
        const { ttl: _ttl, display: _display, ...identity } = rec;
        const key = JSON.stringify(identity);
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    // A name that is an alias can't carry other records; drop leftovers for it.
    const aliases = new Set(unique.filter((rec) => rec.type === 'CNAME').map((rec) => rec.host));
    const cleaned = unique.filter((rec) => rec.type === 'CNAME' || !aliases.has(rec.host) || rec.host === dns.zone);

    return cleaned.sort((a, b) => {
        const byType = ORDER.indexOf(a.display) - ORDER.indexOf(b.display);
        if (byType !== 0) return byType;
        if (a.type === 'MX' && b.type === 'MX') return a.pri - b.pri;
        return a.host.localeCompare(b.host, undefined, { numeric: true });
    });
}
