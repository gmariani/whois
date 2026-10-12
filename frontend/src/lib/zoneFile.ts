import type { DisplayRecord } from './records';

const HEADER = `;
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
`;

/** Owner name relative to the zone: "www.example.com" => "www", apex => "example.com." */
function owner(zone: string, host: string): string {
    if (host === zone) return `${zone}.`;
    if (host.endsWith(`.${zone}`)) return host.slice(0, -(zone.length + 1));
    return `${host}.`;
}

const quote = (text: string) => `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;

function rdata(rec: DisplayRecord): string {
    switch (rec.type) {
        case 'SOA':
            return `${rec.mname}.\t${rec.rname}.\t(\n\t\t\t\t\t\t${rec.serial} ;Serial Number\n\t\t\t\t\t\t${rec.refresh} ;refresh\n\t\t\t\t\t\t${rec.retry} ;retry\n\t\t\t\t\t\t${rec.expire} ;expire\n\t\t\t\t\t\t${rec['minimum-ttl']}\t)`;
        case 'NS':
        case 'CNAME':
        case 'PTR':
            return `${rec.target}.`;
        case 'A':
            return rec.ip;
        case 'AAAA':
            return rec.ipv6;
        case 'MX':
            return `${rec.pri}\t${rec.target}.`;
        case 'TXT':
            // Long values are split into 255-byte strings, as published.
            return rec.entries.map(quote).join(' ');
        case 'SRV':
            return `${rec.pri}\t${rec.weight}\t${rec.port}\t${rec.target}.`;
        case 'NAPTR':
            return `${rec.order}\t${rec.pref}\t${quote(rec.flags)}\t${quote(rec.services)}\t${quote(rec.regex)}\t${rec.replacement || '.'}${rec.replacement ? '.' : ''}`;
        case 'CAA':
            return `${rec.flags}\t${rec.tag}\t${quote(rec.value)}`;
        case 'DNSKEY':
        case 'CDNSKEY':
            return `${rec.flags}\t${rec.protocol}\t${rec.algorithm}\t${rec.key}`;
        case 'DS':
        case 'CDS':
            return `${rec.keytag}\t${rec.algorithm}\t${rec.digesttype}\t${rec.digest}`;
        case 'HTTPS':
        case 'SVCB': {
            const params = Object.entries(rec.params).map(([k, v]) => (k === 'alpn' ? `${k}=${quote(v)}` : `${k}=${v}`));
            return [rec.priority, rec.target ? `${rec.target}.` : '.', ...params].join(' ');
        }
        case 'TLSA':
            return `${rec.usage}\t${rec.selector}\t${rec.matchingType}\t${rec.data}`;
    }
}

export function buildZoneFile(zone: string, records: DisplayRecord[]): string {
    const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
    let out = `; Domain: ${zone}\n; Exported (y-m-d hh:mm:ss): ${now}\n${HEADER}\n`;

    let group: string | null = null;
    // Wildcard placeholders ("*.example.com") are real zone syntax, but DS lives in the parent zone.
    for (const rec of records.filter((r) => r.type !== 'DS')) {
        if (rec.display !== group) {
            out += `${group ? '\n' : ''}; ${rec.display} Record\n`;
            group = rec.display;
        }
        out += `${owner(zone, rec.host)}\t${rec.ttl}\t${rec.class}\t${rec.type}\t${rdata(rec)}\n`;
    }
    return out;
}

export function download(filename: string, text: string): void {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain;charset=utf-8' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}
