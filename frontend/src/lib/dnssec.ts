// IANA DNSSEC algorithm and DS digest numbers.

const ALGORITHMS: Record<number, string> = {
    1: 'RSA/MD5',
    2: 'Diffie-Hellman',
    3: 'DSA/SHA-1',
    4: 'Elliptic Curve',
    5: 'RSA/SHA-1',
    6: 'DSA-NSEC3-SHA1',
    7: 'RSASHA1-NSEC3-SHA1',
    8: 'RSA/SHA-256',
    10: 'RSA/SHA-512',
    12: 'GOST R 34.10-2001',
    13: 'ECDSA/SHA-256',
    14: 'ECDSA/SHA-384',
    15: 'Ed25519',
    16: 'Ed448',
    252: 'Indirect',
    253: 'Private',
    254: 'Private OID',
};

const DIGESTS: Record<number, string> = {
    1: 'SHA-1',
    2: 'SHA-256',
    3: 'GOST R 34.11-94',
    4: 'SHA-384',
};

export const algorithmName = (n: number) => ALGORITHMS[n] ?? `Unknown (${n})`;
export const digestName = (n: number) => DIGESTS[n] ?? `Unknown (${n})`;

/** DNSKEY flags: bit 7 (0x0100) = zone key, bit 15 (0x0001) = secure entry point (KSK). */
export function dnskeyFlags(flags: number): { zoneKey: boolean; secureEntryPoint: boolean } {
    return { zoneKey: (flags & 0x0100) !== 0, secureEntryPoint: (flags & 0x0001) !== 0 };
}

// TLSA (DANE) fields, RFC 6698 / RFC 7218.
const TLSA_USAGE: Record<number, string> = {
    0: 'PKIX-TA: must chain to this CA, and to a public CA',
    1: 'PKIX-EE: must be this exact certificate, also publicly trusted',
    2: 'DANE-TA: must chain to this CA (private CAs allowed)',
    3: 'DANE-EE: must be this exact certificate/key (no CA needed)',
};
const TLSA_SELECTOR: Record<number, string> = { 0: 'whole certificate', 1: 'public key only' };
const TLSA_MATCHING: Record<number, string> = { 0: 'exact data', 1: 'SHA-256 hash', 2: 'SHA-512 hash' };

export const tlsaUsage = (n: number) => TLSA_USAGE[n] ?? `Unknown (${n})`;
export const tlsaSelector = (n: number) => TLSA_SELECTOR[n] ?? `Unknown (${n})`;
export const tlsaMatching = (n: number) => TLSA_MATCHING[n] ?? `Unknown (${n})`;

/** Readable summary of an HTTPS/SVCB record's parameters. */
export function svcSummary(params: Record<string, string>): string[] {
    const out: string[] = [];
    const alpn = (params.alpn ?? '').split(',').filter(Boolean);
    if (alpn.length) out.push(`Protocols: ${alpn.map((p) => (p === 'h3' ? 'HTTP/3' : p === 'h2' ? 'HTTP/2' : p === 'http/1.1' ? 'HTTP/1.1' : p)).join(', ')}`);
    if (params.ech) out.push('Encrypted Client Hello (ECH): yes');
    if (params.port) out.push(`Port: ${params.port}`);
    return out;
}
