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
