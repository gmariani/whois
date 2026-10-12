// Shapes returned by api.php. Keep in sync with app/Sections/*.php.

export interface BootConfig {
    query: string;
    domain: string | null;
    token: string | null;
    error: string | null;
    /** URL path of the app, e.g. "/projects/dns/" */
    base: string;
    api: string;
    mapsKey: string;
}

// ---------------------------------------------------------------- DNS

interface RecordBase {
    host: string;
    ttl: number;
    class: string;
}

export type DnsRecord = RecordBase &
    (
        | { type: 'A'; ip: string }
        | { type: 'AAAA'; ipv6: string }
        | { type: 'CNAME'; target: string }
        | { type: 'NS'; target: string }
        | { type: 'PTR'; target: string }
        | { type: 'MX'; pri: number; target: string }
        | {
              type: 'SOA';
              mname: string;
              rname: string;
              serial: number;
              refresh: number;
              retry: number;
              expire: number;
              'minimum-ttl': number;
          }
        | { type: 'TXT'; txt: string; entries: string[] }
        | { type: 'SRV'; pri: number; weight: number; port: number; target: string }
        | { type: 'NAPTR'; order: number; pref: number; flags: string; services: string; regex: string; replacement: string }
        | { type: 'CAA'; flags: number; tag: string; value: string }
        | { type: 'DNSKEY'; flags: number; protocol: number; algorithm: number; key: string }
        | { type: 'DS'; keytag: number; algorithm: number; digesttype: number; digest: string }
    );

export type RecordOf<T extends DnsRecord['type']> = Extract<DnsRecord, { type: T }>;

export interface NameServer {
    host: string;
    ips: string[];
}

export interface DnsSection {
    zone: string | null;
    delegated: boolean;
    nameservers: NameServer[];
    records: {
        soa: RecordOf<'SOA'>[];
        ns: RecordOf<'NS'>[];
        a: RecordOf<'A'>[];
        aaaa: RecordOf<'AAAA'>[];
        cname: RecordOf<'CNAME'>[];
        mx: RecordOf<'MX'>[];
        txt: RecordOf<'TXT'>[];
        caa: RecordOf<'CAA'>[];
        naptr: RecordOf<'NAPTR'>[];
        dnskey: RecordOf<'DNSKEY'>[];
        ds: RecordOf<'DS'>[];
        dmarc: RecordOf<'TXT'>[];
        ptr: RecordOf<'PTR'>[];
    };
    /** hostname => IPv4 addresses, for NS/MX/CNAME targets */
    targets: Record<string, string[]>;
    dsServer: string | null;
    dnsHosts: string[];
    stats: { queries: number; elapsedMs: number };
}

export interface SubdomainsSection {
    domains: string[];
    wildcard: boolean;
    checked: number;
    records: {
        a: RecordOf<'A'>[];
        cname: RecordOf<'CNAME'>[];
        txt: RecordOf<'TXT'>[];
        srv: RecordOf<'SRV'>[];
    };
    stats: { queries: number; elapsedMs: number };
}

// ------------------------------------------------------- Registration

export interface Registrar {
    name: string | null;
    label?: string | null;
    url: string | null;
    ianaId: string | null;
    abuseEmail: string | null;
    abusePhone: string | null;
}

export interface Contact {
    name: string | null;
    organization: string | null;
    email: string | null;
    phone: string | null;
    address: string | null;
    country: string | null;
}

export interface RegistrationSection {
    domain: string;
    source: 'rdap' | 'whois' | 'none';
    server: string | null;
    registered: boolean;
    record: {
        handle: string | null;
        registrar: Registrar | null;
        created: string | null;
        updated: string | null;
        expires: string | null;
        status: string[];
        nameservers: string[];
        dnssec: boolean | null;
        registrant: Contact | null;
    } | null;
    raw: { label: string; source: string | null; text: string }[];
}

// ------------------------------------------------------------ Network

export interface GeoLocation {
    city: string | null;
    region: string | null;
    country: string | null;
    countryCode: string | null;
    lat: number | null;
    lon: number | null;
    asn: number | null;
    org: string | null;
    /** true: the address is served from many sites, so the city is only one of them. null: unknown */
    anycast?: boolean | null;
}

export interface IpNetwork {
    registry: string | null;
    url: string | null;
    handle: string | null;
    name: string | null;
    type: string | null;
    country: string | null;
    startAddress: string | null;
    endAddress: string | null;
    cidrs: string[];
    parentHandle: string | null;
    registered: string | null;
    updated: string | null;
    organization: { name: string | null; handle: string | null; address: string | null; url: string | null } | null;
    abuseEmail: string | null;
    remarks: string[];
}

export interface NetworkSection {
    ip: string | null;
    ipv4: string[];
    ipv6: string[];
    hostname: string | null;
    network: IpNetwork | null;
    networkError?: string | null;
    location: GeoLocation | null;
    geoSource?: string;
    webHost: string | null;
}

export interface LocationsSection {
    ips: Record<string, { hostname: string | null; location: GeoLocation | null }>;
    markers: {
        lat: number;
        lng: number;
        servers: { role: string; host: string; ip: string; org: string | null; anycast?: boolean | null }[];
    }[];
    geoSource: string;
}

// -------------------------------------------------------------- Email

export type SpfQualifier = 'pass' | 'fail' | 'softfail' | 'neutral';

export interface SpfServer {
    host: string | null;
    ip: string;
    hostname?: string | null;
    location?: GeoLocation | null;
}

export interface SpfTerm {
    kind: 'mechanism' | 'modifier';
    qualifier: SpfQualifier | null;
    mechanism: string;
    value: string | null;
    cidr?: string | null;
    raw: string;
    servers?: SpfServer[];
}

export interface DkimKey {
    selector: string;
    host: string;
    tags: Record<string, string>;
    keyType: string;
    keyBits: number | null;
    publicKey: string | null;
    revoked: boolean;
    testing: boolean;
    weak: boolean;
    raw: string;
    provider: string | null;
    cname: string | null;
}

export interface EmailSection {
    spf: {
        raw: string;
        records: string[];
        terms: SpfTerm[];
        includes: Record<string, { raw: string; terms: SpfTerm[] } | null>;
        lookups: number;
        lookupLimit: number;
        all: SpfQualifier | null;
        warnings: string[];
    } | null;
    dkim: DkimKey[];
    dmarc: { raw: string; host: string; tags: Record<string, string> } | null;
    emailHost: { providers: string[]; gateway: boolean; via: string | null } | null;
    dkimSelectors: Record<string, string>;
}

// ---------------------------------------------------------- HTTP/TLS

export interface HttpSection {
    reachable: boolean;
    error?: string;
    url: string | null;
    status?: number;
    ip?: string | null;
    redirects?: { url: string; status: number }[];
    elapsedMs?: number;
    server?: string | null;
    poweredBy?: string | null;
    cdn?: string | null;
    security?: { name: string; value: string }[];
    headers?: { name: string; value: string }[];
}

export interface TlsSection {
    present: boolean;
    error?: string;
    protocol?: string | null;
    cipher?: string | null;
    subject?: Record<string, string>;
    issuer?: Record<string, string>;
    validFrom?: string;
    validTo?: string;
    expired?: boolean;
    selfSigned?: boolean;
    hostnameMatches?: boolean;
    altNames?: string[];
    publicKey?: { type: string; bits: number | null; pem: string | null };
    serial?: string;
    signatureAlgorithm?: string | null;
    version?: number;
    fingerprints?: { sha256: string; sha1: string; md5: string };
    keyUsage?: string | null;
    extendedKeyUsage?: string | null;
    subjectKeyId?: string | null;
    authorityKeyId?: string | null;
    pem?: string;
    chain?: { subject: string | null; issuer: string | null; validTo: string | null }[];
}

// ----------------------------------------------------------- Sections

export interface SectionData {
    registration: RegistrationSection;
    network: NetworkSection;
    dns: DnsSection;
    subdomains: SubdomainsSection;
    email: EmailSection;
    http: HttpSection;
    tls: TlsSection;
    locations: LocationsSection;
}

export type SectionName = keyof SectionData;

export type SectionState<T> =
    | { status: 'loading' }
    | { status: 'ready'; data: T; elapsedMs: number }
    | { status: 'error'; error: string };
