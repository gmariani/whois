import type { ReactNode } from 'react';
import { Badge } from 'react-bootstrap';
import { Await, CodeBlock, Dl, Group, Muted, SectionTitle } from '../components/ui';
import { algorithmName, digestName, dnskeyFlags } from '../lib/dnssec';
import { base64ToHex, colonHex, formatDateTime, timeUntil } from '../lib/format';
import type { DnsSection, HttpSection, TlsSection } from '../types';
import type { Sections } from '../useSections';

type Row = [ReactNode, ReactNode];

export function SecurityTab({ sections, onRetry }: { sections: Sections; onRetry: (name: 'dns' | 'http' | 'tls') => void }) {
    return (
        <>
            <SectionTitle>DNS Security</SectionTitle>
            <Await state={sections.dns} label="Checking DNSSEC" onRetry={() => onRetry('dns')}>
                {(dns) => (
                    <Dnssec
                        dns={dns}
                        registryFlag={sections.registration.status === 'ready' ? sections.registration.data.record?.dnssec ?? null : null}
                    />
                )}
            </Await>

            <SectionTitle className="mt-5">HTTP Security Headers</SectionTitle>
            <Await state={sections.http} label="Fetching the website" onRetry={() => onRetry('http')}>
                {(http) => <HttpHeaders http={http} />}
            </Await>

            <SectionTitle className="mt-5">SSL/TLS Certificate</SectionTitle>
            <Await state={sections.tls} label="Connecting on port 443" onRetry={() => onRetry('tls')}>
                {(tls) => <Certificate tls={tls} />}
            </Await>
        </>
    );
}

function Dnssec({ dns, registryFlag }: { dns: DnsSection; registryFlag: boolean | null }) {
    const { dnskey, ds } = dns.records;
    if (dnskey.length === 0 && ds.length === 0) {
        return (
            <Group>
                <Dl rows={[['', registryFlag ? 'The registry says this domain is signed, but no DNSSEC records were found.' : 'No DNSSEC records found']]} />
            </Group>
        );
    }

    const signed = dnskey.length > 0 && ds.length > 0;
    return (
        <>
            <Group>
                <Dl
                    rows={[
                        [
                            'Status',
                            signed ? (
                                <Badge bg="success">Signed and delegated</Badge>
                            ) : dnskey.length > 0 ? (
                                <Badge bg="warning" text="dark">
                                    Keys published but no DS record at the parent — validation won't happen
                                </Badge>
                            ) : (
                                <Badge bg="danger">DS record at the parent but no DNSKEY — validation will fail</Badge>
                            ),
                        ],
                    ]}
                />
            </Group>
            {dnskey.map((key, i) => {
                const flags = dnskeyFlags(key.flags);
                return (
                    <Group key={`k${i}`} title={flags.secureEntryPoint ? 'DNS Key (KSK)' : 'DNS Key (ZSK)'}>
                        <Dl
                            rows={[
                                ['Holds DNS Zone Key', flags.zoneKey ? 'True' : 'False'],
                                ['Secure Entry Point', flags.secureEntryPoint ? 'True' : 'False'],
                                ['Algorithm', algorithmName(key.algorithm)],
                                ['Protocol', key.protocol],
                                ['Public Key', <code className="text-break">{colonHex(base64ToHex(key.key))}</code>],
                            ]}
                        />
                    </Group>
                );
            })}
            {ds.map((record, i) => (
                <Group key={`d${i}`} title={`Delegation Signer via ${dns.dsServer ?? 'parent zone'}`}>
                    <Dl
                        rows={[
                            ['Key Tag', record.keytag],
                            ['Algorithm', algorithmName(record.algorithm)],
                            ['Digest Type', digestName(record.digesttype)],
                            ['Digest', <code className="text-break">{colonHex(record.digest)}</code>],
                        ]}
                    />
                </Group>
            ))}
        </>
    );
}

const HEADER_LABELS: Record<string, ReactNode> = {
    'Content-Security-Policy': <abbr title="Content Security Policy">CSP</abbr>,
    'Content-Security-Policy-Report-Only': (
        <>
            <abbr title="Content Security Policy">CSP</abbr> Report Only
        </>
    ),
    'Strict-Transport-Security': <abbr title="HTTP Strict Transport Security">HSTS</abbr>,
    'Public-Key-Pins': <abbr title="HTTP Public Key Pinning (obsolete)">HPKP</abbr>,
    'X-Frame-Options': 'Frame Options',
    'X-Content-Type-Options': 'Content Type Options',
    'X-XSS-Protection': 'XSS Protection',
    'Referrer-Policy': 'Referrer Policy',
    'Permissions-Policy': 'Permissions Policy',
    'Cross-Origin-Opener-Policy': (
        <>
            <abbr title="Cross-Origin Opener Policy">COOP</abbr>
        </>
    ),
    'Cross-Origin-Resource-Policy': (
        <>
            <abbr title="Cross-Origin Resource Policy">CORP</abbr>
        </>
    ),
};

function HttpHeaders({ http }: { http: HttpSection }) {
    if (!http.reachable) {
        return (
            <Group>
                <Dl rows={[['', `Website unreachable: ${http.error ?? 'no response'}`]]} />
            </Group>
        );
    }
    const security = http.security ?? [];
    return (
        <>
            <Group>
                <Dl
                    rows={[
                        ['Final URL', `${http.url} (HTTP ${http.status})`],
                        ...(http.redirects?.length
                            ? [['Redirects', http.redirects.map((r, i) => <div key={i}>{`${r.status} ← ${r.url}`}</div>)] as Row]
                            : []),
                        ...security.map((h): Row => [HEADER_LABELS[h.name] ?? h.name, <span className="text-break">{h.value}</span>]),
                        ...(security.length === 0 ? [['', 'No security related headers found'] as Row] : []),
                    ]}
                />
            </Group>
            {http.headers && http.headers.length > 0 && (
                <details className="mt-2">
                    <summary className="text-body-secondary">All response headers</summary>
                    <CodeBlock>{http.headers.map((h) => `${h.name}: ${h.value}`).join('\n')}</CodeBlock>
                </details>
            )}
        </>
    );
}

function Certificate({ tls }: { tls: TlsSection }) {
    if (!tls.present) {
        return (
            <Group>
                <Dl rows={[['', `No SSL/TLS certificate found${tls.error ? ` (${tls.error})` : ''}`]]} />
            </Group>
        );
    }
    const subject = tls.subject ?? {};
    const issuer = tls.issuer ?? {};
    const remaining = timeUntil(tls.validTo);
    const problems = [
        tls.expired && 'Expired',
        tls.selfSigned && 'Self-signed',
        tls.hostnameMatches === false && "Doesn't cover this hostname",
    ].filter(Boolean) as string[];

    const named = (dn: Record<string, string>, keys: [string, string][]): Row[] =>
        keys.filter(([key]) => dn[key]).map(([key, label]) => [label, dn[key]]);

    return (
        <>
            <Group title="Summary">
                <Dl
                    rows={[
                        [
                            'Status',
                            problems.length ? (
                                problems.map((p) => (
                                    <Badge key={p} bg="danger" className="me-1">
                                        {p}
                                    </Badge>
                                ))
                            ) : (
                                <Badge bg="success">Valid for this hostname</Badge>
                            ),
                        ],
                        ...(tls.protocol ? [['Connection', `${tls.protocol}, ${tls.cipher}`] as Row] : []),
                    ]}
                />
            </Group>
            <Group title="Subject Name">
                <Dl
                    rows={named(subject, [
                        ['C', 'Country'],
                        ['ST', 'State/Province'],
                        ['L', 'Locality'],
                        ['O', 'Organization'],
                        ['CN', 'Common Name'],
                    ])}
                />
            </Group>
            <Group title="Issuer Name">
                <Dl
                    rows={named(issuer, [
                        ['C', 'Country'],
                        ['O', 'Organization'],
                        ['OU', 'Organizational Unit'],
                        ['CN', 'Common Name'],
                    ])}
                />
            </Group>
            <Group title="Validity">
                <Dl
                    rows={[
                        ['Valid From', formatDateTime(tls.validFrom)],
                        ['Valid Until', formatDateTime(tls.validTo)],
                        [remaining?.past ? 'Expired' : 'Expires in', remaining ? `${remaining.label}${remaining.past ? ' ago' : ''}` : 'Unknown'],
                    ]}
                />
            </Group>
            <Group title="Subject Alt Names">
                <Dl rows={(tls.altNames ?? []).map((name): Row => ['DNS Name', name])} />
            </Group>
            {tls.chain && tls.chain.length > 0 && (
                <Group title="Chain">
                    <Dl rows={tls.chain.map((c, i): Row => [`Intermediate ${i + 1}`, `${c.subject ?? '?'} (issued by ${c.issuer ?? '?'})`])} />
                </Group>
            )}
            <Group title="Public Key Info">
                <Dl
                    rows={[
                        ['Algorithm', tls.publicKey?.type],
                        ['Key Size', tls.publicKey?.bits ? `${tls.publicKey.bits} Bits` : <Muted>Unknown</Muted>],
                        ['Raw Public Value', tls.publicKey?.pem ? <CodeBlock>{tls.publicKey.pem}</CodeBlock> : <Muted>—</Muted>],
                    ]}
                />
            </Group>
            <Group title="Miscellaneous">
                <Dl
                    rows={[
                        ['Serial Number', <code>{colonHex(tls.serial ?? '')}</code>],
                        ['Signature Algorithm', tls.signatureAlgorithm],
                        ['Version', tls.version],
                    ]}
                />
            </Group>
            <Group title="Fingerprints">
                <Dl
                    rows={[
                        ['SHA-256', <code className="text-break">{colonHex(tls.fingerprints?.sha256 ?? '')}</code>],
                        ['SHA-1', <code className="text-break">{colonHex(tls.fingerprints?.sha1 ?? '')}</code>],
                        ['MD5', <code className="text-break">{colonHex(tls.fingerprints?.md5 ?? '')}</code>],
                    ]}
                />
            </Group>
            <Group title="Key Usages">
                <Dl
                    rows={[
                        ['Purposes', tls.keyUsage ?? <Muted>—</Muted>],
                        ['Extended', tls.extendedKeyUsage ?? <Muted>—</Muted>],
                    ]}
                />
            </Group>
            <Group title="Key IDs">
                <Dl
                    rows={[
                        ['Subject Key ID', <code>{tls.subjectKeyId ?? '—'}</code>],
                        ['Authority Key ID', <code>{tls.authorityKeyId ?? '—'}</code>],
                    ]}
                />
            </Group>
            <Group title="Certificate">
                <Dl rows={[['Raw Certificate', <CodeBlock copy>{tls.pem ?? ''}</CodeBlock>]]} />
            </Group>
        </>
    );
}
