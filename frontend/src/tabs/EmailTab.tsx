import type { ReactNode } from 'react';
import { Alert, Badge } from 'react-bootstrap';
import { Await, CodeBlock, CopyButton, Dl, Group, Muted, SectionTitle } from '../components/ui';
import { locationLabel } from '../lib/format';
import type { EmailSection, SpfServer, SpfTerm } from '../types';
import type { Sections } from '../useSections';

type Row = [ReactNode, ReactNode];
type Spf = NonNullable<EmailSection['spf']>;

export function EmailTab({ sections, onRetry }: { sections: Sections; onRetry: () => void }) {
    return (
        <Await state={sections.email} label="Checking SPF, DKIM and DMARC" onRetry={onRetry}>
            {(email) => (
                <>
                    <SectionTitle>
                        <abbr title="Sender Policy Framework">SPF</abbr> Records
                    </SectionTitle>
                    <div className="bd-group row">{email.spf ? <SpfDetails spf={email.spf} /> : <p>None</p>}</div>

                    <SectionTitle className="mt-5">
                        <abbr title="DomainKeys Identified Mail">DKIM</abbr> Records
                    </SectionTitle>
                    <div className="bd-group row">
                        <p>
                            <em>
                                Checks common selectors:{' '}
                                {Object.entries(groupSelectors(email.dkimSelectors))
                                    .map(([provider, selectors]) => `${selectors.join(', ')} (${provider})`)
                                    .join('; ')}
                            </em>
                        </p>
                        {email.dkim.length ? email.dkim.map((key) => <DkimKey key={key.host} dkim={key} />) : <Dl rows={[['', 'None found']]} />}
                    </div>

                    <SectionTitle className="mt-5">
                        <abbr title="Domain-based Message Authentication, Reporting & Conformance">DMARC</abbr> Record
                    </SectionTitle>
                    <div className="bd-group row">{email.dmarc ? <Dmarc dmarc={email.dmarc} /> : <Dl rows={[['', 'None']]} />}</div>
                </>
            )}
        </Await>
    );
}

function groupSelectors(selectors: Record<string, string>): Record<string, string[]> {
    const out: Record<string, string[]> = {};
    for (const [selector, provider] of Object.entries(selectors)) (out[provider] ??= []).push(selector);
    return out;
}

// ---------------------------------------------------------------- SPF

const QUALIFIER_HELP: Record<string, string> = {
    pass: 'Pass — allowed to send',
    fail: 'Fail — reject mail from these senders',
    softfail: 'Soft fail — accept but mark as suspicious',
    neutral: 'Neutral — no opinion',
};

function SpfDetails({ spf }: { spf: Spf }) {
    return (
        <>
            {spf.warnings.map((w) => (
                <Alert key={w} variant="warning" className="py-2">
                    {w}
                </Alert>
            ))}
            <Dl
                rows={[
                    [
                        'Record',
                        <>
                            <code>{spf.raw}</code>
                            <CopyButton text={spf.raw} />
                        </>,
                    ],
                    [
                        'DNS lookups',
                        <Badge bg={spf.lookups > spf.lookupLimit ? 'danger' : spf.lookups >= spf.lookupLimit - 1 ? 'warning' : 'secondary'}>
                            {spf.lookups} / {spf.lookupLimit}
                        </Badge>,
                    ],
                ]}
            />
            <div className="table-responsive">
                <table className="table table-dark table-striped records">
                    <thead>
                        <tr>
                            <th>Action</th>
                            <th>Mechanism/Address</th>
                            <th>Host/IP/Value</th>
                            <th>Location</th>
                        </tr>
                    </thead>
                    <tbody>
                        {spf.terms.map((term, i) => (
                            <SpfRow key={i} term={term} spf={spf} />
                        ))}
                    </tbody>
                </table>
            </div>
        </>
    );
}

function SpfRow({ term, spf }: { term: SpfTerm; spf: Spf }) {
    const action = term.qualifier ?? 'modifier';
    const servers = term.servers ?? [];
    let value: ReactNode = null;
    let location: ReactNode = null;

    if (term.mechanism === 'include' || term.mechanism === 'redirect') {
        value = <Included name={term.value ?? ''} spf={spf} seen={new Set()} />;
    } else if (servers.length) {
        value = servers.map((s, i) => <div key={i}>{serverLabel(s)}</div>);
        location = servers.map((s, i) => (
            <div key={i}>
                {s.location?.org ?? <Muted>Unknown</Muted>}
                <br />
                <Muted>{locationLabel(s.location)}</Muted>
            </div>
        ));
    } else if ((term.mechanism === 'ip4' || term.mechanism === 'ip6') && term.cidr) {
        value = <Muted>Address range {term.value}{term.cidr}</Muted>;
    } else if (term.mechanism === 'a' || term.mechanism === 'mx') {
        value = <Muted>No addresses found</Muted>;
    } else if (term.mechanism === 'ptr') {
        value = <Muted>Deprecated mechanism (RFC 7208 §5.5)</Muted>;
    }

    return (
        <tr>
            <th className={`spf-${action}`} title={QUALIFIER_HELP[action]}>
                {action}
            </th>
            <td className="text-break">{term.raw}</td>
            <td className="text-break">{value}</td>
            <td>{location}</td>
        </tr>
    );
}

function serverLabel(server: SpfServer): ReactNode {
    return (
        <>
            {server.ip}
            {(server.hostname || server.host) && (
                <>
                    <br />
                    <Muted>{server.hostname ?? server.host}</Muted>
                </>
            )}
        </>
    );
}

/** An include:/redirect= target, expandable to show what it allows in turn. */
function Included({ name, spf, seen }: { name: string; spf: Spf; seen: Set<string> }) {
    const key = name.toLowerCase().replace(/\.$/, '');
    const record = spf.includes[key];
    if (record === undefined) return <code>{name}</code>;
    if (record === null) return <span className="text-warning">No SPF record at {name}</span>;
    if (seen.has(key)) return <Muted>(loop)</Muted>;
    const next = new Set(seen).add(key);

    return (
        <details>
            <summary>
                <code>{record.raw}</code>
            </summary>
            <ul className="spf-tree">
                {record.terms.map((term, i) => (
                    <li key={i}>
                        <span className={`spf-${term.qualifier ?? 'modifier'}`}>{term.raw}</span>
                        {(term.mechanism === 'include' || term.mechanism === 'redirect') && term.value && (
                            <Included name={term.value} spf={spf} seen={next} />
                        )}
                    </li>
                ))}
            </ul>
        </details>
    );
}

// --------------------------------------------------------------- DKIM

const DKIM_FLAGS: Record<string, string> = {
    s: "Any DKIM-Signature header fields using the 'i=' tag MUST have the same domain value on the right-hand side of the '@' as the 'd=' tag.",
    y: 'This domain is testing DKIM. Verifiers MUST NOT treat messages from Signers in testing mode differently from unsigned email.',
};

function DkimKey({ dkim }: { dkim: EmailSection['dkim'][number] }) {
    const t = dkim.tags;
    const rows: Row[] = [
        [
            'Selector',
            <>
                {dkim.host}
                {dkim.cname && <abbr title="CNAME"> → {dkim.cname}</abbr>}
                {dkim.provider && <Muted> ({dkim.provider})</Muted>}
            </>,
        ],
        [
            'Key Size',
            dkim.revoked ? (
                <Badge bg="secondary">Revoked (empty key)</Badge>
            ) : (
                <>
                    {dkim.keyBits ?? '?'} Bits
                    {dkim.weak && (
                        <Badge bg="danger" className="ms-2">
                            Insecure (&lt;1024)
                        </Badge>
                    )}
                </>
            ),
        ],
    ];
    if (t.v) rows.push(['Version', t.v]);
    if (t.g) rows.push(['Key Granularity', t.g]);
    if (t.h) rows.push(['Hash Algorithm', t.h]);
    rows.push(['Key Type', dkim.keyType]);
    if (t.n) rows.push(['Notes', t.n]);
    if (t.s) rows.push(['Service Type', t.s]);
    if (t.t) {
        rows.push([
            'Flags',
            t.t.split(':').map((flag) => (
                <abbr key={flag} title={DKIM_FLAGS[flag.trim().toLowerCase()] ?? ''} className="me-2">
                    {flag.trim()}
                </abbr>
            )),
        ]);
    }
    if (dkim.publicKey) rows.push(['Public Key', <CodeBlock>{dkim.publicKey}</CodeBlock>]);
    rows.push(['Raw', <CodeBlock copy>{dkim.raw}</CodeBlock>]);

    return (
        <Group>
            <Dl rows={rows} />
        </Group>
    );
}

// -------------------------------------------------------------- DMARC

const POLICY: Record<string, string> = {
    none: 'none — monitor only',
    quarantine: 'quarantine — send failures to spam',
    reject: 'reject — refuse failures',
};

function Dmarc({ dmarc }: { dmarc: NonNullable<EmailSection['dmarc']> }) {
    const t = dmarc.tags;
    const alignment = (v?: string) => (v === 's' ? 'Strict Mode' : v === 'r' ? 'Relaxed Mode' : v);
    const rows: Row[] = [];
    const add = (label: string, value: ReactNode | undefined) => value !== undefined && value !== '' && rows.push([label, value]);

    add('Version', t.v);
    add('Policy for domain', t.p && (POLICY[t.p.toLowerCase()] ?? t.p));
    add('Policy for subdomains', t.sp && (POLICY[t.sp.toLowerCase()] ?? t.sp));
    add('Messages subject to filtering', t.pct && `${t.pct}%`);
    add('Alignment mode for DKIM', alignment(t.adkim));
    add('Alignment mode for SPF', alignment(t.aspf));
    add('Send aggregate reports to', t.rua);
    add('Send forensic reports to', t.ruf);
    add('Failure reporting options', t.fo);
    add('Failure report format', t.rf);
    add('Interval between aggregate reports', t.ri && `${t.ri} seconds`);
    rows.push([
        'Raw',
        <>
            <code>{dmarc.raw}</code>
            <CopyButton text={dmarc.raw} />
        </>,
    ]);
    return <Dl rows={rows} />;
}
