import type { ReactNode } from 'react';
import { Badge } from 'react-bootstrap';
import { Await, CodeBlock, Dl, ExternalLink, Muted, SectionTitle } from '../components/ui';
import { eppCode, formatDate, timeUntil } from '../lib/format';
import type { RegistrationSection } from '../types';
import type { Sections } from '../useSections';

type Row = [ReactNode, ReactNode];

export function RegistrationTab({ sections, onRetry }: { sections: Sections; onRetry: () => void }) {
    return (
        <Await state={sections.registration} label="Asking the registry" onRetry={onRetry}>
            {(registration) => <Registration registration={registration} />}
        </Await>
    );
}

function Registration({ registration: r }: { registration: RegistrationSection }) {
    const source =
        r.source === 'rdap' ? (
            <>
                <abbr title="Registration Data Access Protocol">RDAP</abbr> — <ExternalLink href={r.server}>{r.server}</ExternalLink>
            </>
        ) : r.source === 'whois' ? (
            <>WHOIS — {r.server} (this TLD has no RDAP service)</>
        ) : (
            <Muted>No registration service answered{r.server ? ` (${r.server})` : ''}</Muted>
        );

    const rec = r.record;
    const rows: Row[] = [
        ['Domain', r.domain],
        ['Source', source],
    ];

    if (!r.registered) {
        rows.push(['Status', <Badge bg="warning" text="dark">Not registered — this domain may be available</Badge>]);
    } else if (rec) {
        const registrar = rec.registrar;
        if (registrar) {
            rows.push([
                'Registrar',
                <>
                    <ExternalLink href={registrar.url}>{registrar.name}</ExternalLink>
                    {registrar.ianaId && <Muted> (IANA ID {registrar.ianaId})</Muted>}
                </>,
            ]);
            if (registrar.abuseEmail || registrar.abusePhone) {
                rows.push([
                    'Registrar Abuse Contact',
                    [registrar.abuseEmail && <a key="e" href={`mailto:${registrar.abuseEmail}`}>{registrar.abuseEmail}</a>, registrar.abusePhone]
                        .filter(Boolean)
                        .map((v, i) => <div key={i}>{v}</div>),
                ]);
            }
        }
        rows.push(['Created', formatDate(rec.created)]);
        rows.push(['Updated', formatDate(rec.updated)]);
        const remaining = timeUntil(rec.expires);
        rows.push([
            'Expires',
            <>
                {formatDate(rec.expires)}
                {remaining && (remaining.past ? <span className="error"> Expired</span> : <Muted> (in {remaining.label})</Muted>)}
            </>,
        ]);
        if (rec.status.length) {
            rows.push([
                'Status',
                rec.status.map((s) => (
                    <div key={s}>
                        <a href={`https://icann.org/epp#${eppCode(s)}`} target="_blank" rel="noopener noreferrer">
                            {s}
                        </a>
                    </div>
                )),
            ]);
        }
        rows.push(['Name Servers', rec.nameservers.length ? rec.nameservers.map((ns) => <div key={ns}>{ns}</div>) : <Muted>None listed</Muted>]);
        rows.push(['DNSSEC', rec.dnssec === null ? <Muted>Unknown</Muted> : rec.dnssec ? 'Signed delegation' : 'Unsigned']);

        const c = rec.registrant;
        rows.push([
            'Registrant',
            c ? (
                <>
                    {[c.name, c.organization].filter(Boolean).join(', ') || <Muted>Name withheld</Muted>}
                    {c.email && (
                        <div>
                            <a href={`mailto:${c.email}`}>{c.email}</a>
                        </div>
                    )}
                    {c.phone && <div>{c.phone}</div>}
                    {c.address && <div className="pre-line">{c.address}</div>}
                    {c.country && !c.address && <div>{c.country}</div>}
                </>
            ) : (
                <Muted>Redacted for privacy</Muted>
            ),
        ]);
    }

    return (
        <>
            <SectionTitle>Registration</SectionTitle>
            <div className="bd-group row">
                <Dl rows={rows} />
            </div>
            {r.raw.map((raw) => (
                <details key={raw.label} className="mt-3" open={r.source === 'whois'}>
                    <summary className="text-body-secondary">
                        Raw {raw.label.toLowerCase()} response{raw.source && <> from {raw.source}</>}
                    </summary>
                    <CodeBlock copy>{raw.text}</CodeBlock>
                </details>
            ))}
        </>
    );
}
