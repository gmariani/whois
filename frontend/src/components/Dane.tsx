import { tlsaMatching, tlsaSelector, tlsaUsage } from '../lib/dnssec';
import type { RecordOf } from '../types';
import { Dl, Muted } from './ui';

/** TLSA (DANE) records for one TLS service, explained. */
export function TlsaList({ records }: { records: RecordOf<'TLSA'>[] }) {
    if (records.length === 0) return <Muted>None published</Muted>;
    return (
        <>
            {records.map((r, i) => (
                <div key={i} className={i > 0 ? 'mt-2' : undefined}>
                    <div>{tlsaUsage(r.usage)}</div>
                    <Muted>
                        {tlsaSelector(r.selector)}, {tlsaMatching(r.matchingType)}
                    </Muted>
                    <div>
                        <code className="text-break">{r.data}</code>
                    </div>
                </div>
            ))}
        </>
    );
}

/** One row per host, e.g. each mail server. */
export function DaneTable({ entries }: { entries: { host: string; records: RecordOf<'TLSA'>[] }[] }) {
    return <Dl rows={entries.map((e) => [e.host, <TlsaList records={e.records} />])} />;
}
