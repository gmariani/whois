import { useMemo, type ReactNode } from 'react';
import { Button, Spinner } from 'react-bootstrap';
import { Await, CopyButton, Muted, SectionTitle, Tip } from '../components/ui';
import { algorithmName, digestName, dnskeyFlags } from '../lib/dnssec';
import { locationLabel, secondsToTime } from '../lib/format';
import { mergeRecords, TYPE_LABELS, type DisplayRecord } from '../lib/records';
import { buildZoneFile, download } from '../lib/zoneFile';
import type { DnsSection, LocationsSection, SubdomainsSection } from '../types';
import type { Sections } from '../useSections';

type IpInfo = (ip: string) => string | null;

export function DnsTab({ sections, onRetry }: { sections: Sections; onRetry: (name: 'dns' | 'subdomains') => void }) {
    return (
        <Await state={sections.dns} label="Querying the domain's name servers" onRetry={() => onRetry('dns')}>
            {(dns) =>
                dns.delegated ? (
                    <DnsTables dns={dns} sections={sections} onRetry={onRetry} />
                ) : (
                    <p className="lead mt-4">This domain isn't delegated in DNS, so it has no records.</p>
                )
            }
        </Await>
    );
}

function DnsTables({ dns, sections, onRetry }: { dns: DnsSection; sections: Sections; onRetry: (name: 'subdomains') => void }) {
    const subdomains = sections.subdomains.status === 'ready' ? sections.subdomains.data : null;
    const locations = sections.locations.status === 'ready' ? sections.locations.data : null;
    const records = useMemo(() => mergeRecords(dns, subdomains), [dns, subdomains]);
    const ipInfo = useMemo(() => makeIpInfo(locations), [locations]);

    const hostInfo = (host: string): string | null => {
        const ips = dns.targets[host] ?? [];
        if (ips.length === 0) return null;
        return [ips.join(', '), ipInfo(ips[0])].filter(Boolean).join('\n');
    };

    return (
        <div className="row">
            <div className="col">
                {dns.records.ptr.length > 0 && (
                    <>
                        <SectionTitle>
                            Reverse <abbr title="Domain Name System">DNS</abbr> Record
                        </SectionTitle>
                        <div className="bd-group row">
                            <RecordTable records={dns.records.ptr.map((r) => ({ ...r, display: 'PTR' as const }))} hostInfo={hostInfo} ipInfo={ipInfo} />
                        </div>
                    </>
                )}

                <SectionTitle className="mt-4">
                    <abbr title="Domain Name System">DNS</abbr> Records
                </SectionTitle>
                <p className="text-body-secondary small mt-2 mb-0">
                    Answers straight from the zone's name servers ({dns.nameservers.map((n) => n.host).slice(0, 4).join(', ')}
                    {dns.nameservers.length > 4 && `, +${dns.nameservers.length - 4} more`}).
                </p>
                <div className="bd-group row">
                    <RecordTable records={records} hostInfo={hostInfo} ipInfo={ipInfo} />
                    <SubdomainStatus state={sections.subdomains} onRetry={() => onRetry('subdomains')} />
                </div>
                <Button
                    className="download-dns"
                    onClick={() => download(`${dns.zone}.db`, buildZoneFile(dns.zone ?? '', records))}
                    disabled={sections.subdomains.status === 'loading'}
                    title={sections.subdomains.status === 'loading' ? 'Waiting for subdomain checks to finish' : undefined}
                >
                    <i className="bi bi-download" />
                    &nbsp;Download Zone File
                </Button>
            </div>
        </div>
    );
}

function SubdomainStatus({ state, onRetry }: { state: Sections['subdomains']; onRetry: () => void }) {
    if (state.status === 'loading') {
        return (
            <p className="text-body-secondary small mb-0">
                <Spinner animation="border" size="sm" /> Checking common subdomains and service records…
            </p>
        );
    }
    if (state.status === 'error') {
        return (
            <p className="text-body-secondary small mb-0">
                Subdomain checks failed: {state.error}{' '}
                <Button size="sm" variant="link" onClick={onRetry}>
                    Retry
                </Button>
            </p>
        );
    }
    const data: SubdomainsSection = state.data;
    return (
        <p className="text-body-secondary small mb-0">
            Checked {data.checked} common names under {data.domains.join(' and ')}.
            {data.wildcard && ' A wildcard record exists, so matching answers were filtered out.'}
        </p>
    );
}

function makeIpInfo(locations: LocationsSection | null): IpInfo {
    return (ip) => {
        const info = locations?.ips?.[ip];
        if (!info) return null;
        return [info.location?.org, info.hostname, info.location ? locationLabel(info.location) : null].filter(Boolean).join('\n');
    };
}

function RecordTable({ records, hostInfo, ipInfo }: { records: DisplayRecord[]; hostInfo: (host: string) => string | null; ipInfo: IpInfo }) {
    return (
        <div className="table-responsive">
            <table className="table table-dark table-striped records mb-2">
                <thead>
                    <tr>
                        <th>Host</th>
                        <th>TTL</th>
                        <th>Type</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    {records.map((record, i) => (
                        <tr key={i}>
                            <td className="record-host">{record.host}</td>
                            <Tip label={`TTL — ${secondsToTime(record.ttl)}`}>
                                <td>{record.ttl}</td>
                            </Tip>
                            <Tip label={TYPE_LABELS[record.display] ?? record.display}>
                                <td>{record.display}</td>
                            </Tip>
                            <td className="record-value">
                                <RecordValue record={record} hostInfo={hostInfo} ipInfo={ipInfo} />
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

/** One labelled part of a record's data, with an explanation on hover. */
function Part({ tip, children }: { tip: string | null; children: ReactNode }) {
    return (
        <Tip label={tip}>
            <span className="record-part">{children}</span>
        </Tip>
    );
}

function RecordValue({ record, hostInfo, ipInfo }: { record: DisplayRecord; hostInfo: (host: string) => string | null; ipInfo: IpInfo }) {
    switch (record.type) {
        case 'A':
            return <Part tip={ipInfo(record.ip)}>{record.ip}</Part>;
        case 'AAAA':
            return <Part tip={ipInfo(record.ipv6)}>{record.ipv6}</Part>;
        case 'NS':
        case 'CNAME':
        case 'PTR':
            return <Part tip={hostInfo(record.target)}>{record.target}</Part>;
        case 'MX':
            return (
                <>
                    <Part tip="Priority (lower is tried first)">{record.pri}</Part>
                    <Part tip={hostInfo(record.target)}>{record.target}</Part>
                </>
            );
        case 'SRV':
            return (
                <>
                    <Part tip="Priority">{record.pri}</Part>
                    <Part tip="Weight">{record.weight}</Part>
                    <Part tip="Port">{record.port}</Part>
                    <Part tip={hostInfo(record.target)}>{record.target}</Part>
                </>
            );
        case 'SOA':
            return (
                <>
                    <Part tip="Primary name server">{record.mname}</Part>
                    <Part tip="Hostmaster e-mail address">{record.rname}</Part>
                    <Part tip="Serial #">{record.serial}</Part>
                    <Part tip={`Refresh — ${secondsToTime(record.refresh)}`}>{record.refresh}</Part>
                    <Part tip={`Retry — ${secondsToTime(record.retry)}`}>{record.retry}</Part>
                    <Part tip={`Expire — ${secondsToTime(record.expire)}`}>{record.expire}</Part>
                    <Part tip={`Default (negative) TTL — ${secondsToTime(record['minimum-ttl'])}`}>{record['minimum-ttl']}</Part>
                </>
            );
        case 'TXT':
            return (
                <>
                    <code>{record.txt}</code>
                    <CopyButton text={record.txt} />
                </>
            );
        case 'CAA':
            return (
                <>
                    <Part tip={record.flags & 128 ? 'Flags — critical' : 'Flags'}>{record.flags}</Part>
                    <Part tip="Tag">{record.tag}</Part>
                    <code>"{record.value}"</code>
                </>
            );
        case 'NAPTR':
            return (
                <>
                    <Part tip="Order">{record.order}</Part>
                    <Part tip="Preference">{record.pref}</Part>
                    <Part tip="Flags">"{record.flags}"</Part>
                    <Part tip="Service">"{record.services}"</Part>
                    <Part tip="Regexp">
                        <code>"{record.regex}"</code>
                    </Part>
                    <Part tip="Replacement">{record.replacement || '.'}</Part>
                </>
            );
        case 'DNSKEY': {
            const flags = dnskeyFlags(record.flags);
            return (
                <>
                    <Part tip={`Flags — zone key: ${flags.zoneKey ? 'yes' : 'no'}, secure entry point: ${flags.secureEntryPoint ? 'yes' : 'no'}`}>
                        {record.flags}
                    </Part>
                    <Part tip="Protocol">{record.protocol}</Part>
                    <Part tip={`Algorithm — ${algorithmName(record.algorithm)}`}>{record.algorithm}</Part>
                    <Part tip="Public key">
                        <code>{record.key}</code>
                    </Part>
                </>
            );
        }
        case 'DS':
            return (
                <>
                    <Part tip="Key tag">{record.keytag}</Part>
                    <Part tip={`Algorithm — ${algorithmName(record.algorithm)}`}>{record.algorithm}</Part>
                    <Part tip={`Digest type — ${digestName(record.digesttype)}`}>{record.digesttype}</Part>
                    <code>{record.digest}</code>
                </>
            );
    }
    return <Muted>—</Muted>;
}
