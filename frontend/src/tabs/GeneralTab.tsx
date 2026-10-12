import { useMemo, type ReactNode } from 'react';
import { Badge } from 'react-bootstrap';
import { GoogleMap, type MapMarker } from '../components/GoogleMap';
import { Await, Dl, ExternalLink, HelpButton, Muted, SectionTitle } from '../components/ui';
import { formatDate, locationLabel, timeUntil } from '../lib/format';
import type { NetworkSection, RegistrationSection } from '../types';
import type { Sections } from '../useSections';

export function GeneralTab({ sections }: { sections: Sections }) {
    const { network, registration, dns, http, email } = sections;

    return (
        <>
            <div className="row g-4">
                <div className="col-lg-8">
                    <SectionTitle>General</SectionTitle>
                    <div className="bd-group row">
                        <Dl
                            labelCols={4}
                            rows={[
                                ['Server IP', <Await inline state={network}>{(n) => n.ip ?? <Muted>No A/AAAA record</Muted>}</Await>],
                                ['Reverse DNS', <Await inline state={network}>{(n) => n.hostname ?? <Muted>None</Muted>}</Await>],
                                ['Server Location', <Await inline state={network}>{(n) => (n.ip ? locationLabel(n.location) : 'Unknown')}</Await>],
                                ['Network', <Await inline state={network}>{(n) => <NetworkOwner network={n} />}</Await>],
                                ['Net Blocks', <Await inline state={network}>{(n) => <NetBlocks network={n} />}</Await>],
                                ['Domain Expiration', <Await inline state={registration}>{(r) => <Expiration registration={r} />}</Await>],
                                ['Domain Contact', <Await inline state={registration}>{(r) => <Registrant registration={r} />}</Await>],
                            ]}
                        />
                    </div>
                    <Await inline state={http}>
                        {(h) =>
                            h.reachable && (h.server || h.poweredBy || h.cdn) ? (
                                <div className="bd-group row">
                                    <Dl
                                        labelCols={4}
                                        rows={[
                                            ...(h.server ? [['Server Software', h.server] as [ReactNode, ReactNode]] : []),
                                            ...(h.poweredBy ? [['Powered By', h.poweredBy] as [ReactNode, ReactNode]] : []),
                                            ...(h.cdn ? [['CDN', h.cdn] as [ReactNode, ReactNode]] : []),
                                        ]}
                                    />
                                </div>
                            ) : null
                        }
                    </Await>
                </div>
                <div className="col-lg-4">
                    <Await state={network} label="Locating server">
                        {(n) => <ServerMap network={n} />}
                    </Await>
                </div>
            </div>

            <div className="row g-4 mt-1">
                <Card
                    title="Domain Name Registrar"
                    help="The domain name registrar is the company that the domain name was purchased through. This is who you would go to make changes to the domain name itself, such as transferring it to someone else, changing the name servers, or updating contact information."
                >
                    <Await inline state={registration}>
                        {(r) => {
                            const registrar = r.record?.registrar;
                            if (!r.registered) return 'Not registered';
                            if (!registrar) return 'Unknown';
                            return <ExternalLink href={registrar.url}>{registrar.label ?? registrar.name}</ExternalLink>;
                        }}
                    </Await>
                </Card>
                <Card
                    title={
                        <>
                            <abbr title="Domain Name System">DNS</abbr> Host
                        </>
                    }
                    help="The DNS host (or name server provider) is the company that hosts the DNS records for the domain name. This is who you would go to make changes to DNS records. The name servers are set at the registrar, and can be a different company from the registrar."
                >
                    <Await inline state={dns}>{(d) => (d.delegated ? d.dnsHosts.join(', ') || 'Unknown' : 'Not delegated')}</Await>
                </Card>
                <Card
                    title="Website Host"
                    help="Also known as a hosting provider, this is where the website is located. If there is no website, this will be blank."
                >
                    <Await inline state={network}>{(n) => (n.ip ? n.webHost ?? 'Unknown/Self' : <Muted>No website</Muted>)}</Await>
                </Card>
                <Card
                    title="Email Host"
                    help="Also known as an email provider, this is where the email is located. If the domain doesn't receive email, this will be blank."
                >
                    <Await inline state={email}>
                        {(e) =>
                            e.emailHost ? (
                                <>
                                    {e.emailHost.providers.join(', ')}
                                    {e.emailHost.via && <> (via {e.emailHost.via})</>}
                                </>
                            ) : (
                                <Muted>No MX records</Muted>
                            )
                        }
                    </Await>
                </Card>
            </div>
        </>
    );
}

function Card({ title, help, children }: { title: ReactNode; help: string; children: ReactNode }) {
    return (
        <div className="col-md-6">
            <h3>
                {title} <HelpButton>{help}</HelpButton>
            </h3>
            <div className="alert alert-light mb-0">{children}</div>
        </div>
    );
}

function NetworkOwner({ network }: { network: NetworkSection }) {
    const net = network.network;
    if (!net) return <Muted>{network.ip ? network.networkError ?? 'Unknown' : 'Unknown'}</Muted>;
    const org = net.organization;
    return (
        <>
            {org?.name ?? net.name ?? 'Unknown'}
            {(org?.handle || net.handle) && (
                <>
                    {' '}
                    (<ExternalLink href={org?.url ?? net.url}>{org?.handle ?? net.handle}</ExternalLink>)
                </>
            )}
            {net.registry && (
                <Badge bg="secondary" className="ms-2" title="Regional Internet Registry">
                    {net.registry}
                </Badge>
            )}
        </>
    );
}

function NetBlocks({ network }: { network: NetworkSection }) {
    const net = network.network;
    if (!net) return <Muted>Unknown</Muted>;
    return (
        <>
            <div>
                {net.startAddress} – {net.endAddress}
            </div>
            {net.cidrs.length > 0 && <Muted>{net.cidrs.join(', ')}</Muted>}
        </>
    );
}

function Expiration({ registration }: { registration: RegistrationSection }) {
    if (!registration.registered) return <Badge bg="warning" text="dark">Not registered</Badge>;
    const expires = registration.record?.expires;
    const remaining = timeUntil(expires);
    if (!expires || !remaining) return <Muted>Unknown</Muted>;
    return (
        <>
            {formatDate(expires)}{' '}
            {remaining.past ? (
                <span className="error">Expired</span>
            ) : (
                <Muted>
                    ({remaining.label}
                    {remaining.days < 30 && <span className="text-warning"> — renew soon</span>})
                </Muted>
            )}
        </>
    );
}

function Registrant({ registration }: { registration: RegistrationSection }) {
    const contact = registration.record?.registrant;
    if (!registration.registered) return <Muted>—</Muted>;
    if (!contact) return <Muted>Redacted for privacy</Muted>;
    const name = contact.name ?? contact.organization ?? 'Unknown';
    return (
        <>
            {contact.email ? <a href={`mailto:${contact.email}`}>{name}</a> : name}
            {contact.name && contact.organization && <>, {contact.organization}</>}
            {contact.country && <Muted> ({contact.country})</Muted>}
        </>
    );
}

function ServerMap({ network }: { network: NetworkSection }) {
    const location = network.location;
    const markers = useMemo<MapMarker[]>(() => {
        if (!network.ip || location?.lat == null || location.lon == null) return [];
        return [
            {
                lat: location.lat,
                lng: location.lon,
                title: 'Web Server',
                lines: [
                    { strong: location.org ?? network.network?.organization?.name ?? 'Web Server', text: '— Web Server' },
                    { strong: 'Host Name:', text: network.hostname ?? 'Unknown' },
                    { strong: 'IP:', text: network.ip },
                ],
            },
        ];
    }, [network, location]);
    return <GoogleMap markers={markers} zoom={10} className="map-single" />;
}
