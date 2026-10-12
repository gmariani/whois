import { useEffect, useState, type ReactNode } from 'react';
import { Alert, Nav, Spinner, Tab } from 'react-bootstrap';
import { boot } from './api';
import { SearchBar } from './components/SearchBar';
import { DnsTab } from './tabs/DnsTab';
import { EmailTab } from './tabs/EmailTab';
import { GeneralTab } from './tabs/GeneralTab';
import { MapTab } from './tabs/MapTab';
import { RegistrationTab } from './tabs/RegistrationTab';
import { SecurityTab } from './tabs/SecurityTab';
import { isLoading, useSections } from './useSections';

export function App() {
    const ready = Boolean(boot.domain && boot.token);
    return (
        <>
            <SearchBar initial={boot.query} />
            {boot.error && (
                <div className="container-xxl bd-gutter mt-4">
                    <Alert variant="warning">{boot.error}</Alert>
                </div>
            )}
            {ready && <Results domain={boot.domain as string} />}
        </>
    );
}

const TABS = ['general', 'dns', 'security', 'email', 'map', 'whois'] as const;
type TabKey = (typeof TABS)[number];

function initialTab(): TabKey {
    const hash = window.location.hash.slice(1);
    return (TABS as readonly string[]).includes(hash) ? (hash as TabKey) : 'general';
}

function Results({ domain }: { domain: string }) {
    const { sections, retry } = useSections(true);
    const [tab, setTab] = useState<TabKey>(initialTab);

    // Keep the active tab in the URL so it survives reloads and can be shared.
    useEffect(() => {
        const url = new URL(window.location.href);
        url.hash = tab === 'general' ? '' : tab;
        window.history.replaceState(null, '', url);
    }, [tab]);

    const s = sections;
    const tabs: { key: TabKey; title: ReactNode; busy: boolean }[] = [
        { key: 'general', title: 'General', busy: isLoading(s.registration, s.network, s.dns, s.http, s.email) },
        { key: 'dns', title: 'DNS', busy: isLoading(s.dns, s.subdomains) },
        { key: 'security', title: 'Security', busy: isLoading(s.dns, s.http, s.tls) },
        { key: 'email', title: 'Email', busy: isLoading(s.email) },
        { key: 'map', title: 'Map', busy: isLoading(s.locations) },
        { key: 'whois', title: 'WhoIs', busy: isLoading(s.registration) },
    ];

    return (
        <main className="container-xxl bd-gutter mt-3 my-md-4 bd-content">
            <h1 className="display-1 bd-title mb-5 text-center text-break">{domain}</h1>

            {/* Tabs mount on first view so maps get a visible container to size against. */}
            <Tab.Container activeKey={tab} onSelect={(key) => key && setTab(key as TabKey)} mountOnEnter>
                <Nav variant="pills" className="mb-3 justify-content-center" role="tablist">
                    {tabs.map(({ key, title, busy }) => (
                        <Nav.Item key={key}>
                            <Nav.Link eventKey={key}>
                                {title}
                                {busy && <Spinner animation="border" size="sm" className="ms-2 tab-spinner" aria-label="loading" />}
                            </Nav.Link>
                        </Nav.Item>
                    ))}
                </Nav>
                <Tab.Content>
                    <Tab.Pane eventKey="general">
                        <GeneralTab sections={s} />
                    </Tab.Pane>
                    <Tab.Pane eventKey="dns">
                        <DnsTab sections={s} onRetry={retry} />
                    </Tab.Pane>
                    <Tab.Pane eventKey="security">
                        <SecurityTab sections={s} onRetry={retry} />
                    </Tab.Pane>
                    <Tab.Pane eventKey="email">
                        <EmailTab sections={s} onRetry={() => retry('email')} />
                    </Tab.Pane>
                    <Tab.Pane eventKey="map">
                        <MapTab sections={s} onRetry={() => retry('locations')} />
                    </Tab.Pane>
                    <Tab.Pane eventKey="whois">
                        <RegistrationTab sections={s} onRetry={() => retry('registration')} />
                    </Tab.Pane>
                </Tab.Content>
            </Tab.Container>
        </main>
    );
}
