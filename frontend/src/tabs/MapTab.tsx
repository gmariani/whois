import { useMemo } from 'react';
import { GoogleMap, type MapMarker } from '../components/GoogleMap';
import { Await } from '../components/ui';
import type { LocationsSection } from '../types';
import type { Sections } from '../useSections';

export function MapTab({ sections, onRetry }: { sections: Sections; onRetry: () => void }) {
    return (
        <Await state={sections.locations} label="Locating servers" onRetry={onRetry}>
            {(locations) => <AllServers locations={locations} />}
        </Await>
    );
}

function AllServers({ locations }: { locations: LocationsSection }) {
    const markers = useMemo<MapMarker[]>(
        () =>
            locations.markers.map((m) => ({
                lat: m.lat,
                lng: m.lng,
                title: [...new Set(m.servers.map((s) => s.role))].join(', '),
                lines: m.servers.flatMap((s, i) => [
                    ...(i > 0 ? [{ text: ' ' }] : []),
                    { strong: s.org ?? 'Unknown', text: `— ${s.role}` },
                    { strong: 'Host Name:', text: s.host },
                    { strong: 'IP:', text: s.ip },
                    ...(s.anycast ? [{ strong: 'Anycast:', text: 'served from many locations; this is one of them' }] : []),
                ]),
            })),
        [locations],
    );
    return <GoogleMap markers={markers} zoom={5} className="google-map--tall" />;
}
