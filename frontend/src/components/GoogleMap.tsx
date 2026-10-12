import { useEffect, useRef, useState } from 'react';
import { boot } from '../api';

export interface MapMarker {
    lat: number;
    lng: number;
    title: string;
    /** Plain-text lines for the info window (rendered as text, never HTML). */
    lines: { strong?: string; text: string }[];
}

let loader: Promise<void> | null = null;

/** Load the Maps JavaScript API once, on first use. */
function loadMaps(key: string): Promise<void> {
    if (window.google?.maps?.Map) return Promise.resolve();
    loader ??= new Promise<void>((resolve, reject) => {
        const callback = '__domainInspectorMapsReady';
        (window as unknown as Record<string, () => void>)[callback] = () => resolve();
        const script = document.createElement('script');
        script.src = `https://maps.googleapis.com/maps/api/js?${new URLSearchParams({ key, callback, loading: 'async' })}`;
        script.async = true;
        script.onerror = () => {
            loader = null;
            reject(new Error('Google Maps failed to load'));
        };
        document.head.appendChild(script);
    });
    return loader;
}

function infoContent(marker: MapMarker): HTMLElement {
    const root = document.createElement('div');
    root.className = 'map-info';
    for (const line of marker.lines) {
        const row = document.createElement('div');
        if (line.strong) {
            const strong = document.createElement('strong');
            strong.textContent = line.strong;
            row.append(strong, ' ');
        }
        row.append(line.text);
        root.append(row);
    }
    return root;
}

export function GoogleMap({ markers, zoom, className = '' }: { markers: MapMarker[]; zoom: number; className?: string }) {
    const ref = useRef<HTMLDivElement>(null);
    const [error, setError] = useState<string | null>(boot.mapsKey ? null : 'Map unavailable (no Google Maps key configured).');

    useEffect(() => {
        if (!boot.mapsKey || !ref.current || markers.length === 0) return;
        let cancelled = false;
        const placed: google.maps.Marker[] = [];

        loadMaps(boot.mapsKey).then(
            () => {
                if (cancelled || !ref.current) return;
                const map = new google.maps.Map(ref.current, { center: markers[0], zoom });
                const bounds = new google.maps.LatLngBounds();
                const info = new google.maps.InfoWindow();
                for (const m of markers) {
                    const marker = new google.maps.Marker({ position: m, title: m.title, map });
                    marker.addListener('click', () => {
                        info.setContent(infoContent(m));
                        info.open({ map, anchor: marker });
                    });
                    placed.push(marker);
                    bounds.extend(m);
                }
                if (markers.length > 1) map.fitBounds(bounds, 48);
            },
            (e: Error) => !cancelled && setError(e.message),
        );

        return () => {
            cancelled = true;
            placed.forEach((m) => m.setMap(null));
        };
    }, [markers, zoom]);

    if (error) return <div className={`google-map map-empty ${className}`}>{error}</div>;
    if (markers.length === 0) return <div className={`google-map map-empty ${className}`}>No location available</div>;
    return <div ref={ref} className={`google-map ${className}`} />;
}
