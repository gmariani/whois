import type { GeoLocation } from '../types';

/** 90061 => "1d 1h 1m 1s" */
export function secondsToTime(seconds: number): string {
    const units: [string, number][] = [
        ['y', 31_536_000],
        ['d', 86_400],
        ['h', 3_600],
        ['m', 60],
        ['s', 1],
    ];
    const parts: string[] = [];
    let rest = Math.max(0, Math.floor(seconds));
    for (const [label, size] of units) {
        const amount = Math.floor(rest / size);
        if (amount > 0) {
            parts.push(`${amount}${label}`);
            rest -= amount * size;
        }
    }
    return parts.join(' ') || '0s';
}

export function formatDate(iso: string | null | undefined): string {
    if (!iso) return 'Unknown';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso;
    return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatDateTime(iso: string | null | undefined): string {
    if (!iso) return 'Unknown';
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return iso;
    return date.toUTCString();
}

/** Coarse time remaining until a date, e.g. "1y 340d"; null if unparseable. */
export function timeUntil(iso: string | null | undefined): { label: string; past: boolean; days: number } | null {
    if (!iso) return null;
    const ms = new Date(iso).getTime() - Date.now();
    if (Number.isNaN(ms)) return null;
    const days = Math.floor(Math.abs(ms) / 86_400_000);
    const label = secondsToTime(days * 86_400).replace(/ \d+[hms].*$/, '');
    return { label: days === 0 ? 'today' : label, past: ms < 0, days };
}

/** "ab12cd" => "AB:12:CD" */
export function colonHex(hex: string): string {
    return (hex.toUpperCase().replace(/[^0-9A-F]/g, '').match(/.{1,2}/g) ?? []).join(':');
}

export function base64ToHex(base64: string): string {
    try {
        return Array.from(atob(base64), (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    } catch {
        return '';
    }
}

export function locationLabel(location: GeoLocation | null | undefined): string {
    if (!location) return 'Unknown';
    const place = [location.city, location.region].filter(Boolean).join(', ');
    const label = [place, location.country].filter(Boolean).join(' ') || 'Unknown';
    return location.anycast ? `${label} (anycast — one of many locations)` : label;
}

/** "client transfer prohibited" => "clientTransferProhibited" (EPP status code) */
export function eppCode(status: string): string {
    const words = status.trim().split(/\s+/);
    return words.map((w, i) => (i === 0 ? w.toLowerCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())).join('');
}
