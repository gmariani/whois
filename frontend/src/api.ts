import type { BootConfig, SectionData, SectionName } from './types';

declare global {
    interface Window {
        __DOMAIN_INSPECTOR__: BootConfig;
    }
}

export const boot: BootConfig = window.__DOMAIN_INSPECTOR__ ?? {
    query: '',
    domain: null,
    token: null,
    error: null,
    base: '/',
    api: 'api.php',
    mapsKey: '',
};

export class ApiError extends Error {}

export async function fetchSection<K extends SectionName>(
    section: K,
    signal: AbortSignal,
): Promise<{ data: SectionData[K]; elapsedMs: number }> {
    if (!boot.domain || !boot.token) {
        throw new ApiError(boot.error ?? 'No domain to look up.');
    }

    const url = `${boot.api}?${new URLSearchParams({ section, q: boot.domain })}`;
    let response: Response;
    try {
        response = await fetch(url, {
            signal,
            credentials: 'same-origin',
            headers: {
                Accept: 'application/json',
                // Both headers are required by the API (see app/Http/ApiGuard.php).
                'X-Requested-With': 'DomainInspector',
                'X-Lookup-Token': boot.token,
            },
        });
    } catch (error) {
        if (signal.aborted) throw error;
        throw new ApiError('Network error — check your connection and try again.');
    }

    let body: { ok: boolean; data?: SectionData[K]; error?: string; meta?: { elapsedMs: number } };
    try {
        body = await response.json();
    } catch {
        throw new ApiError(`Unexpected response from the server (HTTP ${response.status}).`);
    }
    if (!response.ok || !body.ok || body.data === undefined) {
        throw new ApiError(body.error ?? `Request failed (HTTP ${response.status}).`);
    }
    return { data: body.data, elapsedMs: body.meta?.elapsedMs ?? 0 };
}
