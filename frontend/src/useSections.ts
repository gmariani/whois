import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchSection } from './api';
import type { SectionData, SectionName, SectionState } from './types';

export type Sections = { [K in SectionName]: SectionState<SectionData[K]> };

// Request order: what the General tab needs first, slow subdomain probing last.
const ORDER: SectionName[] = ['registration', 'network', 'dns', 'http', 'email', 'tls', 'locations', 'subdomains'];

const initial = Object.fromEntries(ORDER.map((name) => [name, { status: 'loading' }])) as Sections;

/**
 * Loads every results section independently and in parallel, so each part of
 * the page fills in as soon as its own data arrives.
 */
export function useSections(enabled: boolean): { sections: Sections; retry: (name: SectionName) => void } {
    const [sections, setSections] = useState<Sections>(initial);
    const controller = useRef<AbortController | null>(null);

    const load = useCallback((name: SectionName, signal: AbortSignal) => {
        setSections((prev) => ({ ...prev, [name]: { status: 'loading' } }));
        fetchSection(name, signal).then(
            ({ data, elapsedMs }) => setSections((prev) => ({ ...prev, [name]: { status: 'ready', data, elapsedMs } })),
            (error: unknown) => {
                if (signal.aborted) return;
                const message = error instanceof Error ? error.message : 'Something went wrong.';
                setSections((prev) => ({ ...prev, [name]: { status: 'error', error: message } }));
            },
        );
    }, []);

    useEffect(() => {
        if (!enabled) return;
        const abort = new AbortController();
        controller.current = abort;
        for (const name of ORDER) load(name, abort.signal);
        return () => abort.abort();
    }, [enabled, load]);

    const retry = useCallback(
        (name: SectionName) => {
            if (controller.current) load(name, controller.current.signal);
        },
        [load],
    );

    return { sections, retry };
}

export function isLoading(...states: SectionState<unknown>[]): boolean {
    return states.some((s) => s.status === 'loading');
}
