import type { FormEvent } from 'react';
import { boot } from '../api';

/**
 * Each lookup is a fresh page load at <base>/<domain>/, which gives it its own
 * API token. The server cleans up whatever was typed (URLs, paths, case).
 */
function go(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = new FormData(event.currentTarget).get('q')?.toString().trim() ?? '';
    window.location.assign(boot.base + (value ? `${encodeURI(value)}/` : ''));
}

export function SearchBar({ initial }: { initial: string }) {
    return (
        <header className="navbar navbar-expand-lg bd-navbar">
            <nav className="container-xxl bd-gutter flex-wrap flex-lg-nowrap">
                <form method="get" className="search-form" action={boot.base} role="search" onSubmit={go}>
                    <label className="search-magnifier-label" htmlFor="search-input">
                        <svg width="20" height="20" className="search-icon" viewBox="0 0 20 20" aria-hidden="true">
                            <path
                                d="M14.386 14.386l4.0877 4.0877-4.0877-4.0877c-2.9418 2.9419-7.7115 2.9419-10.6533 0-2.9419-2.9418-2.9419-7.7115 0-10.6533 2.9418-2.9419 7.7115-2.9419 10.6533 0 2.9419 2.9418 2.9419 7.7115 0 10.6533z"
                                stroke="currentColor"
                                fill="none"
                                fillRule="evenodd"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                            />
                        </svg>
                        <span className="visually-hidden">Domain</span>
                    </label>
                    <input
                        id="search-input"
                        className="search-input"
                        placeholder="Enter a domain"
                        name="q"
                        defaultValue={initial}
                        type="text"
                        autoComplete="off"
                        autoCapitalize="off"
                        spellCheck={false}
                        autoFocus={!initial}
                    />
                </form>
            </nav>
        </header>
    );
}
