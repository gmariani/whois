import { useState, type ReactElement, type ReactNode } from 'react';
import { Alert, Button, OverlayTrigger, Popover, Spinner, Tooltip } from 'react-bootstrap';
import type { SectionState } from '../types';

/**
 * Renders a section's data once it arrives. Block mode shows a spinner/error
 * panel; inline mode shows a placeholder bar inside a sentence or table cell.
 */
export function Await<T>({
    state,
    children,
    onRetry,
    inline = false,
    label,
}: {
    state: SectionState<T>;
    children: (data: T) => ReactNode;
    onRetry?: () => void;
    inline?: boolean;
    label?: string;
}) {
    if (state.status === 'loading') {
        return inline ? (
            <span className="placeholder-glow" aria-busy="true">
                <span className="placeholder col-6" />
            </span>
        ) : (
            <div className="section-loading" aria-busy="true">
                <Spinner animation="border" size="sm" role="status" /> <span>{label ?? 'Loading'}…</span>
            </div>
        );
    }
    if (state.status === 'error') {
        return inline ? (
            <span className="text-body-secondary" title={state.error}>
                Unavailable
            </span>
        ) : (
            <Alert variant="danger" className="d-flex align-items-center gap-3 my-3">
                <span className="flex-grow-1">{state.error}</span>
                {onRetry && (
                    <Button size="sm" variant="outline-light" onClick={onRetry}>
                        Retry
                    </Button>
                )}
            </Alert>
        );
    }
    return <>{children(state.data)}</>;
}

export function Tip({ label, children }: { label: ReactNode; children: ReactElement }) {
    if (label === null || label === undefined || label === '') return children;
    return (
        <OverlayTrigger placement="top" overlay={<Tooltip className="tip-multiline">{label}</Tooltip>}>
            {children}
        </OverlayTrigger>
    );
}

export function HelpButton({ children }: { children: ReactNode }) {
    return (
        <OverlayTrigger
            trigger="click"
            rootClose
            placement="top"
            overlay={
                <Popover>
                    <Popover.Body>{children}</Popover.Body>
                </Popover>
            }
        >
            <button type="button" className="btn btn-help" aria-label="What is this?">
                <i className="bi bi-question-circle" />
            </button>
        </OverlayTrigger>
    );
}

export function CopyButton({ text }: { text: string }) {
    const [copied, setCopied] = useState(false);
    return (
        <button
            type="button"
            className="btn btn-clipboard"
            title={copied ? 'Copied!' : 'Copy to clipboard'}
            onClick={() => {
                navigator.clipboard.writeText(text).then(() => {
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1200);
                });
            }}
        >
            <i className={`bi ${copied ? 'bi-check2' : 'bi-clipboard'}`} />
        </button>
    );
}

/** Label/value rows in the original page's two-column layout. */
export function Dl({ rows, labelCols = 3 }: { rows: [ReactNode, ReactNode][]; labelCols?: number }) {
    return (
        <dl className="row">
            {rows.map(([label, value], i) => (
                <DlRow key={i} label={label} labelCols={labelCols}>
                    {value}
                </DlRow>
            ))}
        </dl>
    );
}

function DlRow({ label, children, labelCols }: { label: ReactNode; children: ReactNode; labelCols: number }) {
    return (
        <>
            <dt className={`col-sm-${labelCols}`}>{label}</dt>
            <dd className={`col-sm-${12 - labelCols}`}>{children}</dd>
        </>
    );
}

export function Group({ title, children }: { title?: ReactNode; children: ReactNode }) {
    return (
        <div className="bd-group row">
            {title && <h3 className="bg-group-section-title col-sm-3">{title}</h3>}
            {children}
        </div>
    );
}

export function SectionTitle({ children, className = '' }: { children: ReactNode; className?: string }) {
    return <h2 className={`display-5 bd-group-title ${className}`}>{children}</h2>;
}

export function CodeBlock({ children, copy }: { children: string; copy?: boolean }) {
    return (
        <div className="bd-code-snippet">
            <div className="highlight">
                {copy && (
                    <div className="code-copy">
                        <CopyButton text={children} />
                    </div>
                )}
                <pre>{children}</pre>
            </div>
        </div>
    );
}

export function Muted({ children }: { children: ReactNode }) {
    return <span className="text-body-secondary">{children}</span>;
}

export function ExternalLink({ href, children }: { href: string | null | undefined; children: ReactNode }) {
    if (!href || !/^https?:\/\//i.test(href)) return <>{children}</>;
    return (
        <a href={href} target="_blank" rel="noopener noreferrer">
            {children}
        </a>
    );
}
