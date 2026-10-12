<?php

declare(strict_types=1);

namespace Whois\Sections;

use Whois\Lookup\Context;

/**
 * Response headers from the website: server software and security headers.
 */
final class HttpSection implements Section
{
    private const SECURITY_HEADERS = [
        'content-security-policy' => 'Content-Security-Policy',
        'content-security-policy-report-only' => 'Content-Security-Policy-Report-Only',
        'strict-transport-security' => 'Strict-Transport-Security',
        'x-frame-options' => 'X-Frame-Options',
        'x-content-type-options' => 'X-Content-Type-Options',
        'referrer-policy' => 'Referrer-Policy',
        'permissions-policy' => 'Permissions-Policy',
        'cross-origin-opener-policy' => 'Cross-Origin-Opener-Policy',
        'cross-origin-resource-policy' => 'Cross-Origin-Resource-Policy',
        'x-xss-protection' => 'X-XSS-Protection',
        'public-key-pins' => 'Public-Key-Pins',
    ];

    public function build(Context $context): array
    {
        $http = $context->http();
        $response = null;
        foreach (["https://{$context->domain}/", "http://{$context->domain}/"] as $url) {
            // We only want headers, so stop reading the body early.
            $response = $http->get($url, ['Accept: text/html,*/*;q=0.8'], timeout: 8.0, maxRedirects: 5, maxBytes: 32_768);
            if ($response->status > 0) {
                break;
            }
        }

        if ($response === null || $response->status === 0) {
            return ['reachable' => false, 'error' => $response?->error ?? 'No response', 'url' => null];
        }

        $security = [];
        foreach (self::SECURITY_HEADERS as $key => $label) {
            if (($value = $response->header($key)) !== null) {
                $security[] = ['name' => $label, 'value' => $value];
            }
        }

        $cdn = match (true) {
            $response->header('cf-ray') !== null => 'Cloudflare',
            $response->header('x-amz-cf-id') !== null => 'Amazon CloudFront',
            $response->header('x-fastly-request-id') !== null || str_contains((string) $response->header('x-served-by'), 'cache-') => 'Fastly',
            $response->header('x-akamai-transformed') !== null || $response->header('akamai-grn') !== null => 'Akamai',
            $response->header('x-vercel-id') !== null => 'Vercel',
            $response->header('x-nf-request-id') !== null => 'Netlify',
            $response->header('x-azure-ref') !== null => 'Azure Front Door',
            default => null,
        };

        $headers = [];
        foreach ($response->headers as $name => $values) {
            if ($name !== 'set-cookie') {
                $headers[] = ['name' => $name, 'value' => implode(', ', $values)];
            }
        }

        return [
            'reachable' => true,
            'url' => $response->url,
            'status' => $response->status,
            'ip' => $response->ip,
            'redirects' => $response->redirects,
            'elapsedMs' => $response->elapsedMs,
            'server' => $response->header('server'),
            'poweredBy' => $response->header('x-powered-by'),
            'cdn' => $cdn,
            'security' => $security,
            'headers' => $headers,
        ];
    }
}
