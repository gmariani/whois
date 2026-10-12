<?php

declare(strict_types=1);

namespace Whois\Http;

use Whois\Config;

/**
 * Emits the <script>/<link> tags for the React bundle: the Vite dev server
 * (with hot reload) in development, the hashed files from build/ otherwise.
 */
final class Vite
{
    private const ENTRY = 'frontend/src/main.tsx';
    private const BUILD_DIR = 'build';

    /**
     * @param string $base URL path of the app directory, e.g. "/projects/dns/"
     */
    public function __construct(private readonly Config $config, private readonly string $base = '/')
    {
    }

    public function tags(): string
    {
        if ($this->config->viteDevServer !== null) {
            $dev = htmlspecialchars($this->config->viteDevServer, ENT_QUOTES);
            return <<<HTML
                <script type="module">
                    import RefreshRuntime from '{$dev}/@react-refresh';
                    RefreshRuntime.injectIntoGlobalHook(window);
                    window.\$RefreshReg\$ = () => {};
                    window.\$RefreshSig\$ = () => (type) => type;
                    window.__vite_plugin_react_preamble_installed__ = true;
                </script>
                <script type="module" src="{$dev}/@vite/client"></script>
                <script type="module" src="{$dev}/{$this->entry()}"></script>
                HTML;
        }

        $manifestFile = $this->config->rootDir . '/' . self::BUILD_DIR . '/.vite/manifest.json';
        $manifest = is_file($manifestFile) ? json_decode((string) file_get_contents($manifestFile), true) : null;
        $chunk = $manifest[self::ENTRY] ?? null;
        if ($chunk === null) {
            return '<p class="container text-danger mt-5">Front-end not built. Run <code>npm ci &amp;&amp; npm run build</code>.</p>';
        }

        $tags = [];
        foreach ($chunk['css'] ?? [] as $css) {
            $tags[] = sprintf('<link rel="stylesheet" href="%s">', $this->asset($css));
        }
        foreach ($chunk['imports'] ?? [] as $import) {
            if (isset($manifest[$import]['file'])) {
                $tags[] = sprintf('<link rel="modulepreload" href="%s">', $this->asset($manifest[$import]['file']));
            }
        }
        $tags[] = sprintf('<script type="module" src="%s"></script>', $this->asset($chunk['file']));
        return implode("\n    ", $tags);
    }

    private function entry(): string
    {
        return self::ENTRY;
    }

    private function asset(string $file): string
    {
        // Absolute path: pages live at <base>/<domain>/, so relative URLs would break.
        return htmlspecialchars($this->base . self::BUILD_DIR . '/' . $file, ENT_QUOTES);
    }
}
