import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// index.php is the HTML page; Vite only bundles the script it loads.
// Development: `npm run serve` (PHP on :8000) + `npm run dev` (Vite on :5173),
// with APP_ENV=development and VITE_DEV_SERVER=http://localhost:5173 in .env.
export default defineConfig({
    plugins: [react()],
    // Relative asset URLs so the site works from a sub-directory (e.g. /projects/dns/).
    base: './',
    build: {
        outDir: 'build',
        emptyOutDir: true,
        manifest: true,
        rolldownOptions: {
            input: 'frontend/src/main.tsx',
        },
    },
    server: {
        port: 5173,
        strictPort: true,
        origin: 'http://localhost:5173',
        cors: { origin: 'http://localhost:8000' },
    },
});
