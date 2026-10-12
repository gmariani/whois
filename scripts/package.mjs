// Builds dist/: exactly the files that go on the web server.
// Usage: npm run package   then upload the *contents* of dist/ (e.g. by FTP).

import { execSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const dist = join(root, 'dist');
const run = (cmd, cwd = root) => execSync(cmd, { cwd, stdio: 'inherit' });

console.log('\n› Building the front-end');
run('npm run build');

console.log('\n› Copying files to dist/');
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist);

const copy = (path, filter) => cpSync(join(root, path), join(dist, path), { recursive: true, filter });
for (const file of ['index.php', 'api.php', '.htaccess', '.user.ini', 'composer.json', 'composer.lock']) copy(file);
copy('build');
// Server code, but not the dev vendor/ (a production one is installed below).
copy('app', (src) => !relative(join(root, 'app'), src).startsWith('vendor'));
// storage/ ships empty apart from its access rules; the server fills it at runtime.
mkdirSync(join(dist, 'storage'));
copy('storage/.htaccess');

console.log('\n› Installing production PHP dependencies into dist/app/vendor');
run('composer install --no-dev --optimize-autoloader --no-interaction --quiet', dist);
rmSync(join(dist, 'composer.json'));
rmSync(join(dist, 'composer.lock'));

const size = (dir) =>
    readdirSync(dir).reduce((sum, name) => {
        const path = join(dir, name);
        return sum + (statSync(path).isDirectory() ? size(path) : statSync(path).size);
    }, 0);

console.log(`
✓ dist/ is ready (${(size(dist) / 1048576).toFixed(1)} MB)

Upload everything inside dist/ to the site folder (e.g. public_html/projects/dns/).
It never contains .env or storage data, so uploading over a live site is safe.
${existsSync(join(root, '.env')) ? '' : '\nFirst deploy: also create .env on the server (see .env-sample).\n'}`);
