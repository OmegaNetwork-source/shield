// STRIX Directory Enumeration Module
// Discovers hidden files, directories, and sensitive paths

// Check if running in Electron
// @ts-ignore
const isElectron = typeof window !== 'undefined' && window.ipcRenderer !== undefined;

// ============================================================================
// WORDLISTS
// ============================================================================

export const WORDLISTS = {
    // Critical paths to check first
    critical: [
        '.git/HEAD',
        '.git/config',
        '.svn/entries',
        '.hg/hgrc',
        '.env',
        '.env.local',
        '.env.production',
        '.env.backup',
        'config.php',
        'wp-config.php',
        'configuration.php',
        'settings.py',
        'config.yml',
        'config.yaml',
        'database.yml',
        'secrets.yml',
        '.htaccess',
        '.htpasswd',
        'web.config',
        'server.xml',
        'phpinfo.php',
        'info.php',
        'test.php',
        'debug.php',
        'backup.sql',
        'dump.sql',
        'database.sql',
        'db.sql',
        'backup.zip',
        'backup.tar.gz',
        'site.zip',
        'www.zip',
        '.DS_Store',
        'Thumbs.db',
        'crossdomain.xml',
        'clientaccesspolicy.xml',
        'id_rsa',
        'id_rsa.pub',
        '.ssh/id_rsa',
        'credentials.json',
        'credentials.xml',
        'service-account.json',
        'firebase.json',
        'google-credentials.json',

        // Web3/Crypto specific
        '.env.development',
        '.env.staging',
        '.env.development.local',
        '.env.production.local',
        'env.js',
        'env.json',
        'config.json',
        'config.js',
        'settings.json',
        'settings.js',
        'secrets.json',
        'keys.json',
        'api-keys.json',
        'apikeys.json',
        'hardhat.config.js',
        'hardhat.config.ts',
        'truffle-config.js',
        'truffle.js',
        'foundry.toml',
        'brownie-config.yaml',
        '.secret',
        '.mnemonic',
        'mnemonic.txt',
        'seed.txt',
        'wallet.json',
        'keystore.json',
        'private-key.txt',
        'private_key.txt',
        'privatekey.txt',

        // API/Backend configs
        'package.json',
        'package-lock.json',
        'yarn.lock',
        '.npmrc',
        'next.config.js',
        'nuxt.config.js',
        'vite.config.js',
        'vercel.json',
        'netlify.toml',
        'docker-compose.yml',
        'docker-compose.yaml',
        'Dockerfile',
        '.dockerenv',
        'kubernetes.yml',
        'k8s.yml',

        // Source maps
        'main.js.map',
        'bundle.js.map',
        'app.js.map',
        'vendor.js.map',
        'index.js.map',
        'chunk.js.map',

        // Debug/Dev endpoints
        'debug',
        'debug.json',
        '_debug',
        '__debug',
        'actuator',
        'actuator/env',
        'actuator/health',
        'actuator/configprops',
        'metrics',
        'prometheus',
        'health',
        'healthz',
        'status',
        'info',
        '_info',
        'version',
        '_version',

        // Git exposure
        '.git/logs/HEAD',
        '.git/index',
        '.git/objects/',
        '.gitconfig',
    ],

    // Common directories
    common: [
        'admin',
        'administrator',
        'admin.php',
        'admin.html',
        'adminpanel',
        'admin-panel',
        'wp-admin',
        'cpanel',
        'dashboard',
        'login',
        'login.php',
        'signin',
        'auth',
        'authenticate',
        'api',
        'api/v1',
        'api/v2',
        'api/docs',
        'swagger',
        'swagger-ui',
        'graphql',
        'graphiql',
        'console',
        'shell',
        'manager',
        'management',
        'config',
        'configuration',
        'settings',
        'setup',
        'install',
        'installer',
        'backup',
        'backups',
        'bak',
        'old',
        'temp',
        'tmp',
        'test',
        'tests',
        'testing',
        'dev',
        'development',
        'staging',
        'debug',
        'phpmyadmin',
        'pma',
        'mysql',
        'database',
        'db',
        'sql',
        'upload',
        'uploads',
        'files',
        'assets',
        'static',
        'media',
        'images',
        'img',
        'css',
        'js',
        'scripts',
        'vendor',
        'node_modules',
        'packages',
        'lib',
        'libs',
        'include',
        'includes',
        'src',
        'source',
        'bin',
        'cgi-bin',
        'logs',
        'log',
        'error_log',
        'access_log',
        'private',
        'secret',
        'hidden',
        'secure',
        'internal',
        'portal',
        'intranet',
        'extranet',
        'webmail',
        'email',
        'mail',
        'forum',
        'blog',
        'news',
        'support',
        'help',
        'docs',
        'documentation',
        'readme',
        'changelog',
        'license',
        'robots.txt',
        'sitemap.xml',
        'sitemap',
        'humans.txt',
        'security.txt',
        '.well-known',
        '.well-known/security.txt',
        'server-status',
        'server-info',
    ],

    // API endpoints
    api: [
        'api',
        'api/v1',
        'api/v2',
        'api/v3',
        'api/users',
        'api/user',
        'api/auth',
        'api/login',
        'api/register',
        'api/config',
        'api/settings',
        'api/admin',
        'api/debug',
        'api/health',
        'api/status',
        'api/version',
        'api/info',
        'api/docs',
        'api/swagger.json',
        'api/openapi.json',
        'api/graphql',
        'v1',
        'v2',
        'v3',
        'rest',
        'rest/api',
        'graphql',
        'graphiql',
        'playground',
        'swagger',
        'swagger.json',
        'swagger.yaml',
        'swagger-ui',
        'swagger-ui.html',
        'api-docs',
        'openapi',
        'openapi.json',
        'openapi.yaml',
        'redoc',
        'actuator',
        'actuator/health',
        'actuator/info',
        'actuator/env',
        'actuator/mappings',
        'actuator/beans',
        'actuator/configprops',
        'actuator/heapdump',
        'actuator/threaddump',
        'metrics',
        'health',
        'healthcheck',
        'health-check',
        'ping',
        'status',
        'version',
        'info',
        'debug',
        'trace',
    ],

    // Backup/archive files
    backup: [
        'backup',
        'backup.zip',
        'backup.tar',
        'backup.tar.gz',
        'backup.tgz',
        'backup.rar',
        'backup.7z',
        'backup.sql',
        'backup.bak',
        'site.zip',
        'site.tar.gz',
        'www.zip',
        'www.tar.gz',
        'web.zip',
        'public.zip',
        'html.zip',
        'htdocs.zip',
        'database.sql',
        'database.zip',
        'db.sql',
        'db.zip',
        'dump.sql',
        'mysql.sql',
        'data.sql',
        'export.sql',
        '*.bak',
        '*.old',
        '*.orig',
        '*.save',
        '*.swp',
        '*.tmp',
        '*.temp',
        'index.php.bak',
        'config.php.bak',
        '.env.bak',
    ],

    // Version control
    vcs: [
        '.git',
        '.git/HEAD',
        '.git/config',
        '.git/logs/HEAD',
        '.git/index',
        '.git/objects',
        '.git/refs',
        '.gitignore',
        '.gitattributes',
        '.svn',
        '.svn/entries',
        '.svn/wc.db',
        '.hg',
        '.hg/hgrc',
        '.bzr',
        'CVS',
        'CVS/Root',
        'CVS/Entries',
    ],

    // Common CMS paths
    cms: [
        // WordPress
        'wp-admin',
        'wp-login.php',
        'wp-config.php',
        'wp-content',
        'wp-includes',
        'wp-json',
        'xmlrpc.php',
        'readme.html',
        'license.txt',

        // Drupal
        'sites/default/settings.php',
        'sites/default/files',
        'misc',
        'modules',
        'profiles',
        'themes',
        'CHANGELOG.txt',

        // Joomla
        'administrator',
        'configuration.php',
        'includes',
        'components',
        'modules',
        'plugins',
        'templates',

        // Magento
        'app/etc/local.xml',
        'app/etc/env.php',
        'downloader',
        'var/export',
        'var/backups',

        // SharePoint
        '_layouts',
        '_vti_bin',
        '_vti_pvt',
        'aspnet_client',
    ],
};

// ============================================================================
// INTERFACES
// ============================================================================

export interface DirectoryEnumOptions {
    wordlist?: 'critical' | 'common' | 'api' | 'backup' | 'vcs' | 'cms' | 'all';
    customPaths?: string[];
    timeout?: number;
    maxConcurrent?: number;
    followRedirects?: boolean;
    extensions?: string[];
    statusCodes?: number[];
    onProgress?: (current: number, total: number, path: string) => void;
}

export interface DiscoveredPath {
    path: string;
    url: string;
    status: number;
    contentType?: string;
    contentLength?: number;
    redirect?: string;
    sensitive: boolean;
    category: string;
    evidence?: string;
}

// Sensitive path indicators
const SENSITIVE_PATTERNS: Array<{ pattern: RegExp; category: string; severity: string }> = [
    { pattern: /\.git/i, category: 'Version Control', severity: 'critical' },
    { pattern: /\.svn/i, category: 'Version Control', severity: 'critical' },
    { pattern: /\.hg/i, category: 'Version Control', severity: 'critical' },
    { pattern: /\.env/i, category: 'Configuration', severity: 'critical' },
    { pattern: /config\.(php|yml|yaml|json|xml)/i, category: 'Configuration', severity: 'high' },
    { pattern: /settings\.(py|php|json)/i, category: 'Configuration', severity: 'high' },
    { pattern: /\.sql$/i, category: 'Database', severity: 'critical' },
    { pattern: /database|dump|backup/i, category: 'Backup', severity: 'high' },
    { pattern: /\.bak|\.old|\.orig/i, category: 'Backup', severity: 'medium' },
    { pattern: /admin|administrator|cpanel/i, category: 'Admin Panel', severity: 'medium' },
    { pattern: /phpinfo|info\.php/i, category: 'Information Disclosure', severity: 'medium' },
    { pattern: /\.htpasswd|\.htaccess/i, category: 'Server Config', severity: 'high' },
    { pattern: /web\.config/i, category: 'Server Config', severity: 'high' },
    { pattern: /id_rsa|\.pem|\.key/i, category: 'Private Key', severity: 'critical' },
    { pattern: /credentials|secrets/i, category: 'Credentials', severity: 'critical' },
    { pattern: /swagger|openapi|graphql/i, category: 'API Documentation', severity: 'low' },
    { pattern: /actuator|health|metrics/i, category: 'Monitoring', severity: 'medium' },
];

// ============================================================================
// FETCH HELPER
// ============================================================================

async function checkPath(url: string, options: DirectoryEnumOptions): Promise<{
    exists: boolean;
    status: number;
    contentType?: string;
    contentLength?: number;
    redirect?: string;
}> {
    try {
        if (isElectron) {
            // @ts-ignore
            const response = await window.ipcRenderer.invoke('web-scan-fetch', {
                url,
                method: 'HEAD', // Use HEAD for efficiency
                timeout: options.timeout || 10000,
                followRedirects: false
            });

            return {
                exists: response.status >= 200 && response.status < 400,
                status: response.status || 0,
                contentType: response.headers?.['content-type'],
                contentLength: response.headers?.['content-length'] ?
                    parseInt(response.headers['content-length']) : undefined,
                redirect: response.headers?.['location']
            };
        } else {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), options.timeout || 10000);

            const response = await fetch(url, {
                method: 'HEAD',
                signal: controller.signal,
                redirect: 'manual'
            });

            clearTimeout(timeoutId);

            return {
                exists: response.ok || response.status === 301 || response.status === 302,
                status: response.status,
                contentType: response.headers.get('content-type') || undefined,
                contentLength: response.headers.get('content-length') ?
                    parseInt(response.headers.get('content-length')!) : undefined,
                redirect: response.headers.get('location') || undefined
            };
        }
    } catch {
        return { exists: false, status: 0 };
    }
}

// ============================================================================
// MAIN FUNCTIONS
// ============================================================================

/**
 * Enumerate directories and files on a target
 */
export async function enumerateDirectories(
    baseUrl: string,
    options: DirectoryEnumOptions = {}
): Promise<DiscoveredPath[]> {
    const discovered: DiscoveredPath[] = [];

    // Build paths to check
    let paths: string[] = [];

    const wordlist = options.wordlist || 'common';
    if (wordlist === 'all') {
        paths = [
            ...WORDLISTS.critical,
            ...WORDLISTS.common,
            ...WORDLISTS.api,
            ...WORDLISTS.backup,
            ...WORDLISTS.vcs,
            ...WORDLISTS.cms,
        ];
    } else {
        paths = [...WORDLISTS[wordlist]];
    }

    // Add custom paths
    if (options.customPaths) {
        paths.push(...options.customPaths);
    }

    // Add extension variants
    if (options.extensions) {
        const withExtensions: string[] = [];
        for (const path of paths) {
            withExtensions.push(path);
            for (const ext of options.extensions) {
                if (!path.includes('.')) {
                    withExtensions.push(`${path}${ext}`);
                }
            }
        }
        paths = withExtensions;
    }

    // Remove duplicates
    paths = [...new Set(paths)];

    // Normalize base URL
    const base = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;

    // Acceptable status codes
    const acceptCodes = options.statusCodes || [200, 201, 204, 301, 302, 307, 308, 401, 403];

    // Check paths concurrently
    const maxConcurrent = options.maxConcurrent || 20;
    const results: Promise<DiscoveredPath | null>[] = [];

    for (let i = 0; i < paths.length; i++) {
        const path = paths[i];
        const fullUrl = `${base}/${path.startsWith('/') ? path.slice(1) : path}`;

        const checkPromise = (async (): Promise<DiscoveredPath | null> => {
            if (options.onProgress) {
                options.onProgress(i + 1, paths.length, path);
            }

            const result = await checkPath(fullUrl, options);

            if (result.exists || acceptCodes.includes(result.status)) {
                // Determine if sensitive
                let sensitive = false;
                let category = 'Directory';

                for (const { pattern, category: cat } of SENSITIVE_PATTERNS) {
                    if (pattern.test(path)) {
                        sensitive = true;
                        category = cat;
                        break;
                    }
                }

                return {
                    path,
                    url: fullUrl,
                    status: result.status,
                    contentType: result.contentType,
                    contentLength: result.contentLength,
                    redirect: result.redirect,
                    sensitive,
                    category
                };
            }

            return null;
        })();

        results.push(checkPromise);

        // Limit concurrency
        if (results.length >= maxConcurrent) {
            const batch = await Promise.all(results);
            for (const r of batch) {
                if (r) discovered.push(r);
            }
            results.length = 0;
        }
    }

    // Process remaining
    if (results.length > 0) {
        const batch = await Promise.all(results);
        for (const r of batch) {
            if (r) discovered.push(r);
        }
    }

    return discovered;
}

/**
 * Quick scan for critical/sensitive files only
 */
export async function quickDirectoryScan(baseUrl: string): Promise<DiscoveredPath[]> {
    return enumerateDirectories(baseUrl, {
        wordlist: 'critical',
        maxConcurrent: 30,
        timeout: 5000
    });
}

/**
 * Full directory enumeration
 */
export async function fullDirectoryScan(
    baseUrl: string,
    onProgress?: (current: number, total: number, path: string) => void
): Promise<DiscoveredPath[]> {
    return enumerateDirectories(baseUrl, {
        wordlist: 'all',
        maxConcurrent: 15,
        timeout: 10000,
        extensions: ['.php', '.asp', '.aspx', '.jsp', '.html', '.json', '.xml', '.txt'],
        onProgress
    });
}

/**
 * Scan for source map files from a list of JS file URLs
 */
export async function scanForSourceMaps(
    jsUrls: string[],
    onProgress?: (current: number, total: number, url: string) => void
): Promise<DiscoveredPath[]> {
    const discovered: DiscoveredPath[] = [];
    const allMapUrls: string[] = [];

    for (const jsUrl of jsUrls) {
        // Try common source map patterns
        const mapPatterns = [
            jsUrl + '.map',
            jsUrl.replace(/\.js$/, '.js.map'),
            jsUrl.replace(/\.min\.js$/, '.js.map'),
            jsUrl.replace(/\.js$/, '.map'),
        ];
        allMapUrls.push(...new Set(mapPatterns));
    }

    const uniqueMapUrls = [...new Set(allMapUrls)];
    const maxConcurrent = 10;

    for (let i = 0; i < uniqueMapUrls.length; i += maxConcurrent) {
        const batch = uniqueMapUrls.slice(i, i + maxConcurrent);
        const batchResults = await Promise.all(batch.map(async (mapUrl, index) => {
            const currentIndex = i + index + 1;
            if (onProgress) {
                onProgress(currentIndex, uniqueMapUrls.length, mapUrl);
            }

            try {
                const result = await checkPath(mapUrl, { timeout: 5000 });
                if (result.exists && result.contentType?.includes('json')) {
                    return {
                        path: mapUrl.split('/').pop() || mapUrl,
                        url: mapUrl,
                        status: result.status,
                        contentType: result.contentType,
                        contentLength: result.contentLength,
                        sensitive: true,
                        category: 'Source Map'
                    } as DiscoveredPath;
                }
            } catch {
                // Ignore errors
            }
            return null;
        }));

        for (const r of batchResults) {
            if (r) discovered.push(r);
        }
    }

    return discovered;
}

/**
 * Fetch and return content of a sensitive file (for secret scanning)
 */
export async function fetchSensitiveFileContent(url: string): Promise<{ content: string; url: string } | null> {
    try {
        if (isElectron) {
            // @ts-ignore
            const response = await window.ipcRenderer.invoke('web-scan-fetch', {
                url,
                method: 'GET',
                timeout: 10000
            });

            if (response.success && response.body) {
                return { content: response.body, url };
            }
        } else {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000);

            const response = await fetch(url, {
                method: 'GET',
                signal: controller.signal
            });

            clearTimeout(timeoutId);

            if (response.ok) {
                const content = await response.text();
                return { content, url };
            }
        }
    } catch {
        // Ignore errors
    }
    return null;
}

/**
 * Credential-focused file scan - fetches content and scans for secrets
 */
export const CREDENTIAL_FILES = [
    '.env',
    '.env.local',
    '.env.production',
    '.env.development',
    'env.js',
    'env.json',
    'config.json',
    'config.js',
    'settings.json',
    'secrets.json',
    'keys.json',
    'api-keys.json',
    'credentials.json',
    'firebase.json',
    '.npmrc',
    'package.json',
    'hardhat.config.js',
    'truffle-config.js',
    'next.config.js',
    'vercel.json',
    '.secret',
    'mnemonic.txt',
    'wallet.json',
];

export async function scanCredentialFiles(
    baseUrl: string,
    onProgress?: (current: number, total: number, file: string) => void
): Promise<{ file: string; url: string; content: string; hasSecrets: boolean }[]> {
    const results: { file: string; url: string; content: string; hasSecrets: boolean }[] = [];
    const base = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
    const maxConcurrent = 10;

    for (let i = 0; i < CREDENTIAL_FILES.length; i += maxConcurrent) {
        const batch = CREDENTIAL_FILES.slice(i, i + maxConcurrent);
        const batchResults = await Promise.all(batch.map(async (file, index) => {
            const currentIndex = i + index + 1;
            const url = `${base}/${file}`;

            if (onProgress) {
                onProgress(currentIndex, CREDENTIAL_FILES.length, file);
            }

            const result = await fetchSensitiveFileContent(url);
            if (result && result.content.length > 0 && result.content.length < 500000) {
                // Quick check for potential secrets
                const hasSecrets = /(?:api[_-]?key|secret|password|token|private|mnemonic|seed|credential)/i.test(result.content);
                return { file, url: result.url, content: result.content, hasSecrets };
            }
            return null;
        }));

        for (const r of batchResults) {
            if (r) results.push(r);
        }
    }

    return results;
}

export default {
    enumerateDirectories,
    quickDirectoryScan,
    fullDirectoryScan,
    scanForSourceMaps,
    fetchSensitiveFileContent,
    scanCredentialFiles,
    WORDLISTS,
    SENSITIVE_PATTERNS,
    CREDENTIAL_FILES
};
