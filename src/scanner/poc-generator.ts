
import { UnifiedVulnerability } from './types';

export interface PoCArtifacts {
    curl: string;
    python: string;
    javascript: string;
}

/**
 * Generates Proof of Concept (PoC) scripts for a given vulnerability
 */
export function generatePoC(vuln: UnifiedVulnerability): PoCArtifacts | null {
    // If we don't have a URL, we can't generate a web PoC
    if (!vuln.url) return null;

    const method = vuln.method || 'GET';
    const targetUrl = vuln.url;
    // Basic payload handling - if payload is in the URL, it's already there
    // If it's a POST body, we assume 'payload' field contains the body data
    const payload = vuln.payload || '';

    return {
        curl: generateCurl(method, targetUrl, payload),
        python: generatePython(method, targetUrl, payload),
        javascript: generateJavascript(method, targetUrl, payload)
    };
}

function generateCurl(method: string, url: string, payload: string): string {
    let cmd = `curl -X ${method} "${url}"`;

    if (payload && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        // Simple heuristic for JSON
        if (payload.trim().startsWith('{') || payload.trim().startsWith('[')) {
            cmd += ` \\\n  -H "Content-Type: application/json"`;
            cmd += ` \\\n  -d '${payload.replace(/'/g, "'\\''")}'`;
        } else {
            // Assume form encoded
            cmd += ` \\\n  -H "Content-Type: application/x-www-form-urlencoded"`;
            cmd += ` \\\n  -d "${payload.replace(/"/g, '\\"')}"`;
        }
    }

    // Add common headers
    cmd += ` \\\n  -H "User-Agent: STRIX-Scanner/1.0"`;

    return cmd;
}

function generatePython(method: string, url: string, payload: string): string {
    let py = `import requests\n\n`;
    py += `url = "${url}"\n`;
    py += `headers = {"User-Agent": "STRIX-Scanner/1.0"}\n`;

    if (payload && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        if (payload.trim().startsWith('{') || payload.trim().startsWith('[')) {
            py += `payload = ${payload}\n\n`;
            py += `response = requests.${method.toLowerCase()}(url, json=payload, headers=headers)\n`;
        } else {
            py += `payload = "${payload.replace(/"/g, '\\"')}"\n\n`;
            py += `headers["Content-Type"] = "application/x-www-form-urlencoded"\n`;
            py += `response = requests.${method.toLowerCase()}(url, data=payload, headers=headers)\n`;
        }
    } else {
        py += `\nresponse = requests.${method.toLowerCase()}(url, headers=headers)\n`;
    }

    py += `\nprint(f"Status: {response.status_code}")\n`;
    py += `print(f"Response: {response.text[:200]}...")`;

    return py;
}

function generateJavascript(method: string, url: string, payload: string): string {
    let js = `const url = "${url}";\n`;
    js += `const options = {\n`;
    js += `    method: "${method}",\n`;
    js += `    headers: {\n`;
    js += `        "User-Agent": "STRIX-Scanner/1.0"`;

    if (payload && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        js += `,\n        "Content-Type": "${payload.trim().startsWith('{') ? 'application/json' : 'application/x-www-form-urlencoded'}"\n`;
        js += `    },\n`;
        js += `    body: ${payload.trim().startsWith('{') ? `JSON.stringify(${payload})` : `"${payload}"`}\n`;
    } else {
        js += `\n    }\n`;
    }
    js += `};\n\n`;
    js += `fetch(url, options)\n`;
    js += `    .then(res => res.text())\n`;
    js += `    .then(text => console.log(text.substring(0, 200)));`;

    return js;
}
