import { app, BrowserWindow, ipcMain, desktopCapturer, dialog, type WebContents, net as electronNet } from 'electron'
import path from 'node:path'
import net from 'node:net'
import { spawn } from 'node:child_process';
import fs from 'node:fs'
import os from 'node:os'
import https from 'node:https'
import http from 'node:http'
import crypto from 'node:crypto'
import * as msgpack from 'msgpack-lite'

process.env.DIST = path.join(__dirname, '../dist')
process.env.VITE_PUBLIC = app.isPackaged ? process.env.DIST : path.join(process.env.DIST, '../public')


let win: BrowserWindow | null

// ----------------------------------------------------------------------
// IPC Handlers
// ----------------------------------------------------------------------

// STIG file definitions
const STIG_FILES = {
    'win11': {
        name: 'Windows 11 STIG V2R5',
        path: 'Win 11/U_MS_Windows_11_V2R5_Manual_STIG/U_MS_Windows_11_STIG_V2R5_Manual-xccdf.xml'
    },
    'edge': {
        name: 'Microsoft Edge STIG V2R3',
        path: 'Edge/U_MS_Edge_V2R3_Manual_STIG/U_MS_Edge_V2R3_STIG_Manual-xccdf.xml'
    },
    'server2019': {
        name: 'Windows Server 2019 STIG V3R6',
        path: 'Windows Server/U_MS_Windows_Server_2019_V3R6_Manual_STIG/U_MS_Windows_Server_2019_STIG_V3R6_Manual-xccdf.xml'
    },
    'sql-db': {
        name: 'SQL Server 2022 Database STIG V1R1',
        path: 'SQL Server/U_MS_SQL_Server_2022_Database_V1R1_Manual_STIG/U_MS_SQL_Server_2022_Database_STIG_V1R1_Manual-xccdf.xml'
    },
    'sql-instance': {
        name: 'SQL Server 2022 Instance STIG V1R2',
        path: 'SQL Server/U_MS_SQL_Server_2022_Instance_V1R2_Manual_STIG/U_MS_SQL_Server_2022_Instance_STIG_V1R2_Manual-xccdf.xml'
    },
    'iis-server': {
        name: 'IIS 10.0 Server STIG V3R5',
        path: 'IIS/U_MS_IIS_10-0_Server_V3R5_Manual_STIG/U_MS_IIS_10-0_Server_STIG_V3R5_Manual-xccdf.xml'
    },
    'iis-site': {
        name: 'IIS 10.0 Site STIG V2R13',
        path: 'IIS/U_MS_IIS_10-0_Site_V2R13_Manual_STIG/U_MS_IIS_10-0_Site_STIG_V2R13_Manual-xccdf.xml'
    },
    'ad-domain': {
        name: 'Active Directory Domain STIG V3R5',
        path: 'AD Domain/U_Active_Directory_Domain_V3R5_Manual_STIG/U_Active_Directory_Domain_STIG_V3R5_Manual-xccdf.xml'
    },
    'ad-forest': {
        name: 'Active Directory Forest STIG V3R2',
        path: 'AD Forest/U_Active_Directory_Forest_V3R2_Manual_STIG/U_Active_Directory_Forest_STIG_V3R2_Manual-xccdf.xml'
    },
    'defender': {
        name: 'Defender Antivirus STIG V2R6',
        path: 'Defender/U_MS_Defender_Antivirus_V2R6_STIG_SCAP_1-3_Benchmark.xml'
    },
    'firewall': {
        name: 'Windows Firewall STIG V3R3',
        path: 'Firewall/U_Firewall_V3R3_Manual_SRG/U_Firewall_SRG_V3R3_Manual-xccdf.xml'
    }
}

// 0. Get available STIG checklists
ipcMain.handle('get-stig-list', async () => {
    const stigDir = app.isPackaged
        ? path.join(process.resourcesPath, 'STIGs')
        : path.join(__dirname, '../STIGs')

    return Object.entries(STIG_FILES).map(([id, info]) => {
        let date = 'Unknown Date';
        try {
            const xccdfFile = path.join(stigDir, info.path)
            if (fs.existsSync(xccdfFile)) {
                // specific optimized read: just first 5KB
                const fd = fs.openSync(xccdfFile, 'r');
                const buffer = Buffer.alloc(5000);
                fs.readSync(fd, buffer, 0, 5000, 0);
                fs.closeSync(fd);
                const content = buffer.toString('utf-8');

                // Regex: <plain-text id="release-info">... Benchmark Date: 25 Oct 2024 ...</plain-text>
                // Or: <status date="2025-05-29">
                const match = content.match(/Benchmark Date:\s*([^<]+)/);
                if (match) {
                    date = match[1].trim();
                } else {
                    const match2 = content.match(/<status date="([^"]+)">/);
                    if (match2) date = match2[1];
                }
            }
        } catch (e) {
            console.error(`Error reading STIG date for ${id}:`, e);
        }

        return {
            id,
            name: info.name,
            date
        }
    })
})

// 0b. Load STIG XML File by ID
ipcMain.handle('load-stig-file', async (event, stigId: string = 'win11') => {
    const stigInfo = STIG_FILES[stigId as keyof typeof STIG_FILES]
    if (!stigInfo) {
        return { success: false, error: `Unknown STIG: ${stigId}` }
    }

    const stigDir = app.isPackaged
        ? path.join(process.resourcesPath, 'STIGs')
        : path.join(__dirname, '../STIGs')

    const xccdfFile = path.join(stigDir, stigInfo.path)

    if (fs.existsSync(xccdfFile)) {
        return {
            success: true,
            content: fs.readFileSync(xccdfFile, 'utf-8'),
            path: xccdfFile,
            name: stigInfo.name,
            stigId
        }
    }

    return { success: false, error: `STIG file not found: ${xccdfFile}` }
})

// Pentest: Get local IP addresses (for LHOST)
ipcMain.handle('get-local-ip', async () => {
    const ifaces = os.networkInterfaces()
    const ips: string[] = []
    for (const name of Object.keys(ifaces)) {
        const addrs = ifaces[name]
        if (!addrs) continue
        for (const a of addrs) {
            if (a.family === 'IPv4' && !a.internal) ips.push(a.address)
        }
    }
    return ips
})

// Pentest: Run port scan on target (TCP connect to common ports)
const COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
const PORT_SERVICES: Record<number, string> = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC',
    135: 'MSRPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
}
ipcMain.handle('run-port-scan', async (event, data: { target: string }) => {
    const { target } = data
    const timeout = 2000
    const results: Array<{ port: number; state: string; service?: string }> = []
    const scan = (port: number) =>
        new Promise<{ port: number; open: boolean }>((resolve) => {
            const socket = new net.Socket()
            socket.setTimeout(timeout)
            socket.on('connect', () => {
                socket.destroy()
                resolve({ port, open: true })
            })
            socket.on('timeout', () => { socket.destroy(); resolve({ port, open: false }) })
            socket.on('error', () => resolve({ port, open: false }))
            socket.connect(port, target)
        })
    const settled = await Promise.all(COMMON_PORTS.map(scan))
    for (const { port, open } of settled) {
        results.push({
            port,
            state: open ? 'open' : 'closed',
            service: open ? (PORT_SERVICES[port] || 'unknown') : undefined
        })
    }
    return {
        target,
        openPorts: results.filter(r => r.state === 'open'),
        allResults: results
    }
})

// Pentest: Payload hosting — HTTP server to serve one file (for phishing delivery)
let payloadHttpServer: http.Server | null = null
ipcMain.handle('start-payload-server', async (event, data: { port: number; filePath: string; lhost?: string }) => {
    if (payloadHttpServer) {
        try { payloadHttpServer.close() } catch { /* ignore */ }
        payloadHttpServer = null
    }
    const { port, filePath, lhost } = data
    if (!filePath || !fs.existsSync(filePath)) {
        return { success: false, error: 'File not found', url: null }
    }
    const stat = fs.statSync(filePath)
    if (!stat.isFile()) {
        return { success: false, error: 'Path is not a file', url: null }
    }
    const filename = path.basename(filePath)
    payloadHttpServer = http.createServer((req, res) => {
        const stream = fs.createReadStream(filePath)
        res.setHeader('Content-Type', 'application/octet-stream')
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`)
        stream.pipe(res)
    })
    return new Promise<{ success: boolean; url: string | null; error?: string }>((resolve) => {
        payloadHttpServer!.listen(port, lhost || '0.0.0.0', () => {
            const host = lhost || (() => {
                const ifaces = os.networkInterfaces()
                for (const name of Object.keys(ifaces)) {
                    const addrs = ifaces[name]
                    if (!addrs) continue
                    for (const a of addrs) {
                        if (a.family === 'IPv4' && !a.internal) return a.address
                    }
                }
                return '127.0.0.1'
            })()
            resolve({ success: true, url: `http://${host}:${port}/${encodeURIComponent(filename)}` })
        })
        payloadHttpServer!.on('error', (err: NodeJS.ErrnoException) => {
            resolve({ success: false, url: null, error: err.message || 'Server failed to start' })
        })
    })
})
ipcMain.handle('stop-payload-server', async () => {
    if (payloadHttpServer) {
        try { payloadHttpServer.close() } catch { /* ignore */ }
        payloadHttpServer = null
    }
    return { stopped: true }
})

// Pentest: Open file dialog (choose payload file)
ipcMain.handle('show-open-dialog', async (event, opts: { title?: string; filters?: { name: string; extensions: string[] }[] }) => {
    const result = await dialog.showOpenDialog(win!, {
        title: opts.title || 'Choose file',
        properties: ['openFile'],
        filters: opts.filters || [{ name: 'All', extensions: ['*'] }]
    })
    return { canceled: result.canceled, filePaths: result.filePaths }
})

// Pentest: Run Metasploit exploit (write .rc script and launch msfconsole)
ipcMain.handle('run-msf-exploit', async (event, data: { script: string }) => {
    const { script } = data
    if (!script || typeof script !== 'string') {
        return { success: false, error: 'No script provided' }
    }
    const tmpDir = os.tmpdir()
    const rcPath = path.join(tmpDir, `strix-msf-${Date.now()}.rc`)
    try {
        fs.writeFileSync(rcPath, script, 'utf8')
        const isWin = process.platform === 'win32'
        if (isWin) {
            spawn('cmd.exe', ['/c', 'start', 'msfconsole', '-q', '-r', rcPath], { shell: true, detached: true })
        } else {
            spawn('msfconsole', ['-q', '-r', rcPath], { detached: true, stdio: 'ignore' }).unref()
        }
        return { success: true, path: rcPath }
    } catch (e: unknown) {
        const err = e instanceof Error ? e.message : String(e)
        return { success: false, error: err }
    }
})

// Pentest: Create harmless test file for delivery testing (HTML)
ipcMain.handle('create-test-payload-file', async () => {
    const tmpDir = os.tmpdir()
    const filePath = path.join(tmpDir, `strix-test-${Date.now()}.html`)
    const html = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Test</title></head><body><h1>Test — you opened the link</h1><p>Delivery test successful. Use this URL to verify email/SMS delivery.</p></body></html>'
    try {
        fs.writeFileSync(filePath, html, 'utf8')
        return { success: true, path: filePath }
    } catch (e: unknown) {
        const err = e instanceof Error ? e.message : String(e)
        return { success: false, error: err, path: null }
    }
})

// Pentest: Send SMS via Email-to-SMS (carrier gateway + SMTP, no Twilio)
ipcMain.handle('send-sms-email', async (event, data: {
    smtpHost: string; smtpPort: number; smtpSecure?: boolean;
    smtpUser: string; smtpPass: string;
    from: string; toAddress: string; subject: string; body: string;
}) => {
    const { smtpHost, smtpPort, smtpSecure, smtpUser, smtpPass, from, toAddress, subject, body } = data
    if (!smtpHost || !smtpUser || !smtpPass || !toAddress || !body) {
        return { success: false, error: 'Missing SMTP host, user, password, To address, or body' }
    }
    try {
        const nodemailer = await import('nodemailer')
        const transport = nodemailer.default.createTransport({
            host: smtpHost,
            port: smtpPort || 587,
            secure: smtpSecure ?? (smtpPort === 465),
            auth: { user: smtpUser, pass: smtpPass }
        })
        const info = await transport.sendMail({
            from: from || smtpUser,
            to: toAddress,
            subject: subject || 'Message',
            text: body
        })
        return { success: true, messageId: info.messageId }
    } catch (e: unknown) {
        const err = e instanceof Error ? e.message : String(e)
        return { success: false, error: err }
    }
})

// Pentest: Send SMS via Twilio (user provides credentials)
ipcMain.handle('send-sms-twilio', async (event, data: { accountSid: string; authToken: string; from: string; to: string; body: string }) => {
    const { accountSid, authToken, from, to, body } = data
    if (!accountSid || !authToken || !from || !to || !body) {
        return { success: false, error: 'Missing Account SID, Auth Token, From, To, or Body' }
    }
    const url = `https://api.twilio.com/2010-04-01/Accounts/${accountSid}/Messages.json`
    const auth = Buffer.from(`${accountSid}:${authToken}`).toString('base64')
    const params = new URLSearchParams({ To: to, From: from, Body: body })
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${auth}`,
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: params.toString()
        })
        const json = await res.json()
        if (json.error_code || json.code >= 400) {
            return { success: false, error: json.message || json.error_message || JSON.stringify(json) }
        }
        return { success: true, sid: json.sid }
    } catch (e: unknown) {
        const err = e instanceof Error ? e.message : String(e)
        return { success: false, error: err }
    }
})

// ----------------------------------------------------------------------
// WiFi profiles: save credentials, connect this PC, then use Live connections / Packet capture
// Monitoring shows this device's traffic only (not other devices on the WiFi).
// ----------------------------------------------------------------------
const WIFI_PROFILES_PATH = path.join(app.getPath('userData'), 'wifi-profiles.json')

function escapeXml(s: string): string {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&apos;')
}

ipcMain.handle('wifi-get-profiles', async (): Promise<{ success: boolean; profiles?: Array<{ id: string; name: string; ssid: string }>; error?: string }> => {
    try {
        const raw = fs.readFileSync(WIFI_PROFILES_PATH, 'utf-8')
        const data = JSON.parse(raw) as { profiles?: Array<{ id: string; name: string; ssid: string; password?: string }> }
        const list = (data.profiles || []).map(p => ({ id: p.id, name: p.name, ssid: p.ssid }))
        return { success: true, profiles: list }
    } catch (e: unknown) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { success: true, profiles: [] }
        return { success: false, error: e instanceof Error ? e.message : String(e) }
    }
})

ipcMain.handle('wifi-save-profile', async (_e, profile: { id?: string; name: string; ssid: string; password: string; security?: string }) => {
    try {
        let data: { profiles: Array<{ id: string; name: string; ssid: string; password: string; security?: string }> } = { profiles: [] }
        try {
            const raw = fs.readFileSync(WIFI_PROFILES_PATH, 'utf-8')
            data = JSON.parse(raw)
        } catch { /* ignore */ }
        const id = profile.id || `wifi-${Date.now()}`
        const existing = data.profiles.findIndex(p => p.id === id)
        const entry = { id, name: profile.name || profile.ssid, ssid: profile.ssid, password: profile.password, security: profile.security || 'WPA2PSK' }
        if (existing >= 0) data.profiles[existing] = entry
        else data.profiles.push(entry)
        fs.writeFileSync(WIFI_PROFILES_PATH, JSON.stringify(data, null, 2), 'utf-8')
        return { success: true, id }
    } catch (e: unknown) {
        return { success: false, error: e instanceof Error ? e.message : String(e) }
    }
})

ipcMain.handle('wifi-delete-profile', async (_e, profileId: string) => {
    try {
        let data: { profiles: Array<{ id: string }> } = { profiles: [] }
        try {
            const raw = fs.readFileSync(WIFI_PROFILES_PATH, 'utf-8')
            data = JSON.parse(raw)
        } catch { return { success: true } }
        data.profiles = data.profiles.filter(p => p.id !== profileId)
        fs.writeFileSync(WIFI_PROFILES_PATH, JSON.stringify(data, null, 2), 'utf-8')
        return { success: true }
    } catch (e: unknown) {
        return { success: false, error: e instanceof Error ? e.message : String(e) }
    }
})

ipcMain.handle('wifi-connect', async (_e, profileId: string): Promise<{ success: boolean; message?: string; error?: string }> => {
    if (process.platform !== 'win32') {
        return { success: false, error: 'WiFi connect is supported on Windows only. Use system settings on other platforms.' }
    }
    try {
        const raw = fs.readFileSync(WIFI_PROFILES_PATH, 'utf-8')
        const data = JSON.parse(raw) as { profiles?: Array<{ id: string; name: string; ssid: string; password: string }> }
        const profile = (data.profiles || []).find(p => p.id === profileId)
        if (!profile) return { success: false, error: 'Profile not found' }
        const ssidEsc = escapeXml(profile.ssid)
        const keyEsc = escapeXml(profile.password)
        const xml = `<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
  <name>${ssidEsc}</name>
  <SSIDConfig>
    <SSID>
      <name>${ssidEsc}</name>
    </SSID>
  </SSIDConfig>
  <connectionType>ESS</connectionType>
  <connectionMode>auto</connectionMode>
  <MSM>
    <security>
      <authEncryption>
        <authentication>WPA2PSK</authentication>
        <encryption>AES</encryption>
        <useOneX>false</useOneX>
      </authEncryption>
      <sharedKey>
        <keyType>passPhrase</keyType>
        <protected>false</protected>
        <keyMaterial>${keyEsc}</keyMaterial>
      </sharedKey>
    </security>
  </MSM>
</WLANProfile>`
        const profilePath = path.join(app.getPath('temp'), `strix-wifi-${profileId}.xml`)
        fs.writeFileSync(profilePath, xml, 'utf-8')
        const add = spawn('netsh', ['wlan', 'add', 'profile', `filename=${profilePath}`], { stdio: ['ignore', 'pipe', 'pipe'] })
        await new Promise<void>((res) => {
            add.on('close', (code) => res())
        })
        try { fs.unlinkSync(profilePath) } catch { /* ignore */ }
        const connect = spawn('netsh', ['wlan', 'connect', `name=${profile.ssid}`], { stdio: ['ignore', 'pipe', 'pipe'] })
        let err2 = ''
        connect.stderr?.on('data', (d) => { err2 += d.toString() })
        await new Promise<void>((res, rej) => {
            connect.on('close', (code) => {
                if (code === 0) res()
                else rej(new Error(err2 || `Connect exit ${code}`))
            })
        })
        return { success: true, message: `Connected to ${profile.ssid}. Use Live connections above to monitor this device's traffic.` }
    } catch (e: unknown) {
        return { success: false, error: e instanceof Error ? e.message : String(e) }
    }
})

// ----------------------------------------------------------------------
// Network devices: scan home network (IP + MAC), mark known devices, flag unknown
// So you can see if any random/new device shows up on your WiFi.
// ----------------------------------------------------------------------
const KNOWN_DEVICES_PATH = path.join(app.getPath('userData'), 'known-devices.json')

function parseArpTable(out: string): Array<{ ip: string; mac: string }> {
    const devices: Array<{ ip: string; mac: string }> = []
    const ipRe = /^\d+\.\d+\.\d+\.\d+$/
    const macRe = /^([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}$/
    for (const line of out.split(/\r?\n/)) {
        const parts = line.trim().split(/\s+/).filter(Boolean)
        if (parts.length >= 2) {
            const ip = parts[0]
            const mac = parts[1].replace(/:/g, '-')
            if (ipRe.test(ip) && macRe.test(mac)) {
                if (ip.endsWith('.255')) continue
                if (mac === 'ff-ff-ff-ff-ff-ff' || mac === '00-00-00-00-00-00') continue
                devices.push({ ip, mac: mac.toLowerCase() })
            }
        }
    }
    return devices
}

ipcMain.handle('get-network-devices', async (): Promise<{ success: boolean; devices?: Array<{ ip: string; mac: string }>; error?: string }> => {
    if (process.platform !== 'win32') {
        return { success: false, error: 'Network device scan is supported on Windows (arp -a). Use system tools on other platforms.' }
    }
    return new Promise((resolve) => {
        const child = spawn('arp', ['-a'], { stdio: ['ignore', 'pipe', 'pipe'] })
        let out = ''
        child.stdout?.on('data', (d) => { out += d.toString() })
        child.stderr?.on('data', (d) => { out += d.toString() })
        child.on('error', (e) => resolve({ success: false, error: e.message }))
        child.on('close', () => {
            const devices = parseArpTable(out)
            resolve({ success: true, devices })
        })
    })
})

ipcMain.handle('get-known-devices', async (): Promise<{ success: boolean; devices?: Array<{ mac: string; ip: string; name: string }>; error?: string }> => {
    try {
        const raw = fs.readFileSync(KNOWN_DEVICES_PATH, 'utf-8')
        const data = JSON.parse(raw) as { devices?: Array<{ mac: string; ip: string; name: string }> }
        return { success: true, devices: data.devices || [] }
    } catch (e: unknown) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return { success: true, devices: [] }
        return { success: false, error: e instanceof Error ? e.message : String(e) }
    }
})

ipcMain.handle('add-known-device', async (_e, device: { mac: string; ip: string; name: string }) => {
    try {
        let data: { devices: Array<{ mac: string; ip: string; name: string }> } = { devices: [] }
        try {
            const raw = fs.readFileSync(KNOWN_DEVICES_PATH, 'utf-8')
            data = JSON.parse(raw)
        } catch { /* ignore */ }
        const mac = (device.mac || '').toLowerCase().replace(/:/g, '-')
        const existing = data.devices.findIndex(d => (d.mac || '').toLowerCase() === mac || d.ip === device.ip)
        const entry = { mac, ip: device.ip || '', name: (device.name || 'My device').trim() || 'My device' }
        if (existing >= 0) data.devices[existing] = entry
        else data.devices.push(entry)
        fs.writeFileSync(KNOWN_DEVICES_PATH, JSON.stringify(data, null, 2), 'utf-8')
        return { success: true }
    } catch (e: unknown) {
        return { success: false, error: e instanceof Error ? e.message : String(e) }
    }
})

ipcMain.handle('remove-known-device', async (_e, mac: string) => {
    try {
        let data: { devices: Array<{ mac: string }> } = { devices: [] }
        try {
            const raw = fs.readFileSync(KNOWN_DEVICES_PATH, 'utf-8')
            data = JSON.parse(raw)
        } catch { return { success: true } }
        const key = (mac || '').toLowerCase().replace(/:/g, '-')
        data.devices = data.devices.filter(d => (d.mac || '').toLowerCase() !== key)
        fs.writeFileSync(KNOWN_DEVICES_PATH, JSON.stringify(data, null, 2), 'utf-8')
        return { success: true }
    } catch (e: unknown) {
        return { success: false, error: e instanceof Error ? e.message : String(e) }
    }
})

// Well-known port → service name for live connections (user-friendly)
const LIVE_CONN_PORT_SERVICE: Record<number, string> = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP',
    993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP', 8443: 'HTTPS', 27017: 'MongoDB'
}

function parseForeignAddress(foreign: string): { ip: string; port: number } | null {
    const trimmed = foreign.trim()
    if (!trimmed || trimmed === '0.0.0.0' || trimmed === '*') return null
    const ipv6Match = trimmed.match(/^\[([^\]]+)\]:(\d+)$/)
    if (ipv6Match) return { ip: ipv6Match[1], port: parseInt(ipv6Match[2], 10) }
    const ipv4Match = trimmed.match(/^([^:]+):(\d+)$/)
    if (ipv4Match) return { ip: ipv4Match[1], port: parseInt(ipv4Match[2], 10) }
    return null
}

// Pentest: Live network connections (netstat) — with service names and hostname resolution
ipcMain.handle('get-live-connections', async () => {
    return new Promise((resolve) => {
        const isWin = process.platform === 'win32'
        const cmd = isWin ? 'netstat -an' : 'netstat -tuln 2>/dev/null || ss -tuln'
        const child = spawn(isWin ? 'cmd.exe' : 'sh', isWin ? ['/c', 'netstat', '-an'] : ['-c', cmd])
        let out = ''
        child.stdout?.on('data', (d) => { out += d.toString() })
        child.stderr?.on('data', (d) => { out += d.toString() })
        child.on('error', (e) => resolve({ success: false, connections: [], error: e.message }))
        child.on('close', () => {
            const lines = out.split(/\r?\n/).filter(Boolean)
            const raw: { proto: string; local: string; foreign: string; state: string }[] = []
            if (isWin) {
                for (const line of lines) {
                    const parts = line.trim().split(/\s+/).filter(Boolean)
                    if (parts.length >= 4 && (parts[0] === 'TCP' || parts[0] === 'UDP')) {
                        raw.push({
                            proto: parts[0],
                            local: parts[1] || '',
                            foreign: parts[2] || '',
                            state: parts.slice(3).join(' ') || ''
                        })
                    }
                }
            } else {
                for (const line of lines) {
                    const m = line.match(/(tcp|udp)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(\S*)/)
                    if (m) raw.push({ proto: m[1], local: m[2], foreign: m[3], state: m[4] || '-' })
                }
            }
            void (async () => {
                const connections: { proto: string; local: string; foreign: string; state: string; service: string; hostname: string }[] = []
                const hostnameCache = new Map<string, string>()
                const dns = await import('node:dns').then(m => m.promises).catch((): null => null)
                const maxLookups = 50
                let lookups = 0
                for (const r of raw) {
                    const parsed = parseForeignAddress(r.foreign)
                    const port = parsed?.port ?? 0
                    const service = (port && LIVE_CONN_PORT_SERVICE[port]) ? LIVE_CONN_PORT_SERVICE[port] : (port ? `Port ${port}` : '')
                    let hostname = ''
                    if (parsed?.ip && parsed.ip !== '0.0.0.0' && !parsed.ip.startsWith('127.') && lookups < maxLookups && dns) {
                        const cached = hostnameCache.get(parsed.ip)
                        if (cached !== undefined) hostname = cached
                        else {
                            try {
                                const names = await dns.reverse(parsed.ip).catch((): string[] => [])
                                hostname = names && names[0] ? names[0] : ''
                                hostnameCache.set(parsed.ip, hostname)
                                lookups++
                            } catch { hostnameCache.set(parsed.ip, '') }
                        }
                    }
                    connections.push({
                        proto: r.proto,
                        local: r.local,
                        foreign: r.foreign,
                        state: r.state,
                        service: service || '—',
                        hostname: hostname || '—'
                    })
                }
                // SIEM-friendly: show active connections (ESTABLISHED, etc.) first so website traffic is visible
                const activeFirst = (a: { state: string }, b: { state: string }) => {
                    const order = (s: string) => {
                        const u = s.toUpperCase()
                        if (u.includes('ESTABLISHED')) return 0
                        if (u.includes('TIME_WAIT') || u.includes('CLOSE_WAIT')) return 1
                        if (u.includes('LISTENING')) return 2
                        return 3
                    }
                    return order(a.state) - order(b.state)
                }
                connections.sort(activeFirst)
                resolve({ success: true, connections })
            })()
        })
    })
})

// Pentest: Live packet capture — "see everything on the network"
let packetCaptureProcess: ReturnType<typeof spawn> | null = null
let packetCaptureSender: WebContents | null = null

function parseTsharkJsonLine(line: string): { time: string; src: string; dst: string; protocol: string; length: string; info: string } | null {
    try {
        const obj = JSON.parse(line) as { _source?: { layers?: Record<string, Record<string, string>> } }
        const layers = obj._source?.layers
        if (!layers) return null
        const frame = layers.frame || {}
        const ip = layers.ip || {}
        const tcp = layers.tcp || {}
        const udp = layers.udp || {}
        const time = frame['frame.time'] || ''
        const len = frame['frame.len'] || ''
        const protos = frame['frame.protocols'] || ''
        const src = ip['ip.src'] || (layers.eth as Record<string, string>)?.['eth.src'] || '-'
        const dst = ip['ip.dst'] || (layers.eth as Record<string, string>)?.['eth.dst'] || '-'
        const info = tcp['tcp.srcport'] ? `${tcp['tcp.srcport']} → ${tcp['tcp.dstport']}` : udp['udp.srcport'] ? `${udp['udp.srcport']} → ${udp['udp.dstport']}` : protos
        return { time, src, dst, protocol: protos || '—', length: len, info: String(info || '—') }
    } catch {
        return null
    }
}

const PACKET_CAPTURE_UNAVAILABLE =
    'Packet capture is unavailable. Install a capture driver (e.g. Npcap) and the capture tool in the default location, or add it to your PATH.'

// Resolve capture binary: bundled first (build/capture or resources/capture), then Windows install path, then PATH
function getCaptureBinary(): string {
    const isWin = process.platform === 'win32'
    const bundledName = isWin ? 'tshark.exe' : 'tshark'
    const bundledDir = app.isPackaged
        ? path.join(process.resourcesPath, 'capture')
        : path.join(__dirname, '..', 'build', 'capture')
    const bundledPath = path.join(bundledDir, bundledName)
    try {
        if (fs.existsSync(bundledPath)) return bundledPath
    } catch { /* ignore */ }
    if (!isWin) return 'tshark'
    const prog = process.env['ProgramFiles'] || 'C:\\Program Files'
    const alt = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)'
    const candidates = [
        path.join(prog, 'Wireshark', 'tshark.exe'),
        path.join(alt, 'Wireshark', 'tshark.exe'),
    ]
    for (const c of candidates) {
        try {
            if (fs.existsSync(c)) return c
        } catch { /* ignore */ }
    }
    return 'tshark'
}

ipcMain.handle('list-capture-interfaces', async (): Promise<{ success: boolean; interfaces?: Array<{ index: string; name: string }>; error?: string }> => {
    const bin = getCaptureBinary()
    if (bin === 'tshark') return { success: false, error: PACKET_CAPTURE_UNAVAILABLE }
    return new Promise((resolve) => {
        const child = spawn(bin, ['-D'], { stdio: ['ignore', 'pipe', 'pipe'] })
        let out = ''
        let err = ''
        child.stdout?.on('data', (d: Buffer) => { out += d.toString() })
        child.stderr?.on('data', (d: Buffer) => { err += d.toString() })
        child.on('error', (e) => resolve({ success: false, error: (e as NodeJS.ErrnoException).code === 'ENOENT' ? PACKET_CAPTURE_UNAVAILABLE : e.message }))
        child.on('close', (code) => {
            if (code !== 0) return resolve({ success: false, error: err || out || 'Failed to list interfaces' })
            const list: Array<{ index: string; name: string }> = []
            for (const line of out.split(/\n/)) {
                const m = line.match(/^\s*(\d+)\.\s+(.+)$/)
                if (m) list.push({ index: m[1], name: m[2].trim() })
            }
            resolve({ success: true, interfaces: list })
        })
    })
})

ipcMain.handle('start-packet-capture', async (event, opts: { interface?: string }) => {
    if (packetCaptureProcess) {
        try { packetCaptureProcess.kill() } catch { /* ignore */ }
        packetCaptureProcess = null
    }
    const iface = String(opts?.interface ?? '1').trim() || '1'
    packetCaptureSender = event.sender
    const bin = getCaptureBinary()
    if (bin === 'tshark') {
        packetCaptureSender = null
        return { success: false, error: PACKET_CAPTURE_UNAVAILABLE }
    }
    try {
        const child = spawn(bin, ['-i', iface, '-T', 'json', '-l'], { stdio: ['ignore', 'pipe', 'pipe'] })
        packetCaptureProcess = child
        child.stdout?.on('data', (data: Buffer) => {
            const lines = data.toString().split(/\n/).filter(Boolean)
            for (const line of lines) {
                const p = parseTsharkJsonLine(line)
                if (p && packetCaptureSender) packetCaptureSender.send('packet-capture-data', p)
            }
        })
        child.stderr?.on('data', (data: Buffer) => {
            const msg = data.toString().trim()
            if (msg && packetCaptureSender) packetCaptureSender.send('packet-capture-error', msg)
        })
        child.on('error', (err: NodeJS.ErrnoException) => {
            packetCaptureProcess = null
            packetCaptureSender = null
            if (event.sender && !event.sender.isDestroyed()) {
                const msg = err.code === 'ENOENT' ? PACKET_CAPTURE_UNAVAILABLE : err.message
                event.sender.send('packet-capture-error', msg)
            }
        })
        child.on('close', (code, signal) => {
            packetCaptureProcess = null
            packetCaptureSender = null
        })
        return { success: true }
    } catch (e: unknown) {
        packetCaptureSender = null
        const msg = e instanceof Error ? e.message : String(e)
        const friendly = msg.includes('ENOENT') || msg.includes('spawn') ? PACKET_CAPTURE_UNAVAILABLE : msg
        return { success: false, error: friendly }
    }
})

ipcMain.handle('stop-packet-capture', async () => {
    if (packetCaptureProcess) {
        try { packetCaptureProcess.kill() } catch { /* ignore */ }
        packetCaptureProcess = null
    }
    packetCaptureSender = null
    return { success: true }
})

// 1. Run PowerShell Command (background, no window)
ipcMain.handle('run-command', async (event, command) => {
    return new Promise((resolve) => {
        // Use spawn for better output streaming and quoting handling
        const ps = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command]);

        let stdout = '';
        let stderr = '';

        ps.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        ps.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        ps.on('error', (error) => {
            resolve({ success: false, output: error.message });
        });

        ps.on('close', (code) => {
            if (code !== 0) {
                // Check if it's an access denied error
                if (stderr.includes('Access is denied') || stderr.includes('Run as Administrator')) {
                    resolve({
                        success: false,
                        output: stderr || 'Access Denied: Administrative privileges required.',
                        requiresAdmin: true
                    });
                } else {
                    // Normalize "code 1" with empty output to just empty string, 
                    // as PowerShell often returns exit code 1 for "ItemNotFound" even with SilentlyContinue
                    const finalOutput = stdout.trim() ? stdout : (stderr || '');
                    resolve({
                        success: false,
                        output: finalOutput
                    });
                }
            } else {
                resolve({ success: true, output: stdout });
            }
        });
    });
});

// 1b. Run PowerShell Command in Visible Window
ipcMain.handle('run-command-visible', async (event, data: { command: string, ruleId: string, ruleTitle: string }) => {
    return new Promise((resolve) => {
        const { command, ruleId, ruleTitle } = data;
        // Escape command for PowerShell - use single quotes to avoid issues
        const safeCommand = command.replace(/'/g, "''");
        const safeRuleId = ruleId.replace(/'/g, "''");
        const safeRuleTitle = ruleTitle.replace(/'/g, "''").substring(0, 100);

        // Create a script file that will be executed visibly
        const tempDir = os.tmpdir();
        const scriptPath = path.join(tempDir, `stig-check-${Date.now()}.ps1`);

        const scriptContent = `
            Clear-Host
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-Host "STIG Check: '${safeRuleId}'" -ForegroundColor Cyan -BackgroundColor DarkBlue
            Write-Host "'${safeRuleTitle}'" -ForegroundColor Gray
            Write-Host ("=" * 80) -ForegroundColor Cyan
            Write-Host ""
            Write-Host "Command: " -NoNewline -ForegroundColor Yellow
            Write-Host '${safeCommand}' -ForegroundColor White
            Write-Host ""
            Write-Host "Output:" -ForegroundColor Green
            Write-Host ("-" * 80) -ForegroundColor DarkGray
            
            try {
                $result = Invoke-Expression '${safeCommand}' 2>&1
                if ($result) {
                    $output = $result | Out-String
                    Write-Host $output.Trim() -ForegroundColor White
                } else {
                    Write-Host "(No output - value may not exist)" -ForegroundColor Gray
                }
            } catch {
                Write-Host "ERROR: $_" -ForegroundColor Red
            }
            
            Write-Host ""
            Write-Host "Press any key to close..." -ForegroundColor Yellow
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        `;

        // Write script to file
        fs.writeFileSync(scriptPath, scriptContent, 'utf-8');

        // Launch PowerShell in visible window
        const ps = spawn('powershell.exe', [
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-WindowStyle', 'Normal',
            '-File', scriptPath
        ], {
            shell: true,
            detached: true
        });

        // Unref so parent doesn't wait
        ps.unref();

        // Also execute the command in background to get output for the UI
        const execPs = spawn('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command], {
            shell: true
        });

        let stdout = '';
        let stderr = '';

        execPs.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        execPs.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        execPs.on('close', (code) => {
            // Clean up script file
            try {
                setTimeout(() => {
                    if (fs.existsSync(scriptPath)) {
                        fs.unlinkSync(scriptPath);
                    }
                }, 5000); // Give PowerShell time to read it
            } catch (e) {
                // Ignore cleanup errors
            }

            // Return the output for UI display
            if (code !== 0) {
                const finalOutput = stdout.trim() ? stdout : (stderr || '');
                resolve({
                    success: false,
                    output: finalOutput
                });
            } else {
                resolve({ success: true, output: stdout });
            }
        });

        execPs.on('error', (error) => {
            resolve({ success: false, output: error.message });
        });
    });
});


// 2. Save Evidence (structured data with optional screenshot and folder)
ipcMain.handle('save-evidence', async (event, data: {
    ruleId: string;
    ruleTitle: string;
    command: string;
    output: string;
    status: string;
    captureScreenshot: boolean; // Keep for backward compatibility or optional full screen capture
    screenshotDataUrl?: string; // NEW: Base64 image data
    folder?: string;
    findingDetails?: string;
}) => {
    try {
        const baseEvidenceDir = path.join(app.getPath('userData'), 'evidence')

        // Create subfolder if specified
        const evidenceDir = data.folder
            ? path.join(baseEvidenceDir, data.folder.replace(/[^a-zA-Z0-9_-]/g, '_'))
            : baseEvidenceDir;

        if (!fs.existsSync(evidenceDir)) {
            fs.mkdirSync(evidenceDir, { recursive: true })
        }

        const timestamp = new Date()
        const dateStr = timestamp.toISOString().replace(/[:.]/g, '-')
        const safeRuleId = data.ruleId.replace(/[^a-zA-Z0-9_-]/g, '_')
        const baseFilename = `${safeRuleId}_${dateStr}`

        let screenshotPath = null
        let screenshotUrl = null

        // Save provided screenshot (Base64) OR Capture screenshot if requested
        if (data.screenshotDataUrl) {
            try {
                // data:image/png;base64,....
                const matches = data.screenshotDataUrl.match(/^data:([A-Za-z-+\/]+);base64,(.+)$/);
                if (matches && matches.length === 3) {
                    const buffer = Buffer.from(matches[2], 'base64');
                    const imgFilename = `${baseFilename}.png`
                    screenshotPath = path.join(evidenceDir, imgFilename)
                    fs.writeFileSync(screenshotPath, buffer)
                    screenshotUrl = `file://${screenshotPath}`
                }
            } catch (e) {
                console.error('Failed to save screenshot data URL:', e);
            }
        } else if (data.captureScreenshot) {
            const sources = await desktopCapturer.getSources({ types: ['screen'], thumbnailSize: { width: 1920, height: 1080 } })
            const primarySource = sources[0]
            const image = primarySource.thumbnail.toPNG()

            const imgFilename = `${baseFilename}.png`
            screenshotPath = path.join(evidenceDir, imgFilename)
            fs.writeFileSync(screenshotPath, image)
            screenshotUrl = `file://${screenshotPath}`
        }

        // Save JSON evidence file
        const evidenceData = {
            ruleId: data.ruleId,
            ruleTitle: data.ruleTitle,
            command: data.command,
            output: data.output,
            status: data.status,
            folder: data.folder || '',
            timestamp: timestamp.toISOString(),
            timestampReadable: timestamp.toLocaleString(),
            screenshotPath,
            screenshotUrl,
            findingDetails: data.findingDetails || ''
        }

        const jsonFilename = `${baseFilename}.json`
        const jsonPath = path.join(evidenceDir, jsonFilename)
        fs.writeFileSync(jsonPath, JSON.stringify(evidenceData, null, 2))

        return { success: true, evidenceData, jsonPath }
    } catch (error: any) {
        return { success: false, error: error.message }
    }
})

// 3. Get All Evidence (reads JSON files from all subfolders)
ipcMain.handle('get-evidence', async () => {
    const baseEvidenceDir = path.join(app.getPath('userData'), 'evidence')
    if (!fs.existsSync(baseEvidenceDir)) return []

    const evidenceItems: any[] = []

    // Helper function to read a directory recursively
    const readDir = (dir: string, folderName: string = '') => {
        const items = fs.readdirSync(dir, { withFileTypes: true })

        for (const item of items) {
            const fullPath = path.join(dir, item.name)

            if (item.isDirectory()) {
                // Recurse into subdirectory
                readDir(fullPath, item.name)
            } else if (item.name.endsWith('.json')) {
                try {
                    const content = fs.readFileSync(fullPath, 'utf-8')
                    const data = JSON.parse(content)
                    data.folder = folderName || data.folder || '' // Ensure folder field
                    evidenceItems.push(data)
                } catch (e) {
                    // Skip malformed files
                }
            }
            // Skip image files - don't include .png files in the list
        }
    }

    readDir(baseEvidenceDir)

    // Sort by timestamp descending
    return evidenceItems.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
})

// 3b. Clear All Evidence
ipcMain.handle('clear-evidence', async () => {
    const baseEvidenceDir = path.join(app.getPath('userData'), 'evidence')
    if (!fs.existsSync(baseEvidenceDir)) return { success: true, deleted: 0 }

    // Recursively delete all files and folders
    const deleteRecursive = (dir: string) => {
        const items = fs.readdirSync(dir, { withFileTypes: true })
        for (const item of items) {
            const fullPath = path.join(dir, item.name)
            if (item.isDirectory()) {
                deleteRecursive(fullPath)
                fs.rmdirSync(fullPath)
            } else {
                fs.unlinkSync(fullPath)
            }
        }
    }

    try {
        deleteRecursive(baseEvidenceDir)
        return { success: true }
    } catch (e: any) {
        return { success: false, error: e.message }
    }
})

// 4. Capture "Real" Evidence (RPA style)
ipcMain.handle('capture-real-evidence', async (event, data: { type: 'regedit' | 'powershell', path: string, command: string, manual?: boolean }) => {
    return new Promise((resolve) => {
        const { type, path: targetPath, command, manual } = data;
        let script = '';

        if (manual) {
            // MANUAL MODE: User sets up the screen, we just capture
            script = `
                $ErrorActionPreference = 'SilentlyContinue'
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing
                
                # Short wait to let user clear the alert box if needed
                Start-Sleep -Seconds 1

                $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
                $graphics = [System.Drawing.Graphics]::FromImage($bmp)
                $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size) # Capture Full Screen

                $ms = New-Object System.IO.MemoryStream
                $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
                $base64 = [Convert]::ToBase64String($ms.ToArray())

                $graphics.Dispose()
                $bmp.Dispose()
                $ms.Dispose()

                Write-Output $base64
             `;
        } else if (type === 'regedit') {
            const regKeyClean = targetPath.replace(/^[A-Z_]+:\\/, '').replace('Hostname', '').trim();
            let swarmKey = "";
            let root = ""
            if (targetPath.toUpperCase().startsWith("HKLM") || targetPath.toUpperCase().includes("HKEY_LOCAL_MACHINE")) {
                root = "HKEY_LOCAL_MACHINE";
                swarmKey = targetPath.substring(targetPath.indexOf("\\") + 1);
            } else if (targetPath.toUpperCase().startsWith("HKCU") || targetPath.toUpperCase().includes("HKEY_CURRENT_USER")) {
                root = "HKEY_CURRENT_USER";
                swarmKey = targetPath.substring(targetPath.indexOf("\\") + 1);
            }
            if (!swarmKey) swarmKey = targetPath;

            script = `
                $ErrorActionPreference = 'SilentlyContinue'
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing

                # 1. Force Regedit to open at specific key
                $regPath = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit"
                $lastKeyVal = "Computer\\${root}\\${swarmKey}"
                Set-ItemProperty -Path $regPath -Name "LastKey" -Value $lastKeyVal -ErrorAction SilentlyContinue

                # 2. Launch Regedit
                $proc = Start-Process regedit.exe -PassThru
                
                # Give user time to accept UAC if needed
                Start-Sleep -Seconds 5

                # 3. Capture Screen
                $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
                $graphics = [System.Drawing.Graphics]::FromImage($bmp)
                $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)

                # 4. Save to Memory Stream
                $ms = New-Object System.IO.MemoryStream
                $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
                $base64 = [Convert]::ToBase64String($ms.ToArray())

                # 5. Cleanup
                $graphics.Dispose()
                $bmp.Dispose()
                $ms.Dispose()
                
                # Kill by Name to ensure elevated process dies
                Stop-Process -Name regedit -Force -ErrorAction SilentlyContinue

                Write-Output $base64
            `;
        } else {
            const safeCommand = command.replace(/"/g, '`"');
            script = `
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing

                # 1. Launch Visible PowerShell
                $proc = Start-Process powershell.exe -ArgumentList "-NoExit", "-Command & { ${safeCommand}; Write-Host 'Capturing in 4s...'; Start-Sleep -Seconds 4; Stop-Process -Id $PID }" -PassThru
                
                Start-Sleep -Seconds 3 # Wait for window to be fully visible

                # 2. Capture Screen
                $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
                $graphics = [System.Drawing.Graphics]::FromImage($bmp)
                $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
                
                # 3. Serialize
                $ms = New-Object System.IO.MemoryStream
                $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
                $base64 = [Convert]::ToBase64String($ms.ToArray())

                $graphics.Dispose()
                $bmp.Dispose()
                $ms.Dispose()
                
                Write-Output $base64
            `;
        }

        const ps = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', script]);

        let output = '';
        let error = '';

        ps.stdout.on('data', (data) => output += data.toString());
        ps.stderr.on('data', (data) => error += data.toString());

        ps.on('close', (code) => {
            const cleanBase64 = output.trim().replace(/\s/g, '');
            if (cleanBase64.length > 100) {
                resolve({ success: true, base64: `data:image/png;base64,${cleanBase64}` });
            } else {
                resolve({ success: false, error: error || 'Failed to capture image or image was empty.' });
            }
        });
    });
});

// 3c. Delete Single Evidence Item
ipcMain.handle('delete-evidence', async (_event, data: { ruleId: string; folder?: string }) => {
    const baseEvidenceDir = path.join(app.getPath('userData'), 'evidence')
    const evidenceDir = data.folder
        ? path.join(baseEvidenceDir, data.folder.replace(/[^a-zA-Z0-9_-]/g, '_'))
        : baseEvidenceDir;

    if (!fs.existsSync(evidenceDir)) return { success: false, error: 'Directory not found' }

    try {
        // Find and delete matching files
        const files = fs.readdirSync(evidenceDir)
        const safeRuleId = data.ruleId.replace(/[^a-zA-Z0-9_-]/g, '_')
        let deleted = 0

        for (const file of files) {
            if (file.startsWith(safeRuleId)) {
                fs.unlinkSync(path.join(evidenceDir, file))
                deleted++
            }
        }

        return { success: true, deleted }
    } catch (e: any) {
        return { success: false, error: e.message }
    }
})

// 3d. Create Evidence Folder
ipcMain.handle('create-evidence-folder', async (_event, folderName: string) => {
    const baseEvidenceDir = path.join(app.getPath('userData'), 'evidence')
    const safeFolderName = folderName.replace(/[^a-zA-Z0-9_-]/g, '_')
    const folderPath = path.join(baseEvidenceDir, safeFolderName)

    try {
        if (!fs.existsSync(folderPath)) {
            fs.mkdirSync(folderPath, { recursive: true })
        }
        return { success: true, folderPath }
    } catch (e: any) {
        return { success: false, error: e.message }
    }
})

// 3e. Delete Evidence Folder
ipcMain.handle('delete-evidence-folder', async (_event, folderName: string) => {
    const baseEvidenceDir = path.join(app.getPath('userData'), 'evidence')
    // Handle root or specific folder
    if (!folderName || folderName === 'Ungrouped') return { success: false, error: 'Cannot delete root/ungrouped folder' }

    const safeFolderName = folderName.replace(/[^a-zA-Z0-9_-]/g, '_')
    const folderPath = path.join(baseEvidenceDir, safeFolderName)

    try {
        if (fs.existsSync(folderPath)) {
            fs.rmSync(folderPath, { recursive: true, force: true })
            return { success: true }
        } else {
            return { success: false, error: 'Folder not found' }
        }
    } catch (e: any) {
        return { success: false, error: e.message }
    }
})

// 3e. Read File as Base64 (for reports)
ipcMain.handle('read-file-base64', async (_event, filePath: string) => {
    try {
        if (!fs.existsSync(filePath)) return { success: false, error: 'File not found' }
        const bitmap = fs.readFileSync(filePath)
        return { success: true, data: Buffer.from(bitmap).toString('base64') }
    } catch (e: any) {
        return { success: false, error: e.message }
    }
})

// ----------------------------------------------------------------------
// Local Directory Scanner for SAST
// ----------------------------------------------------------------------

// Files to exclude from scanning
const SCAN_EXCLUDE_PATTERNS = [
    'node_modules', '.git', '.svn', '.hg', 'dist', 'build', 'coverage',
    '__pycache__', '.pytest_cache', 'venv', 'env', '.env',
    '.next', '.nuxt', '.output', 'vendor', 'packages',
    '.idea', '.vscode', '.vs', 'bin', 'obj',
];

// Extensions to scan
const SCAN_EXTENSIONS = [
    '.js', '.ts', '.jsx', '.tsx', '.mjs', '.cjs',
    '.py', '.rb', '.php', '.java', '.go', '.rs', '.c', '.cpp', '.h',
    '.sol', '.vy', // Smart contracts
    '.json', '.yaml', '.yml', '.toml', '.xml',
    '.env', '.env.local', '.env.production', '.env.development',
    '.sh', '.bash', '.zsh', '.ps1', '.bat', '.cmd',
    '.sql', '.graphql', '.gql',
    '.html', '.htm', '.vue', '.svelte',
    '.config', '.conf', '.cfg', '.ini',
    '.pem', '.key', '.crt', '.cer',
];

// Max file size to scan (1MB)
const MAX_SCAN_FILE_SIZE = 1024 * 1024;

interface ScanFileInfo {
    path: string;
    relativePath: string;
    content: string;
    size: number;
    extension: string;
}

// Recursively get all files in a directory
function getAllFiles(dirPath: string, basePath: string, files: ScanFileInfo[] = [], maxFiles = 5000): ScanFileInfo[] {
    if (files.length >= maxFiles) return files;

    try {
        const items = fs.readdirSync(dirPath, { withFileTypes: true });

        for (const item of items) {
            if (files.length >= maxFiles) break;

            const fullPath = path.join(dirPath, item.name);
            const relativePath = path.relative(basePath, fullPath);

            // Skip excluded directories
            if (item.isDirectory()) {
                if (SCAN_EXCLUDE_PATTERNS.some(p => item.name === p || item.name.startsWith('.'))) {
                    continue;
                }
                getAllFiles(fullPath, basePath, files, maxFiles);
            } else if (item.isFile()) {
                const ext = path.extname(item.name).toLowerCase();
                const nameWithoutExt = item.name.toLowerCase();

                // Check if file should be scanned
                const shouldScan = SCAN_EXTENSIONS.includes(ext) ||
                    nameWithoutExt.includes('.env') ||
                    nameWithoutExt === 'dockerfile' ||
                    nameWithoutExt === 'makefile' ||
                    nameWithoutExt.endsWith('rc');

                if (shouldScan) {
                    try {
                        const stats = fs.statSync(fullPath);
                        if (stats.size <= MAX_SCAN_FILE_SIZE) {
                            const content = fs.readFileSync(fullPath, 'utf-8');
                            files.push({
                                path: fullPath,
                                relativePath,
                                content,
                                size: stats.size,
                                extension: ext
                            });
                        }
                    } catch (e) {
                        // Skip files that can't be read
                    }
                }
            }
        }
    } catch (e) {
        // Skip directories that can't be read
    }

    return files;
}

// Browse for directory dialog
ipcMain.handle('browse-directory', async (): Promise<{
    success: boolean;
    path?: string;
    canceled?: boolean;
}> => {
    try {
        const result = await dialog.showOpenDialog({
            properties: ['openDirectory'],
            title: 'Select Directory to Scan'
        });

        if (result.canceled || result.filePaths.length === 0) {
            return { success: true, canceled: true };
        }

        return { success: true, path: result.filePaths[0] };
    } catch (e: any) {
        return { success: false, path: undefined };
    }
})

ipcMain.handle('sast-scan-directory', async (_event, targetPath: string): Promise<{
    success: boolean;
    files?: ScanFileInfo[];
    error?: string;
    totalFiles?: number;
}> => {
    console.log('[SAST] Scanning directory:', targetPath);

    try {
        if (!fs.existsSync(targetPath)) {
            return { success: false, error: 'Directory not found' };
        }

        const stats = fs.statSync(targetPath);
        if (!stats.isDirectory()) {
            return { success: false, error: 'Path is not a directory' };
        }

        const files = getAllFiles(targetPath, targetPath, [], 5000);
        console.log('[SAST] Found', files.length, 'files to scan');

        return {
            success: true,
            files,
            totalFiles: files.length
        };
    } catch (e: any) {
        console.error('[SAST] Scan error:', e);
        return { success: false, error: e.message };
    }
})

ipcMain.handle('sast-read-file', async (_event, filePath: string): Promise<{
    success: boolean;
    content?: string;
    error?: string;
}> => {
    try {
        if (!fs.existsSync(filePath)) {
            return { success: false, error: 'File not found' };
        }

        const stats = fs.statSync(filePath);
        if (stats.size > MAX_SCAN_FILE_SIZE) {
            return { success: false, error: 'File too large' };
        }

        const content = fs.readFileSync(filePath, 'utf-8');
        return { success: true, content };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
})

// 5a. Launch Admin PowerShell Window (positioned on left side, like Cursor terminal)
// This window will poll for commands and execute them sequentially
let powershellProcess: any = null;

// Use a more accessible path for elevated processes
// Elevated PowerShell might have different temp directory access
const userDataPath = app.getPath('userData');
const commandQueuePath = path.join(userDataPath, 'stig-command-queue.json');
const commandResultPath = path.join(userDataPath, 'stig-command-result.json');

ipcMain.handle('launch-admin-powershell', async () => {
    return new Promise((resolve) => {
        try {
            // Initialize command queue file
            if (fs.existsSync(commandQueuePath)) {
                fs.unlinkSync(commandQueuePath);
            }
            if (fs.existsSync(commandResultPath)) {
                fs.unlinkSync(commandResultPath);
            }

            // Create the persistent PowerShell script that polls for commands
            const queuePathEscaped = commandQueuePath.replace(/\\/g, '\\\\').replace(/'/g, "''");
            const resultPathEscaped = commandResultPath.replace(/\\/g, '\\\\').replace(/'/g, "''");

            const persistentScript = `
                Add-Type -AssemblyName System.Windows.Forms
                Add-Type -AssemblyName System.Drawing
                
                # Define WindowPositioner type once at the start
                try {
                    $null = [WindowPositioner]
                } catch {
                    $typeDef = @'
using System;
using System.Runtime.InteropServices;
public class WindowPositioner {
    [DllImport("user32.dll")]
    public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
'@
                    Add-Type -TypeDefinition $typeDef
                }
                
                $queuePath = '${queuePathEscaped}'
                $resultPath = '${resultPathEscaped}'
                
                Write-Host "STIG Agent PowerShell - Ready for Commands" -ForegroundColor Green
                Write-Host "Queue file: $queuePath" -ForegroundColor Gray
                Write-Host "Waiting for commands..." -ForegroundColor Yellow
                Write-Host ""
                
                # Verify queue file path exists and is accessible
                if (-not (Test-Path (Split-Path $queuePath))) {
                                    Write-Host "WARNING: Queue directory does not exist!" -ForegroundColor Red
                }
                
                $iteration = 0
                while ($true) {
                    $iteration++
                    if ($iteration % 20 -eq 0) {
                        Write-Host "[$iteration] Still waiting for commands..." -ForegroundColor DarkGray
                        # Debug: Check if file exists
                        if (Test-Path $queuePath) {
                            Write-Host "  DEBUG: Queue file EXISTS but not being processed!" -ForegroundColor Yellow
                        }
                    }
                    
                    if (Test-Path $queuePath) {
                        Write-Host "*** COMMAND FILE DETECTED! ***" -ForegroundColor Magenta
                        Write-Host "Processing command..." -ForegroundColor Green
                        try {
                            # Read command data
                            $rawContent = Get-Content $queuePath -Raw
                            Write-Host "Queue file content: $rawContent" -ForegroundColor Gray
                            $commandData = $rawContent | ConvertFrom-Json
                            Remove-Item $queuePath -Force
                            Write-Host "Command data parsed successfully" -ForegroundColor Green
                            
                            $groupId = $commandData.groupId
                            $command = $commandData.command
                            $registryPath = $commandData.registryPath
                            $evidenceType = if ($commandData.evidenceType) { $commandData.evidenceType } else { 'powershell' }
                            
                            # Launch regedit if this is a registry command AND evidence type includes regedit
                            $regeditProcess = $null
                            $shouldLaunchRegedit = ($evidenceType -eq 'regedit' -or $evidenceType -eq 'both') -and $registryPath -and $registryPath -match '^(HKLM|HKCU):(.+)$'
                            
                            if ($shouldLaunchRegedit) {
                                Write-Host "Evidence type: $evidenceType - Launching regedit for registry path: $registryPath" -ForegroundColor Cyan
                                $hive = $matches[1]
                                $path = $matches[2]
                                
                                # Convert PowerShell path to regedit format
                                $regeditPath = "Computer"
                                if ($hive -eq 'HKLM') {
                                    $regeditPath += "\HKEY_LOCAL_MACHINE"
                                } elseif ($hive -eq 'HKCU') {
                                    $regeditPath += "\HKEY_CURRENT_USER"
                                }
                                $regeditPath += $path
                                
                                Write-Host "Launching regedit and navigating to: $regeditPath" -ForegroundColor Cyan
                                
                                # Launch regedit
                                $regeditProcess = Start-Process "regedit.exe" -PassThru
                                Start-Sleep -Seconds 2
                                
                                # Wait for regedit window to appear and be ready
                                Write-Host "Waiting for regedit window..." -ForegroundColor Cyan
                                $maxWait = 30
                                $waited = 0
                                while ($regeditProcess.MainWindowHandle -eq [IntPtr]::Zero -and $waited -lt $maxWait) {
                                    Start-Sleep -Milliseconds 100
                                    $regeditProcess.Refresh()
                                    $waited++
                                }
                                
                                # Give regedit extra time to fully initialize
                                Start-Sleep -Seconds 2
                                
                                # Try to position windows (but don't fail if this doesn't work)
                                Add-Type -AssemblyName System.Windows.Forms
                                $screen = [System.Windows.Forms.Screen]::PrimaryScreen
                                $screenWidth = $screen.WorkingArea.Width
                                $screenHeight = $screen.WorkingArea.Height
                                
                                # Try to position PowerShell window (optional)
                                $psProcess = Get-Process -Id $PID -ErrorAction SilentlyContinue
                                if ($psProcess) {
                                    try {
                                        $psProcess.Refresh()
                                        $psHandle = $psProcess.MainWindowHandle
                                        if ($psHandle -and $psHandle -ne [IntPtr]::Zero -and $psHandle.ToString() -ne "0") {
                                            $psWidth = [int]($screenWidth * 0.5)
                                            $psHeight = $screenHeight
                                            [WindowPositioner]::MoveWindow($psHandle, 0, 0, $psWidth, $psHeight, $true)
                                        }
                                    } catch {
                                        # Ignore positioning errors
                                    }
                                }
                                
                                # Try to position regedit window (optional)
                                try {
                                    $regeditProcess.Refresh()
                                    $regeditHandle = $regeditProcess.MainWindowHandle
                                    if ($regeditHandle -and $regeditHandle -ne [IntPtr]::Zero -and $regeditHandle.ToString() -ne "0") {
                                        $regeditWidth = [int]($screenWidth * 0.5)
                                        $regeditHeight = $screenHeight
                                        $regeditX = $screenWidth - $regeditWidth
                                        [WindowPositioner]::MoveWindow($regeditHandle, $regeditX, 0, $regeditWidth, $regeditHeight, $true)
                                    }
                                } catch {
                                    # Ignore positioning errors - navigation will still work
                                }
                                
                                # NAVIGATION - This is the critical part, must happen regardless of positioning success
                                Write-Host "Starting regedit navigation..." -ForegroundColor Cyan
                                
                                try {
                                    Add-Type -AssemblyName System.Windows.Forms
                                    
                                    # Wait longer for regedit to be fully ready
                                    Write-Host "Waiting for regedit to be fully ready..." -ForegroundColor Cyan
                                    Start-Sleep -Seconds 2
                                    
                                    # Get regedit window handle for focus (try multiple times if needed)
                                    $navHandle = $null
                                    for ($i = 0; $i -lt 10; $i++) {
                                        try {
                                            $regeditProcess.Refresh()
                                            $navHandle = $regeditProcess.MainWindowHandle
                                            if ($navHandle -and $navHandle -ne [IntPtr]::Zero -and $navHandle.ToString() -ne "0") {
                                                Write-Host "Got regedit window handle" -ForegroundColor Green
                                                break
                                            }
                                        } catch {
                                            Start-Sleep -Milliseconds 300
                                        }
                                    }
                                    
                                    # Bring regedit to foreground - CRITICAL for SendKeys to work
                                    if ($navHandle) {
                                        Write-Host "Bringing regedit to foreground..." -ForegroundColor Cyan
                                        try {
                                            [WindowPositioner]::SetForegroundWindow($navHandle)
                                            Start-Sleep -Milliseconds 800
                                            # Verify it's in foreground by trying again
                                            [WindowPositioner]::SetForegroundWindow($navHandle)
                                            Start-Sleep -Milliseconds 800
                                            # One more time to be sure
                                            [WindowPositioner]::SetForegroundWindow($navHandle)
                                            Start-Sleep -Milliseconds 500
                                        } catch {
                                            Write-Host "Warning: Could not set foreground window" -ForegroundColor Yellow
                                        }
                                    } else {
                                        Write-Host "Warning: No window handle available" -ForegroundColor Yellow
                                    }
                                    
                                    # Additional wait to ensure regedit is ready and has focus
                                    Write-Host "Waiting for regedit to be ready..." -ForegroundColor Cyan
                                    Start-Sleep -Seconds 2
                                    
                                    # Perform navigation - Navigate to HKEY_LOCAL_MACHINE first, then navigate folders
                                    Write-Host "Starting navigation sequence..." -ForegroundColor Cyan
                                    
                                    $hiveName = if ($hive -eq 'HKLM') { "HKEY_LOCAL_MACHINE" } else { "HKEY_CURRENT_USER" }
                                    
                                    # Step 1: Navigate to HKEY_LOCAL_MACHINE (this is where we START)
                                    Write-Host "Step 1: Navigating to $hiveName (starting point)..." -ForegroundColor Cyan
                                    
                                    # Go to Computer root first
                                    [System.Windows.Forms.SendKeys]::SendWait("{HOME}")
                                    Start-Sleep -Milliseconds 1000
                                    
                                    # Navigate to HKEY_LOCAL_MACHINE using arrow keys
                                    Write-Host "  Navigating to $hiveName using arrow keys..." -ForegroundColor Gray
                                    if ($hive -eq 'HKLM') {
                                        # Skip HKEY_CLASSES_ROOT (1st), HKEY_CURRENT_USER (2nd), go to HKEY_LOCAL_MACHINE (3rd)
                                        [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
                                        Start-Sleep -Milliseconds 800
                                        [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
                                        Start-Sleep -Milliseconds 800
                                        [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
                                        Start-Sleep -Milliseconds 1000
                                    } elseif ($hive -eq 'HKCU') {
                                        [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
                                        Start-Sleep -Milliseconds 800
                                        [System.Windows.Forms.SendKeys]::SendWait("{DOWN}")
                                        Start-Sleep -Milliseconds 1000
                                    }
                                    
                                    # Step 2: Expand HKEY_LOCAL_MACHINE
                                    Write-Host "Step 2: Expanding $hiveName..." -ForegroundColor Cyan
                                    [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                                    Start-Sleep -Milliseconds 2000
                                    Write-Host "  $hiveName is now expanded - we can see SOFTWARE, HARDWARE, etc." -ForegroundColor Gray
                                    
                                    # Step 3: Navigate through EACH folder in the path after HKEY_LOCAL_MACHINE
                                    # We START at HKEY_LOCAL_MACHINE (already expanded) - this is our starting point
                                    # The $path variable contains: \SOFTWARE\Policies\Microsoft\Edge
                                    # We navigate: SOFTWARE -> Policies -> Microsoft -> Edge
                                    
                                    # Robust path splitting - handle both \ and /, remove empty entries
                                    $normalizedPath = $path.Trim().TrimStart('\', '/')
                                    Write-Host "  Debug: Original path = '$path'" -ForegroundColor DarkGray
                                    Write-Host "  Debug: Normalized path = '$normalizedPath'" -ForegroundColor DarkGray
                                    
                                    # Split on backslash, remove empty entries
                                    $pathParts = @()
                                    if ($normalizedPath) {
                                        $pathParts = $normalizedPath -split '[\\/]' | Where-Object { $_ -and $_.Trim() -ne '' }
                                    }
                                    
                                    Write-Host "Step 3: Navigating through $($pathParts.Count) folders starting from $hiveName..." -ForegroundColor Cyan
                                    Write-Host ("  Starting at: Computer\$hiveName (expanded)") -ForegroundColor Gray
                                    Write-Host ("  Path parts: " + ($pathParts -join ' -> ')) -ForegroundColor Gray
                                    
                                    if ($pathParts.Count -eq 0) {
                                        Write-Host "  WARNING: No path parts to navigate! Path was: '$path'" -ForegroundColor Yellow
                                    }
                                    
                                    $folderNum = 0
                                    foreach ($folder in $pathParts) {
                                        $folder = $folder.Trim()
                                        if ([string]::IsNullOrWhiteSpace($folder)) { continue }
                                        
                                        $folderNum++
                                        Write-Host "  [$folderNum/$($pathParts.Count)] Navigating to folder: '$folder'" -ForegroundColor Gray
                                        
                                        # CRITICAL: Ensure we're still in the right context
                                        # Before typing, make sure we're at the right level by pressing HOME to go to first child
                                        # This ensures we're navigating within the current expanded key
                                        Start-Sleep -Milliseconds 800
                                        
                                        # Type ONLY the folder name (not the whole path!)
                                        # This will jump to it in the CURRENT context (within HKEY_LOCAL_MACHINE or current parent)
                                        Write-Host "    Typing folder name: '$folder'" -ForegroundColor DarkGray
                                        [System.Windows.Forms.SendKeys]::SendWait($folder)
                                        Start-Sleep -Milliseconds 1500
                                        
                                        # Press Enter to select the folder
                                        Write-Host "    Pressing Enter to select..." -ForegroundColor DarkGray
                                        [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
                                        Start-Sleep -Milliseconds 1500
                                        
                                        # Press Right arrow to expand the folder
                                        # If the folder doesn't exist, this won't expand and we'll stop here
                                        Write-Host "    Pressing Right to expand (verifies it exists)..." -ForegroundColor DarkGray
                                        [System.Windows.Forms.SendKeys]::SendWait("{RIGHT}")
                                        Start-Sleep -Milliseconds 2000
                                        
                                        Write-Host "    Completed navigation to: $folder" -ForegroundColor Gray
                                    }
                                    
                                    Write-Host "Navigation sequence completed. Target: Computer\$hiveName" + $path -ForegroundColor Cyan
                                    Write-Host "  (Note: Verify in regedit window that we're at the correct location)" -ForegroundColor DarkGray
                                } catch {
                                    Write-Host "Regedit navigation error: $_" -ForegroundColor Red
                                    Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
                                }
                                
                                # Final wait for navigation to complete
                                Start-Sleep -Seconds 1
                            } else {
                                if ($registryPath) {
                                    Write-Host "Evidence type: $evidenceType - Skipping regedit (PowerShell only mode)" -ForegroundColor Gray
                                }
                            }
                            
                            # Clear screen and show everything clearly - THIS IS WHAT THE SCREENSHOT CAPTURES
                            Clear-Host
                            
                            # Show PowerShell header and current directory
                            Write-Host "Windows PowerShell" -ForegroundColor White
                            Write-Host "Copyright (C) Microsoft Corporation. All rights reserved." -ForegroundColor Gray
                            Write-Host ""
                            
                            # Get current directory
                            $currentDir = Get-Location
                            Write-Host "PS $currentDir> " -NoNewline -ForegroundColor White
                            
                            # Get timestamp for display
                            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            $dayName = (Get-Date).DayOfWeek
                            $timestampDisplay = "$dayName $timestamp"
                            
                            Write-Host ""
                            Write-Host ("=" * 80) -ForegroundColor Cyan
                            Write-Host "Checking: $groupId" -NoNewline -ForegroundColor Cyan -BackgroundColor DarkBlue
                            Write-Host " - $timestampDisplay" -ForegroundColor Gray
                            Write-Host ("=" * 80) -ForegroundColor Cyan
                            Write-Host ""
                            
                            # Show command with prompt-like format
                            Write-Host "PS $currentDir> " -NoNewline -ForegroundColor White
                            Write-Host $command -ForegroundColor Yellow
                            Write-Host ""
                            
                            # Force output to be visible
                            [Console]::Out.Flush()
                            Start-Sleep -Milliseconds 200
                            
                            # Execute command and capture ALL output - show exactly as PowerShell would
                            $commandOutput = ""
                            $ErrorActionPreference = 'Continue'
                            try {
                                # Execute command - capture everything (stdout and stderr)
                                # This is the REAL PowerShell output, not a custom message
                                $result = Invoke-Expression $command 2>&1
                                
                                # Display output exactly as PowerShell would - no custom messages
                                if ($null -ne $result) {
                                    # Check if result is an error record
                                    if ($result -is [System.Management.Automation.ErrorRecord]) {
                                        # Show error exactly as PowerShell would
                                        $errorOutput = $result | Out-String -Width 4096
                                        $commandOutput = $errorOutput.Trim()
                                        Write-Host $commandOutput -ForegroundColor Red
                                    } else {
                                        # Show normal output exactly as PowerShell would
                                        # Convert to string exactly as PowerShell would display it
                                        $outputLines = $result | Out-String -Width 4096
                                        $commandOutput = $outputLines.Trim()
                                        
                                        # Only write if there's actual output (real PowerShell behavior)
                                        if (-not [string]::IsNullOrWhiteSpace($commandOutput)) {
                                            Write-Host $commandOutput -ForegroundColor White
                                        }
                                        # If no output, just show nothing (like real PowerShell does)
                                    }
                                }
                                # If $result is null/empty, show nothing (like real PowerShell does)
                            } catch {
                                # Show error exactly as PowerShell would
                                $errorMsg = $_.Exception.Message
                                $commandOutput = $errorMsg
                                Write-Host $errorMsg -ForegroundColor Red
                            }
                            Write-Host ""
                            
                            # Show prompt after output
                            Write-Host "PS $currentDir> " -NoNewline -ForegroundColor White
                            Write-Host "_" -NoNewline -ForegroundColor White
                            
                            # Force all output to be visible before screenshot
                            [Console]::Out.Flush()
                            Start-Sleep -Milliseconds 300
                            
                            # Wait before screenshot - show countdown clearly
                            Write-Host ""
                            Write-Host "Waiting 5 seconds before capturing screenshot..." -ForegroundColor Yellow
                            [Console]::Out.Flush()
                            
                            # Countdown - make it very visible
                            for ($i = 5; $i -gt 0; $i--) {
                                Write-Host "  Screenshot in $i seconds..." -ForegroundColor DarkYellow
                                [Console]::Out.Flush()
                                Start-Sleep -Seconds 1
                            }
                            
                            # Final wait to ensure everything is displayed
                            Start-Sleep -Milliseconds 500
                            [Console]::Out.Flush()
                            
                            # Capture screenshot - FULL SCREEN (PowerShell and regedit windows should be visible)
                            try {
                                # Ensure PowerShell window is in foreground first
                                $psProcess = Get-Process -Id $PID
                                if ($psProcess.MainWindowHandle -ne [IntPtr]::Zero) {
                                    $win32TypeDef = @'
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(IntPtr hWnd);
}
'@
                                    Add-Type -TypeDefinition $win32TypeDef
                                    [Win32]::SetForegroundWindow($psProcess.MainWindowHandle)
                                    Start-Sleep -Milliseconds 200
                                }
                                
                                # If regedit was launched, make sure it's also visible (but don't bring to foreground)
                                if ($regeditProcess -and $regeditProcess.MainWindowHandle -ne [IntPtr]::Zero) {
                                    # Just ensure it's visible, don't bring to foreground (PowerShell should be on top)
                                    Start-Sleep -Milliseconds 100
                                }
                                
                                # Capture full screen - both PowerShell and regedit windows should be visible
                                $bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
                                $bmp = New-Object System.Drawing.Bitmap $bounds.Width, $bounds.Height
                                $graphics = [System.Drawing.Graphics]::FromImage($bmp)
                                $graphics.CopyFromScreen($bounds.Location, [System.Drawing.Point]::Empty, $bounds.Size)
                                
                                $ms = New-Object System.IO.MemoryStream
                                $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
                                $base64 = [Convert]::ToBase64String($ms.ToArray())
                                
                                $graphics.Dispose()
                                $bmp.Dispose()
                                $ms.Dispose()
                                
                                # Save results - use -Compress and -Depth to avoid issues
                                $result = @{
                                    commandOutput = $commandOutput
                                    screenshot = $base64
                                    success = $true
                                } | ConvertTo-Json -Compress -Depth 10
                                $result | Out-File -FilePath $resultPath -Encoding UTF8 -NoNewline
                                
                                # Show completion message
                                Write-Host ""
                                Write-Host "Screenshot captured successfully!" -ForegroundColor Green
                                Write-Host "Waiting for next command..." -ForegroundColor Cyan
                                Write-Host ""
                                [Console]::Out.Flush()
                                Start-Sleep -Seconds 1
                            } catch {
                                $result = @{
                                    commandOutput = $commandOutput
                                    screenshot = $null
                                    success = $false
                                    error = $_.ToString()
                                } | ConvertTo-Json -Compress -Depth 10
                                $result | Out-File -FilePath $resultPath -Encoding UTF8 -NoNewline
                                Write-Host "Screenshot failed: $_" -ForegroundColor Red
                                Start-Sleep -Seconds 2
                            }
                        } catch {
                            Write-Host "Error processing command: $_" -ForegroundColor Red
                            Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
                            Write-Host "Stack trace: $($_.ScriptStackTrace)" -ForegroundColor Red
                            
                            # Write error result so the UI knows something went wrong
                            try {
                                $errorResult = @{
                                    commandOutput = "Error: $_"
                                    screenshot = $null
                                    success = $false
                                    error = $_.ToString()
                                } | ConvertTo-Json -Compress -Depth 10
                                $errorResult | Out-File -FilePath $resultPath -Encoding UTF8 -NoNewline
                            } catch {
                                Write-Host "Failed to write error result: $_" -ForegroundColor Red
                            }
                            
                            Start-Sleep -Seconds 1
                        }
                    } else {
                        Start-Sleep -Milliseconds 500
                    }
                }
            `;

            // Write persistent script to temp file
            const scriptPath = path.join(os.tmpdir(), 'stig-persistent-powershell.ps1');
            fs.writeFileSync(scriptPath, persistentScript, 'utf-8');

            // Also log the paths for debugging
            console.log('Queue path:', commandQueuePath);
            console.log('Result path:', commandResultPath);
            console.log('Script path:', scriptPath);

            // Launch PowerShell with admin privileges running the persistent script
            // Use proper escaping for the file path
            const scriptPathEscaped = scriptPath.replace(/\\/g, '/').replace(/'/g, "''");
            const launchScript = `Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoExit','-NoProfile','-ExecutionPolicy','Bypass','-File','${scriptPathEscaped}'`;

            const ps = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', launchScript]);
            let output = '';
            let error = '';

            ps.stdout.on('data', (data) => output += data.toString());
            ps.stderr.on('data', (data) => error += data.toString());

            ps.on('close', (code) => {
                // Give PowerShell window time to appear
                setTimeout(() => {
                    resolve({ success: true, message: 'PowerShell window launched. Please position it on the left side.' });
                }, 2000);
            });

            ps.on('error', (err) => {
                resolve({ success: false, error: err.message });
            });
        } catch (e: any) {
            resolve({ success: false, error: e.message });
        }
    });
});

// 5b. Execute Command in Admin PowerShell Window and Get Output
ipcMain.handle('execute-in-powershell', async (event, command: string) => {
    return new Promise((resolve) => {
        // Execute command in a new elevated PowerShell session and capture output
        const safeCommand = command.replace(/"/g, '`"').replace(/\$/g, '`$');
        const script = `
            Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile", "-Command", "${safeCommand}; Read-Host 'Press Enter to close'" -Wait -NoNewWindow -PassThru
        `;

        // Actually, better approach: Run command directly with elevation and capture output
        const execScript = `
            $ErrorActionPreference = 'Continue'
            try {
                ${command}
            } catch {
                Write-Output "ERROR: $_"
            }
        `;

        const ps = spawn('powershell.exe', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', execScript], {
            shell: true,
            // Request admin elevation (will show UAC prompt)
            windowsVerbatimArguments: false
        });

        let stdout = '';
        let stderr = '';

        ps.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        ps.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        ps.on('error', (error) => {
            resolve({ success: false, output: error.message, requiresAdmin: true });
        });

        ps.on('close', (code) => {
            if (code !== 0) {
                if (stderr.includes('Access is denied') || stderr.includes('Run as Administrator')) {
                    resolve({
                        success: false,
                        output: stderr || 'Access Denied: Administrative privileges required.',
                        requiresAdmin: true
                    });
                } else {
                    resolve({
                        success: false,
                        output: stdout || stderr || 'Command failed'
                    });
                }
            } else {
                resolve({ success: true, output: stdout });
            }
        });
    });
});

// 5c. Execute Command in Visible PowerShell and Capture Screenshot
// This writes the command to the queue file, which the persistent PowerShell window will pick up
ipcMain.handle('execute-command-with-screenshot', async (event, data: { command: string, groupId: string, evidenceType?: 'powershell' | 'regedit' | 'both' }) => {
    return new Promise(async (resolve) => {
        const { command, groupId, evidenceType = 'powershell' } = data;

        // Clear any previous result
        if (fs.existsSync(commandResultPath)) {
            fs.unlinkSync(commandResultPath);
        }

        // Extract registry path if this is a registry command
        let registryPath: string | null = null;
        const registryMatch = command.match(/Get-ItemProperty\s+-Path\s+['"](HKLM:[^'"]+|HKCU:[^'"]+)['"]/i);
        if (registryMatch) {
            registryPath = registryMatch[1];
        }

        // Write command to queue file
        const commandData = {
            groupId: groupId,
            command: command,
            registryPath: registryPath,
            evidenceType: evidenceType
        };

        try {
            const queueData = JSON.stringify(commandData);
            fs.writeFileSync(commandQueuePath, queueData, 'utf-8');
            console.log(`Wrote command to queue: ${commandQueuePath}`);
            console.log(`Command: ${command.substring(0, 100)}...`);

            // Small delay to ensure file is written
            await new Promise(r => setTimeout(r, 100));
        } catch (e: any) {
            console.error(`Failed to write queue file: ${e.message}`);
            resolve({
                success: false,
                output: `Failed to write command to queue: ${e.message}`,
                screenshot: null,
                error: e.message
            });
            return;
        }

        // Wait for result file to appear (the persistent PowerShell will write it)
        const maxWaitTime = 30000; // 30 seconds
        const checkInterval = 500; // Check every 500ms
        let elapsed = 0;

        const checkIntervalId = setInterval(() => {
            if (fs.existsSync(commandResultPath)) {
                clearInterval(checkIntervalId);

                // Wait a moment for file to be fully written
                setTimeout(() => {
                    try {
                        let resultContent = fs.readFileSync(commandResultPath, 'utf-8').trim();

                        // Handle potential BOM or extra whitespace
                        if (resultContent.charCodeAt(0) === 0xFEFF) {
                            resultContent = resultContent.slice(1);
                        }

                        // Try parsing the JSON
                        const result = JSON.parse(resultContent);

                        // Clean up result file
                        try {
                            fs.unlinkSync(commandResultPath);
                        } catch (e) {
                            // Ignore cleanup errors
                        }

                        if (result.screenshot && result.screenshot.length > 100) {
                            resolve({
                                success: result.success !== false,
                                output: result.commandOutput || '',
                                screenshot: `data:image/png;base64,${result.screenshot}`
                            });
                        } else {
                            resolve({
                                success: result.success !== false,
                                output: result.commandOutput || '',
                                screenshot: null,
                                error: result.error || 'Screenshot capture failed'
                            });
                        }
                    } catch (e: any) {
                        resolve({
                            success: false,
                            output: 'Failed to read results',
                            screenshot: null,
                            error: e.message
                        });
                    }
                }, 1000);
            } else {
                elapsed += checkInterval;
                if (elapsed >= maxWaitTime) {
                    clearInterval(checkIntervalId);
                    resolve({
                        success: false,
                        output: 'Timeout waiting for command to execute',
                        screenshot: null,
                        error: 'Result file not found within timeout period. Make sure the persistent PowerShell window is running.'
                    });
                }
            }
        }, checkInterval);
    });
});

// 4. Get Desktop Sources (for screenshots)
ipcMain.handle('get-sources', async () => {
    const sources = await desktopCapturer.getSources({ types: ['window', 'screen'], thumbnailSize: { width: 1920, height: 1080 } })
    return sources.map(source => ({
        id: source.id,
        name: source.name,
        thumbnail: source.thumbnail.toDataURL()
    }))
})

// 5. Save File Dialog
ipcMain.handle('save-file', async (event, { filename, content, type }) => {
    const { canceled, filePath } = await dialog.showSaveDialog({
        defaultPath: filename,
        filters: [
            type === 'csv' ? { name: 'CSV Files', extensions: ['csv'] } : { name: 'CKLB Files', extensions: ['cklb', 'json'] }
        ]
    })

    if (canceled || !filePath) return { success: false }

    try {
        fs.writeFileSync(filePath, content)
        return { success: true, filePath }
    } catch (e: any) {
        return { success: false, error: e.message }
    }
})

// ----------------------------------------------------------------------
// Native Pentest Framework
// ----------------------------------------------------------------------

import * as dns from 'dns';
import { promisify } from 'util';
import * as tls from 'tls';

const dnsReverse = promisify(dns.reverse);
const dnsLookup = promisify(dns.lookup);

// Port to service mapping
const PORT_SERVICE_MAP: { [key: number]: string } = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC',
    139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 587: 'Submission', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
    8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
};

// Native port scanner
ipcMain.handle('pentest-scan-port', async (_event, data: { host: string; port: number; timeout?: number }) => {
    const { host, port, timeout = 2000 } = data;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        let banner = '';

        socket.setTimeout(timeout);

        socket.on('connect', () => {
            // Try to grab banner
            const bannerTimer = setTimeout(() => {
                socket.destroy();
                resolve({
                    port,
                    state: 'open',
                    service: PORT_SERVICE_MAP[port] || 'Unknown',
                    banner: banner.trim() || undefined
                });
            }, 1500);

            // Send probe for HTTP
            if ([80, 8080, 8000, 8008].includes(port)) {
                socket.write('GET / HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n');
            }

            socket.on('data', (chunk) => {
                banner += chunk.toString();
                if (banner.length > 256) {
                    clearTimeout(bannerTimer);
                    socket.destroy();
                    resolve({
                        port,
                        state: 'open',
                        service: PORT_SERVICE_MAP[port] || 'Unknown',
                        banner: banner.substring(0, 256).trim()
                    });
                }
            });
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve({ port, state: 'filtered' });
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            if (err.code === 'ECONNREFUSED') {
                resolve({ port, state: 'closed' });
            } else {
                resolve({ port, state: 'filtered' });
            }
        });

        socket.connect(port, host);
    });
});

// Scan multiple ports
ipcMain.handle('pentest-scan-ports', async (_event, data: {
    host: string;
    ports: number[];
    timeout?: number;
    concurrency?: number
}) => {
    const { host, ports, timeout = 2000, concurrency = 50 } = data;
    const results: any[] = [];

    // Process in batches
    for (let i = 0; i < ports.length; i += concurrency) {
        const batch = ports.slice(i, i + concurrency);
        const batchResults = await Promise.all(
            batch.map(port =>
                new Promise((resolve) => {
                    const socket = new net.Socket();
                    socket.setTimeout(timeout);

                    socket.on('connect', () => {
                        socket.destroy();
                        resolve({
                            port,
                            state: 'open',
                            service: PORT_SERVICE_MAP[port] || 'Unknown'
                        });
                    });

                    socket.on('timeout', () => {
                        socket.destroy();
                        resolve({ port, state: 'filtered' });
                    });

                    socket.on('error', (err: any) => {
                        socket.destroy();
                        resolve({
                            port,
                            state: err.code === 'ECONNREFUSED' ? 'closed' : 'filtered'
                        });
                    });

                    socket.connect(port, host);
                })
            )
        );
        results.push(...batchResults);
    }

    return {
        host,
        ports: results.filter((r: any) => r.state === 'open'),
        allResults: results
    };
});

// SMB scanner
ipcMain.handle('pentest-scan-smb', async (_event, data: { host: string; port?: number; timeout?: number }) => {
    const { host, port = 445, timeout = 5000 } = data;

    // SMB Negotiate Request
    const SMB_NEGOTIATE = Buffer.from([
        0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00,
        0x18, 0x53, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00,
        0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50,
        0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4c,
        0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6e,
        0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b,
        0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02,
        0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4c, 0x41,
        0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c,
        0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
    ]);

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = {
            host,
            port,
            smb: null,
            vulnerabilities: []
        };

        socket.setTimeout(timeout);

        socket.on('connect', () => {
            socket.write(SMB_NEGOTIATE);
        });

        socket.on('data', (data) => {
            socket.destroy();

            // Parse SMB response
            if (data.length > 40) {
                const magic = data.slice(4, 8).toString();

                if (magic === '\\xffSMB' || data[4] === 0xff) {
                    // SMBv1
                    result.smb = {
                        version: '1',
                        dialect: 'NT LM 0.12',
                        smbv1Enabled: true
                    };
                    result.vulnerabilities.push({
                        id: 'SMB-001',
                        name: 'SMBv1 Enabled',
                        severity: 'high',
                        description: 'SMBv1 is enabled. This protocol has known vulnerabilities.',
                        host, port
                    });
                } else if (data[4] === 0xfe) {
                    // SMBv2/3
                    const dialect = data.length > 72 ? data.readUInt16LE(72) : 0;
                    let version = '2.0';
                    if (dialect >= 0x0311) version = '3.1.1';
                    else if (dialect >= 0x0300) version = '3.0';
                    else if (dialect >= 0x0210) version = '2.1';

                    result.smb = {
                        version,
                        dialect: `SMB ${version}`,
                        smbv1Enabled: false
                    };
                }
            }

            resolve(result);
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve({ ...result, error: 'Connection timeout' });
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            resolve({ ...result, error: err.message });
        });

        socket.connect(port, host);
    });
});

// SSH scanner
ipcMain.handle('pentest-scan-ssh', async (_event, data: { host: string; port?: number; timeout?: number }) => {
    const { host, port = 22, timeout = 5000 } = data;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = {
            host,
            port,
            ssh: null,
            vulnerabilities: []
        };

        let banner = '';

        socket.setTimeout(timeout);

        socket.on('data', (chunk) => {
            banner += chunk.toString();

            if (banner.includes('\\n') || banner.length > 200) {
                socket.destroy();

                // Parse SSH banner
                const match = banner.match(/SSH-(\\d+\\.\\d+)-([^\\s\\r\\n]+)/);
                if (match) {
                    result.ssh = {
                        protocol: match[1],
                        software: match[2],
                        banner: banner.trim()
                    };

                    // Check for vulnerable versions
                    if (/OpenSSH[_-]([1-6]\\.|7\\.[0-1])/i.test(banner)) {
                        result.vulnerabilities.push({
                            id: 'SSH-001',
                            name: 'Outdated OpenSSH Version',
                            severity: 'high',
                            description: 'OpenSSH version may have known vulnerabilities',
                            host, port
                        });
                    }

                    // Check for SSH v1
                    if (match[1].startsWith('1.')) {
                        result.vulnerabilities.push({
                            id: 'SSH-002',
                            name: 'SSH Protocol v1 Supported',
                            severity: 'critical',
                            description: 'SSH protocol version 1 is insecure',
                            host, port
                        });
                    }
                }

                resolve(result);
            }
        });

        socket.on('connect', () => {
            // SSH server sends banner first
        });

        socket.on('timeout', () => {
            socket.destroy();
            resolve({ ...result, error: 'Connection timeout' });
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            resolve({ ...result, error: err.message });
        });

        socket.connect(port, host);
    });
});

// HTTP scanner
ipcMain.handle('pentest-scan-http', async (_event, data: {
    host: string;
    port?: number;
    ssl?: boolean;
    timeout?: number
}) => {
    const { host, port = 80, ssl = false, timeout = 10000 } = data;
    const protocol = ssl ? https : http;

    return new Promise((resolve) => {
        const result: any = {
            host,
            port,
            http: null,
            tls: null,
            vulnerabilities: []
        };

        const options = {
            hostname: host,
            port,
            path: '/',
            method: 'GET',
            timeout,
            rejectUnauthorized: false,
            headers: { 'User-Agent': 'STRIX-Scanner/1.0' }
        };

        const req = protocol.request(options, (res) => {
            let body = '';

            res.on('data', (chunk) => {
                body += chunk;
                if (body.length > 5000) res.destroy();
            });

            res.on('end', () => {
                result.http = {
                    statusCode: res.statusCode,
                    server: res.headers.server,
                    poweredBy: res.headers['x-powered-by'],
                    headers: res.headers
                };

                // Check security headers
                const missingHeaders = [];
                if (!res.headers['strict-transport-security']) missingHeaders.push('HSTS');
                if (!res.headers['x-content-type-options']) missingHeaders.push('X-Content-Type-Options');
                if (!res.headers['x-frame-options']) missingHeaders.push('X-Frame-Options');

                if (missingHeaders.length > 0) {
                    result.vulnerabilities.push({
                        id: 'HTTP-001',
                        name: 'Missing Security Headers',
                        severity: 'medium',
                        description: `Missing: ${missingHeaders.join(', ')}`,
                        host, port
                    });
                }

                // Check server disclosure
                if (res.headers.server) {
                    result.vulnerabilities.push({
                        id: 'HTTP-002',
                        name: 'Server Version Disclosure',
                        severity: 'low',
                        description: `Server: ${res.headers.server}`,
                        host, port
                    });
                }

                resolve(result);
            });
        });

        req.on('timeout', () => {
            req.destroy();
            resolve({ ...result, error: 'Request timeout' });
        });

        req.on('error', (err: any) => {
            resolve({ ...result, error: err.message });
        });

        // Get TLS info for HTTPS
        if (ssl) {
            req.on('socket', (socket: any) => {
                socket.on('secureConnect', () => {
                    const cipher = socket.getCipher?.();
                    const cert = socket.getPeerCertificate?.();
                    const proto = socket.getProtocol?.();

                    result.tls = {
                        protocol: proto || 'unknown',
                        cipher: cipher?.name || 'unknown',
                        certValid: socket.authorized
                    };

                    if (cert) {
                        result.tls.certSubject = cert.subject?.CN;
                        result.tls.certExpiry = cert.valid_to;
                    }

                    // Check for weak TLS
                    if (proto && /TLSv1$|TLSv1\\.0|SSLv/i.test(proto)) {
                        result.vulnerabilities.push({
                            id: 'TLS-001',
                            name: 'Weak TLS Version',
                            severity: 'high',
                            description: `Protocol: ${proto}`,
                            host, port
                        });
                    }
                });
            });
        }

        req.end();
    });
});

// Get available modules
ipcMain.handle('pentest-get-modules', async () => {
    return [
        {
            name: 'port_scanner',
            displayName: 'Port Scanner',
            description: 'Fast TCP port scanner with service detection',
            type: 'scanner'
        },
        {
            name: 'smb_scanner',
            displayName: 'SMB Scanner',
            description: 'SMB version detection and vulnerability checks',
            type: 'vuln_check'
        },
        {
            name: 'ssh_scanner',
            displayName: 'SSH Scanner',
            description: 'SSH version and configuration analysis',
            type: 'vuln_check'
        },
        {
            name: 'http_scanner',
            displayName: 'HTTP/HTTPS Scanner',
            description: 'Web server security analysis and TLS checks',
            type: 'vuln_check'
        }
    ];
});

// Run full assessment
ipcMain.handle('pentest-full-assessment', async (_event, data: { host: string; ports?: number[] }) => {
    const { host, ports = [21, 22, 23, 25, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080] } = data;

    const results: any = {
        host,
        startTime: new Date(),
        openPorts: [],
        services: [],
        vulnerabilities: []
    };

    try {
        // Step 1: Port scan
        const portResults = await Promise.all(
            ports.map(port =>
                new Promise<any>((resolve) => {
                    const socket = new net.Socket();
                    socket.setTimeout(2000);

                    socket.on('connect', () => {
                        socket.destroy();
                        resolve({ port, state: 'open', service: PORT_SERVICE_MAP[port] || 'Unknown' });
                    });

                    socket.on('timeout', () => { socket.destroy(); resolve(null); });
                    socket.on('error', () => { socket.destroy(); resolve(null); });

                    socket.connect(port, host);
                })
            )
        );

        results.openPorts = portResults.filter(r => r !== null);

        // Step 2: Run specific scanners based on open ports
        for (const portInfo of results.openPorts) {
            if (portInfo.port === 445 || portInfo.port === 139) {
                // SMB scan would go here (simplified)
                results.services.push({ port: portInfo.port, service: 'SMB', detected: true });
            }
            if (portInfo.port === 22) {
                results.services.push({ port: portInfo.port, service: 'SSH', detected: true });
            }
            if ([80, 443, 8080, 8443].includes(portInfo.port)) {
                results.services.push({ port: portInfo.port, service: 'HTTP', detected: true });
            }
        }

        results.endTime = new Date();
        results.duration = results.endTime - results.startTime;

    } catch (err: any) {
        results.error = err.message;
    }

    return results;
});

// Nmap scanner integration
ipcMain.handle('pentest-nmap-scan', async (_event, data: {
    target: string;
    command: string;
    args: string[];
}) => {
    const { target, command, args } = data;

    return new Promise((resolve) => {
        const result: any = {
            target,
            command: `nmap ${args.join(' ')} ${target}`,
            output: [],
            hosts: [],
            ports: [],
            vulnerabilities: [],
            startTime: new Date(),
            success: false
        };

        try {
            const { spawn } = require('child_process');
            const nmap = spawn('nmap', [...args, target]);

            let stdout = '';
            let stderr = '';

            nmap.stdout.on('data', (data: Buffer) => {
                const text = data.toString();
                stdout += text;
                result.output.push(text);
            });

            nmap.stderr.on('data', (data: Buffer) => {
                stderr += data.toString();
            });

            nmap.on('close', (code: number) => {
                result.exitCode = code;
                result.success = code === 0;
                result.endTime = new Date();
                result.duration = result.endTime - result.startTime;
                result.rawOutput = stdout;
                result.stderr = stderr;

                // Parse nmap output
                const lines = stdout.split('\n');
                let currentHost = '';

                for (const line of lines) {
                    // Parse host
                    const hostMatch = line.match(/Nmap scan report for ([^\s]+)/);
                    if (hostMatch) {
                        currentHost = hostMatch[1];
                        result.hosts.push({ host: currentHost, ports: [] });
                    }

                    // Parse ports
                    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\w+)\s+(.*)$/);
                    if (portMatch && currentHost) {
                        const [, port, protocol, state, service] = portMatch;
                        const portInfo = {
                            port: parseInt(port),
                            protocol,
                            state,
                            service: service.trim(),
                            host: currentHost
                        };
                        result.ports.push(portInfo);

                        const hostEntry = result.hosts.find((h: any) => h.host === currentHost);
                        if (hostEntry) {
                            hostEntry.ports.push(portInfo);
                        }
                    }

                    // Parse OS detection
                    const osMatch = line.match(/OS details?: (.+)/);
                    if (osMatch && currentHost) {
                        const hostEntry = result.hosts.find((h: any) => h.host === currentHost);
                        if (hostEntry) {
                            hostEntry.os = osMatch[1];
                        }
                    }

                    // Parse vulnerabilities from scripts
                    if (line.includes('VULNERABLE') || line.includes('vulnerable')) {
                        result.vulnerabilities.push({
                            host: currentHost,
                            finding: line.trim()
                        });
                    }

                    // Parse CVEs
                    const cveMatch = line.match(/(CVE-\d{4}-\d+)/g);
                    if (cveMatch) {
                        for (const cve of cveMatch) {
                            result.vulnerabilities.push({
                                host: currentHost,
                                cve,
                                finding: line.trim()
                            });
                        }
                    }
                }

                resolve(result);
            });

            nmap.on('error', (err: any) => {
                result.error = err.message;
                if (err.code === 'ENOENT') {
                    result.error = 'nmap not found. Please install nmap and ensure it is in your PATH.';
                }
                resolve(result);
            });

            // Timeout after 10 minutes
            setTimeout(() => {
                nmap.kill();
                result.error = 'Scan timed out after 10 minutes';
                resolve(result);
            }, 600000);

        } catch (err: any) {
            result.error = err.message;
            resolve(result);
        }
    });
});

// Check if nmap is installed
ipcMain.handle('pentest-nmap-check', async () => {
    return new Promise((resolve) => {
        const { spawn } = require('child_process');
        const nmap = spawn('nmap', ['--version']);

        let version = '';

        nmap.stdout.on('data', (data: Buffer) => {
            version += data.toString();
        });

        nmap.on('close', (code: number) => {
            if (code === 0) {
                const match = version.match(/Nmap version ([\d.]+)/);
                resolve({
                    installed: true,
                    version: match ? match[1] : 'unknown',
                    output: version.trim()
                });
            } else {
                resolve({ installed: false });
            }
        });

        nmap.on('error', () => {
            resolve({ installed: false });
        });
    });
});

// ----------------------------------------------------------------------
// Native Exploit Modules
// ----------------------------------------------------------------------

// Common credentials for brute force
const COMMON_CREDENTIALS = [
    { user: 'admin', pass: 'admin' },
    { user: 'admin', pass: 'password' },
    { user: 'admin', pass: '123456' },
    { user: 'root', pass: 'root' },
    { user: 'root', pass: 'toor' },
    { user: 'root', pass: 'password' },
    { user: 'administrator', pass: 'administrator' },
    { user: 'user', pass: 'user' },
    { user: 'test', pass: 'test' },
    { user: 'guest', pass: 'guest' },
    { user: 'admin', pass: '' },
    { user: 'root', pass: '' },
    { user: 'sa', pass: '' },
    { user: 'sa', pass: 'sa' },
    { user: 'postgres', pass: 'postgres' },
];

// FTP Anonymous Login Check
ipcMain.handle('exploit-ftp-anonymous', async (_event, data: { host: string; port?: number }) => {
    const { host, port = 21 } = data;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = { vulnerable: false, host, port, exploit: 'FTP Anonymous Login' };
        let stage = 0;

        socket.setTimeout(10000);

        socket.on('data', (chunk) => {
            const response = chunk.toString();

            if (stage === 0 && response.includes('220')) {
                stage = 1;
                socket.write('USER anonymous\r\n');
            } else if (stage === 1 && response.includes('331')) {
                stage = 2;
                socket.write('PASS anonymous@example.com\r\n');
            } else if (stage === 2) {
                if (response.includes('230')) {
                    result.vulnerable = true;
                    result.message = 'Anonymous FTP login successful!';
                    result.evidence = response.trim();
                    socket.write('QUIT\r\n');
                } else {
                    result.message = 'Anonymous login rejected';
                }
                socket.destroy();
                resolve(result);
            }
        });

        socket.on('timeout', () => {
            socket.destroy();
            result.message = 'Connection timeout';
            resolve(result);
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            result.message = err.message;
            resolve(result);
        });

        socket.connect(port, host);
    });
});

// SSH Brute Force
ipcMain.handle('exploit-ssh-bruteforce', async (_event, data: { host: string; port?: number; credentials?: any[] }) => {
    const { host, port = 22, credentials = COMMON_CREDENTIALS } = data;
    const result: any = {
        vulnerable: false,
        host,
        port,
        exploit: 'SSH Brute Force',
        attempts: [],
        validCredentials: []
    };

    // For SSH brute force, we'd need an SSH library
    // This is a simplified version that just checks if SSH is open
    return new Promise((resolve) => {
        const socket = new net.Socket();
        socket.setTimeout(5000);

        socket.on('connect', () => {
            result.message = 'SSH port is open. Manual brute force testing recommended.';
            result.note = 'For actual SSH brute force, install and use hydra or medusa';
            socket.destroy();
            resolve(result);
        });

        socket.on('error', (err: any) => {
            result.message = `SSH connection failed: ${err.message}`;
            resolve(result);
        });

        socket.on('timeout', () => {
            socket.destroy();
            result.message = 'Connection timeout';
            resolve(result);
        });

        socket.connect(port, host);
    });
});

// SMB Null Session Check
ipcMain.handle('exploit-smb-null-session', async (_event, data: { host: string; port?: number }) => {
    const { host, port = 445 } = data;

    // SMB null session attempt
    const SMB_NEG_REQUEST = Buffer.from([
        0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00,
        0x18, 0x53, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00,
        0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50,
        0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4c,
        0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x57, 0x69, 0x6e,
        0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57, 0x6f, 0x72, 0x6b,
        0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02,
        0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4c, 0x41,
        0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c,
        0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00
    ]);

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = { vulnerable: false, host, port, exploit: 'SMB Null Session' };

        socket.setTimeout(10000);

        socket.on('connect', () => {
            socket.write(SMB_NEG_REQUEST);
        });

        socket.on('data', (data) => {
            // Check if SMB negotiation succeeded
            if (data.length > 8 && (data[4] === 0xff || data[4] === 0xfe)) {
                result.vulnerable = true;
                result.message = 'SMB accepts connections - null session may be possible';
                result.evidence = `SMB Response received (${data.length} bytes)`;
                result.note = 'Use smbclient -N -L to enumerate shares';
            }
            socket.destroy();
            resolve(result);
        });

        socket.on('timeout', () => {
            socket.destroy();
            result.message = 'Connection timeout';
            resolve(result);
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            result.message = err.message;
            resolve(result);
        });

        socket.connect(port, host);
    });
});

// HTTP Directory Listing Check
ipcMain.handle('exploit-http-dirlist', async (_event, data: { host: string; port?: number; ssl?: boolean }) => {
    const { host, port = 80, ssl = false } = data;
    const protocol = ssl ? https : http;

    return new Promise((resolve) => {
        const result: any = { vulnerable: false, host, port, exploit: 'Directory Listing' };
        const directories = ['/', '/admin/', '/backup/', '/images/', '/uploads/', '/files/', '/data/'];
        const found: string[] = [];
        let checked = 0;

        const checkDir = (dir: string) => {
            const req = protocol.request({
                hostname: host,
                port,
                path: dir,
                method: 'GET',
                timeout: 5000,
                rejectUnauthorized: false
            }, (res) => {
                let body = '';
                res.on('data', (chunk) => { body += chunk; });
                res.on('end', () => {
                    if (body.includes('Index of') || body.includes('Directory listing') ||
                        body.includes('<title>Index of') || body.includes('Parent Directory')) {
                        found.push(dir);
                    }
                    checked++;
                    if (checked === directories.length) {
                        result.vulnerable = found.length > 0;
                        result.directories = found;
                        result.message = found.length > 0
                            ? `Found ${found.length} directories with listing enabled`
                            : 'No directory listing found';
                        resolve(result);
                    }
                });
            });
            req.on('error', () => {
                checked++;
                if (checked === directories.length) {
                    result.vulnerable = found.length > 0;
                    result.directories = found;
                    result.message = found.length > 0
                        ? `Found ${found.length} directories with listing enabled`
                        : 'No directory listing found';
                    resolve(result);
                }
            });
            req.on('timeout', () => { req.destroy(); });
            req.end();
        };

        directories.forEach(checkDir);
    });
});

// HTTP Shellshock Check (CVE-2014-6271)
ipcMain.handle('exploit-http-shellshock', async (_event, data: { host: string; port?: number; ssl?: boolean; path?: string }) => {
    const { host, port = 80, ssl = false, path = '/cgi-bin/status' } = data;
    const protocol = ssl ? https : http;

    return new Promise((resolve) => {
        const result: any = { vulnerable: false, host, port, exploit: 'Shellshock (CVE-2014-6271)' };

        // Shellshock payload - safe test that just echoes
        const payload = '() { :; }; echo; echo vulnerable';

        const paths = [path, '/cgi-bin/test.cgi', '/cgi-bin/status', '/cgi-bin/admin.cgi', '/cgi-bin/test.sh'];
        let checked = 0;

        const checkPath = (cgiPath: string) => {
            const req = protocol.request({
                hostname: host,
                port,
                path: cgiPath,
                method: 'GET',
                timeout: 5000,
                rejectUnauthorized: false,
                headers: {
                    'User-Agent': payload,
                    'Cookie': payload,
                    'Referer': payload
                }
            }, (res) => {
                let body = '';
                res.on('data', (chunk) => { body += chunk; });
                res.on('end', () => {
                    if (body.includes('vulnerable')) {
                        result.vulnerable = true;
                        result.path = cgiPath;
                        result.message = `Shellshock vulnerable at ${cgiPath}`;
                        result.evidence = body.substring(0, 200);
                    }
                    checked++;
                    if (checked === paths.length && !result.vulnerable) {
                        result.message = 'No Shellshock vulnerability detected';
                    }
                    if (checked === paths.length || result.vulnerable) {
                        resolve(result);
                    }
                });
            });
            req.on('error', () => {
                checked++;
                if (checked === paths.length) {
                    result.message = result.vulnerable ? result.message : 'Check failed or not vulnerable';
                    resolve(result);
                }
            });
            req.on('timeout', () => { req.destroy(); });
            req.end();
        };

        paths.forEach(checkPath);
    });
});

// Redis No Auth Check
ipcMain.handle('exploit-redis-noauth', async (_event, data: { host: string; port?: number }) => {
    const { host, port = 6379 } = data;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = { vulnerable: false, host, port, exploit: 'Redis No Authentication' };

        socket.setTimeout(5000);

        socket.on('connect', () => {
            socket.write('INFO\r\n');
        });

        socket.on('data', (data) => {
            const response = data.toString();
            if (response.includes('redis_version') || response.includes('# Server')) {
                result.vulnerable = true;
                result.message = 'Redis server has no authentication!';
                // Extract version
                const versionMatch = response.match(/redis_version:([^\r\n]+)/);
                if (versionMatch) {
                    result.version = versionMatch[1];
                }
                result.evidence = response.substring(0, 500);
            } else if (response.includes('NOAUTH') || response.includes('Authentication required')) {
                result.message = 'Redis requires authentication';
            }
            socket.destroy();
            resolve(result);
        });

        socket.on('timeout', () => {
            socket.destroy();
            result.message = 'Connection timeout';
            resolve(result);
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            result.message = err.message;
            resolve(result);
        });

        socket.connect(port, host);
    });
});

// MongoDB No Auth Check
ipcMain.handle('exploit-mongodb-noauth', async (_event, data: { host: string; port?: number }) => {
    const { host, port = 27017 } = data;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = { vulnerable: false, host, port, exploit: 'MongoDB No Authentication' };

        // MongoDB wire protocol - simple isMaster command
        const query = Buffer.from([
            0x3f, 0x00, 0x00, 0x00, // Message length
            0x00, 0x00, 0x00, 0x00, // Request ID
            0x00, 0x00, 0x00, 0x00, // Response to
            0xd4, 0x07, 0x00, 0x00, // OpCode (OP_QUERY)
            0x00, 0x00, 0x00, 0x00, // Flags
            0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // "admin.$cmd"
            0x00, 0x00, 0x00, 0x00, // Number to skip
            0x01, 0x00, 0x00, 0x00, // Number to return
            // BSON document: { isMaster: 1 }
            0x15, 0x00, 0x00, 0x00,
            0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
            0x01, 0x00, 0x00, 0x00,
            0x00
        ]);

        socket.setTimeout(5000);

        socket.on('connect', () => {
            socket.write(query);
        });

        socket.on('data', (data) => {
            // Check if we got a valid response
            if (data.length > 36) {
                result.vulnerable = true;
                result.message = 'MongoDB server has no authentication!';
                result.evidence = `Response received (${data.length} bytes)`;
            }
            socket.destroy();
            resolve(result);
        });

        socket.on('timeout', () => {
            socket.destroy();
            result.message = 'Connection timeout';
            resolve(result);
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            result.message = err.message;
            resolve(result);
        });

        socket.connect(port, host);
    });
});

// VNC No Auth Check
ipcMain.handle('exploit-vnc-noauth', async (_event, data: { host: string; port?: number }) => {
    const { host, port = 5900 } = data;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = { vulnerable: false, host, port, exploit: 'VNC No Authentication' };
        let stage = 0;

        socket.setTimeout(5000);

        socket.on('data', (data) => {
            const response = data.toString();

            if (stage === 0) {
                // Protocol version
                if (response.includes('RFB')) {
                    stage = 1;
                    result.version = response.trim();
                    // Send our version
                    socket.write('RFB 003.008\n');
                }
            } else if (stage === 1) {
                // Security types
                const secTypes = data;
                if (secTypes.length > 0) {
                    const numTypes = secTypes[0];
                    if (numTypes > 0) {
                        // Check if type 1 (None) is in the list
                        for (let i = 1; i <= numTypes && i < secTypes.length; i++) {
                            if (secTypes[i] === 1) {
                                result.vulnerable = true;
                                result.message = 'VNC server accepts connections without authentication!';
                                result.evidence = `Security type 1 (None) available`;
                                break;
                            }
                        }
                        if (!result.vulnerable) {
                            result.message = 'VNC requires authentication';
                        }
                    }
                }
                socket.destroy();
                resolve(result);
            }
        });

        socket.on('timeout', () => {
            socket.destroy();
            result.message = 'Connection timeout';
            resolve(result);
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            result.message = err.message;
            resolve(result);
        });

        socket.connect(port, host);
    });
});

// MySQL No Password Check
ipcMain.handle('exploit-mysql-nopass', async (_event, data: { host: string; port?: number }) => {
    const { host, port = 3306 } = data;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = { vulnerable: false, host, port, exploit: 'MySQL No Password' };

        socket.setTimeout(5000);

        socket.on('data', (data) => {
            // Check MySQL greeting packet
            if (data.length > 5) {
                const protocolVersion = data[4];
                if (protocolVersion === 10 || protocolVersion === 9) {
                    result.message = 'MySQL server detected. Use mysql client to test authentication.';
                    // Try to extract version
                    let versionEnd = 5;
                    while (versionEnd < data.length && data[versionEnd] !== 0) {
                        versionEnd++;
                    }
                    if (versionEnd > 5) {
                        result.version = data.slice(5, versionEnd).toString();
                    }
                }
            }
            socket.destroy();
            resolve(result);
        });

        socket.on('timeout', () => {
            socket.destroy();
            result.message = 'Connection timeout';
            resolve(result);
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            result.message = err.message;
            resolve(result);
        });

        socket.connect(port, host);
    });
});

// Telnet Banner Grab and Default Creds Check
ipcMain.handle('exploit-telnet-banner', async (_event, data: { host: string; port?: number }) => {
    const { host, port = 23 } = data;

    return new Promise((resolve) => {
        const socket = new net.Socket();
        const result: any = { vulnerable: false, host, port, exploit: 'Telnet Service' };
        let banner = '';

        socket.setTimeout(5000);

        socket.on('data', (data) => {
            banner += data.toString();

            // Check for common default credential hints
            if (banner.includes('login:') || banner.includes('Username:')) {
                result.message = 'Telnet login prompt detected. Test for default credentials.';
                result.banner = banner.substring(0, 500);
                result.note = 'Common defaults: admin/admin, root/root, user/user';
                socket.destroy();
                resolve(result);
            }
        });

        // Give time for banner
        setTimeout(() => {
            if (banner) {
                result.message = 'Telnet service detected';
                result.banner = banner.substring(0, 500);
            }
            socket.destroy();
            resolve(result);
        }, 3000);

        socket.on('timeout', () => {
            socket.destroy();
            result.message = banner ? 'Telnet detected' : 'Connection timeout';
            result.banner = banner;
            resolve(result);
        });

        socket.on('error', (err: any) => {
            socket.destroy();
            result.message = err.message;
            resolve(result);
        });

        socket.connect(port, host);
    });
});

// Get available exploits for a port
ipcMain.handle('exploit-get-for-port', async (_event, data: { port: number }) => {
    const { port } = data;

    const exploits: any[] = [];

    // FTP exploits
    if (port === 21) {
        exploits.push(
            { id: 'ftp-anonymous', name: 'FTP Anonymous Login', handler: 'exploit-ftp-anonymous', severity: 'medium' },
        );
    }

    // SSH exploits
    if (port === 22) {
        exploits.push(
            { id: 'ssh-bruteforce', name: 'SSH Brute Force', handler: 'exploit-ssh-bruteforce', severity: 'high' },
        );
    }

    // Telnet
    if (port === 23) {
        exploits.push(
            { id: 'telnet-banner', name: 'Telnet Banner/Default Creds', handler: 'exploit-telnet-banner', severity: 'high' },
        );
    }

    // HTTP exploits
    if ([80, 8080, 8000, 8008].includes(port)) {
        exploits.push(
            { id: 'http-dirlist', name: 'Directory Listing', handler: 'exploit-http-dirlist', severity: 'low' },
            { id: 'http-shellshock', name: 'Shellshock (CVE-2014-6271)', handler: 'exploit-http-shellshock', severity: 'critical' },
        );
    }

    // SMB exploits
    if ([139, 445].includes(port)) {
        exploits.push(
            { id: 'smb-null-session', name: 'SMB Null Session', handler: 'exploit-smb-null-session', severity: 'medium' },
        );
    }

    // MySQL
    if (port === 3306) {
        exploits.push(
            { id: 'mysql-nopass', name: 'MySQL No Password', handler: 'exploit-mysql-nopass', severity: 'critical' },
        );
    }

    // RDP
    if (port === 3389) {
        exploits.push(
            { id: 'rdp-check', name: 'RDP Security Check', handler: 'exploit-rdp-check', severity: 'medium' },
        );
    }

    // VNC
    if ([5900, 5901, 5902].includes(port)) {
        exploits.push(
            { id: 'vnc-noauth', name: 'VNC No Authentication', handler: 'exploit-vnc-noauth', severity: 'critical' },
        );
    }

    // Redis
    if (port === 6379) {
        exploits.push(
            { id: 'redis-noauth', name: 'Redis No Authentication', handler: 'exploit-redis-noauth', severity: 'critical' },
        );
    }

    // MongoDB
    if (port === 27017) {
        exploits.push(
            { id: 'mongodb-noauth', name: 'MongoDB No Authentication', handler: 'exploit-mongodb-noauth', severity: 'critical' },
        );
    }

    return exploits;
});

// ----------------------------------------------------------------------
// Metasploit RPC Integration
// ----------------------------------------------------------------------

// Store for Metasploit connection state
let msfToken: string | null = null;
let msfHost: string = '127.0.0.1';
let msfPort: number = 55553;
let msfSSL: boolean = true;

// Helper function to recursively convert Buffer keys to strings in decoded msgpack
function convertBufferKeys(obj: any): any {
    if (obj === null || obj === undefined) {
        return obj;
    }

    if (obj instanceof Map) {
        const result: any = {};
        obj.forEach((value: any, key: any) => {
            const keyStr = key instanceof Uint8Array || Buffer.isBuffer(key)
                ? Buffer.from(key).toString('utf-8')
                : String(key);
            result[keyStr] = convertBufferKeys(value);
        });
        return result;
    }

    if (Array.isArray(obj)) {
        return obj.map(item => convertBufferKeys(item));
    }

    if (obj instanceof Uint8Array || Buffer.isBuffer(obj)) {
        return Buffer.from(obj).toString('utf-8');
    }

    if (typeof obj === 'object') {
        const result: any = {};
        for (const key of Object.keys(obj)) {
            result[key] = convertBufferKeys(obj[key]);
        }
        return result;
    }

    return obj;
}

// Helper function to make Metasploit RPC calls
async function msfRpcCall(method: string, params: any[] = []): Promise<any> {
    return new Promise((resolve, reject) => {
        const data = msgpack.encode([method, ...params]);

        const options = {
            hostname: msfHost,
            port: msfPort,
            path: '/api/',
            method: 'POST',
            headers: {
                'Content-Type': 'binary/message-pack',
                'Content-Length': data.length
            },
            rejectUnauthorized: false // Metasploit uses self-signed certs
        };

        const protocol = msfSSL ? https : http;

        const req = protocol.request(options, (res) => {
            const chunks: Buffer[] = [];

            res.on('data', (chunk) => {
                chunks.push(chunk);
            });

            res.on('end', () => {
                try {
                    const responseData = Buffer.concat(chunks);
                    // msgpack-lite handles binary keys natively
                    const rawResult = msgpack.decode(responseData);
                    const result = convertBufferKeys(rawResult);

                    if (result && result.error) {
                        reject(new Error(result.error_message || result.error));
                    } else {
                        resolve(result);
                    }
                } catch (e: any) {
                    reject(new Error(`Failed to decode response: ${e.message}`));
                }
            });
        });

        req.on('error', (e: any) => {
            reject(new Error(`Connection failed: ${e.message}`));
        });

        req.setTimeout(10000, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });

        req.write(Buffer.from(data));
        req.end();
    });
}

// MSF Connect - Authenticate and get token
ipcMain.handle('msf-connect', async (_event, data: { host: string; port: string; password: string; ssl?: boolean }) => {
    try {
        msfHost = data.host || '127.0.0.1';
        msfPort = parseInt(data.port) || 55553;
        msfSSL = data.ssl !== false;

        // Authenticate with Metasploit RPC
        const result = await msfRpcCall('auth.login', ['msf', data.password]);

        if (result && result.token) {
            msfToken = result.token;

            // Get version info
            let version = 'Unknown';
            try {
                const versionInfo = await msfRpcCall('core.version', [msfToken]);
                version = versionInfo?.version || 'Unknown';
            } catch (e) {
                // Ignore version fetch errors
            }

            return {
                success: true,
                token: msfToken,
                version: version,
                message: `Connected to Metasploit Framework ${version}`
            };
        } else {
            return { success: false, error: 'Authentication failed - no token received' };
        }
    } catch (e: any) {
        msfToken = null;
        return { success: false, error: e.message };
    }
});

// MSF Disconnect
ipcMain.handle('msf-disconnect', async () => {
    if (msfToken) {
        try {
            await msfRpcCall('auth.logout', [msfToken]);
        } catch (e) {
            // Ignore logout errors
        }
    }
    msfToken = null;
    return { success: true };
});

// MSF Generic RPC Call
ipcMain.handle('msf-call', async (_event, data: { method: string; params?: any[] }) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        // Prepend token to params for authenticated calls
        const params = data.params || [];
        const result = await msfRpcCall(data.method, [msfToken, ...params]);
        return { success: true, result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Module Search
ipcMain.handle('msf-module-search', async (_event, query: string) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('module.search', [msfToken, query]);
        return { success: true, modules: result || [] };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Module Info
ipcMain.handle('msf-module-info', async (_event, data: { type: string; name: string }) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('module.info', [msfToken, data.type, data.name]);
        return { success: true, info: result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Module Options
ipcMain.handle('msf-module-options', async (_event, data: { type: string; name: string }) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('module.options', [msfToken, data.type, data.name]);
        return { success: true, options: result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Execute Module
ipcMain.handle('msf-module-execute', async (_event, data: { type: string; name: string; options: Record<string, any> }) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('module.execute', [msfToken, data.type, data.name, data.options]);
        return { success: true, result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Get Sessions
ipcMain.handle('msf-sessions', async () => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('session.list', [msfToken]);
        return { success: true, sessions: result || {} };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Session Interact (read/write to shell)
ipcMain.handle('msf-session-read', async (_event, sessionId: string) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('session.shell_read', [msfToken, sessionId]);
        return { success: true, data: result?.data || '' };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

ipcMain.handle('msf-session-write', async (_event, data: { sessionId: string; command: string }) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('session.shell_write', [msfToken, data.sessionId, data.command + '\n']);
        return { success: true, result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Console - Create, Read, Write, Destroy
ipcMain.handle('msf-console-create', async () => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('console.create', [msfToken]);
        return { success: true, consoleId: result?.id };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

ipcMain.handle('msf-console-read', async (_event, consoleId: string) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('console.read', [msfToken, consoleId]);
        return { success: true, data: result?.data || '', prompt: result?.prompt, busy: result?.busy };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

ipcMain.handle('msf-console-write', async (_event, data: { consoleId: string; command: string }) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('console.write', [msfToken, data.consoleId, data.command + '\n']);
        return { success: true, result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

ipcMain.handle('msf-console-destroy', async (_event, consoleId: string) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('console.destroy', [msfToken, consoleId]);
        return { success: true, result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF DB Hosts - Get discovered hosts from database
ipcMain.handle('msf-db-hosts', async () => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('db.hosts', [msfToken, {}]);
        return { success: true, hosts: result?.hosts || [] };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF DB Services - Get discovered services
ipcMain.handle('msf-db-services', async (_event, host?: string) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const opts: any = {};
        if (host) opts.hosts = host;
        const result = await msfRpcCall('db.services', [msfToken, opts]);
        return { success: true, services: result?.services || [] };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF DB Vulns - Get discovered vulnerabilities
ipcMain.handle('msf-db-vulns', async (_event, host?: string) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const opts: any = {};
        if (host) opts.hosts = host;
        const result = await msfRpcCall('db.vulns', [msfToken, opts]);
        return { success: true, vulns: result?.vulns || [] };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Jobs - List running jobs (scans, exploits, etc.)
ipcMain.handle('msf-jobs', async () => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('job.list', [msfToken]);
        return { success: true, jobs: result || {} };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Job Info
ipcMain.handle('msf-job-info', async (_event, jobId: string) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('job.info', [msfToken, jobId]);
        return { success: true, info: result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// MSF Job Stop
ipcMain.handle('msf-job-stop', async (_event, jobId: string) => {
    if (!msfToken) {
        return { success: false, error: 'Not connected to Metasploit' };
    }

    try {
        const result = await msfRpcCall('job.stop', [msfToken, jobId]);
        return { success: true, result };
    } catch (e: any) {
        return { success: false, error: e.message };
    }
});

// ----------------------------------------------------------------------
// Web Scanner - HTTP Fetch (bypasses CORS)
// ----------------------------------------------------------------------

interface WebScanRequest {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
    followRedirects?: boolean;
}

interface WebScanResponse {
    success: boolean;
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
    body?: string;
    error?: string;
    url?: string;
    redirected?: boolean;
}

ipcMain.handle('web-scan-fetch', async (_event, request: WebScanRequest): Promise<WebScanResponse> => {
    const timeout = request.timeout || 5000; // Default 5s timeout

    return new Promise((resolve) => {
        let resolved = false;
        let req: ReturnType<typeof http.request> | null = null;

        // Hard timeout - absolutely kill the request after timeout
        const hardTimeout = setTimeout(() => {
            if (!resolved) {
                resolved = true;
                if (req) {
                    req.destroy();
                }
                resolve({
                    success: false,
                    error: 'Request timed out',
                    url: request.url
                });
            }
        }, timeout);

        const cleanup = () => {
            clearTimeout(hardTimeout);
        };

        try {
            const urlObj = new URL(request.url);
            const isHttps = urlObj.protocol === 'https:';
            const httpModule = isHttps ? https : http;

            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port || (isHttps ? 443 : 80),
                path: urlObj.pathname + urlObj.search,
                method: request.method || 'GET',
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) STRIX-Scanner/1.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    ...request.headers
                },
                rejectUnauthorized: false // Allow self-signed certs for scanning
            };

            req = httpModule.request(options, (res) => {
                let body = '';
                const responseHeaders: Record<string, string> = {};

                // Collect headers
                for (const [key, value] of Object.entries(res.headers)) {
                    if (typeof value === 'string') {
                        responseHeaders[key.toLowerCase()] = value;
                    } else if (Array.isArray(value)) {
                        responseHeaders[key.toLowerCase()] = value.join(', ');
                    }
                }

                // Handle redirects
                if (request.followRedirects !== false && res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
                    // Follow redirect - but with reduced timeout
                    cleanup();
                    if (!resolved) {
                        resolved = true;
                        const redirectUrl = new URL(res.headers.location, request.url).href;
                        // Recursively handle redirect via new IPC call
                        resolve({
                            success: false,
                            error: 'Redirect - skipping for speed',
                            url: request.url
                        });
                    }
                    return;
                }

                res.setEncoding('utf8');
                res.on('data', (chunk) => {
                    body += chunk;
                    // Limit body size to 500KB for dir enum (speed)
                    if (body.length > 500 * 1024) {
                        cleanup();
                        if (!resolved) {
                            resolved = true;
                            req?.destroy();
                            resolve({
                                success: true,
                                status: res.statusCode,
                                statusText: res.statusMessage,
                                headers: responseHeaders,
                                body: body.substring(0, 500 * 1024),
                                url: request.url
                            });
                        }
                    }
                });

                res.on('end', () => {
                    cleanup();
                    if (!resolved) {
                        resolved = true;
                        resolve({
                            success: true,
                            status: res.statusCode,
                            statusText: res.statusMessage,
                            headers: responseHeaders,
                            body,
                            url: request.url,
                            redirected: false
                        });
                    }
                });

                res.on('error', () => {
                    cleanup();
                    if (!resolved) {
                        resolved = true;
                        resolve({
                            success: false,
                            error: 'Response error',
                            url: request.url
                        });
                    }
                });
            });

            // Socket timeout
            req.setTimeout(timeout, () => {
                cleanup();
                if (!resolved) {
                    resolved = true;
                    req?.destroy();
                    resolve({
                        success: false,
                        error: 'Socket timeout',
                        url: request.url
                    });
                }
            });

            req.on('error', (e) => {
                cleanup();
                if (!resolved) {
                    resolved = true;
                    resolve({
                        success: false,
                        error: e.message,
                        url: request.url
                    });
                }
            });

            if (request.body) {
                req.write(request.body);
            }

            req.end();
        } catch (e: any) {
            cleanup();
            if (!resolved) {
                resolved = true;
                resolve({
                    success: false,
                    error: e.message,
                    url: request.url
                });
            }
        }
    });
});

// Batch fetch for scanning multiple URLs

// ----------------------------------------------------------------------
// API Key Tester - Tests exchange/service API credentials
// ----------------------------------------------------------------------

interface APITestRequest {
    service: string;
    apiKey: string;
    secretKey?: string;
    passphrase?: string;
}

interface APITestResponse {
    success: boolean;
    active: boolean;
    service: string;
    message: string;
    accountInfo?: any;
    permissions?: string[];
    balance?: string;
    error?: string;
}

// Helper to make HTTPS requests
function makeRequest(options: https.RequestOptions, body?: string): Promise<{ status: number; data: string }> {
    return new Promise((resolve, reject) => {
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode || 0, data }));
        });
        req.on('error', reject);
        req.setTimeout(10000, () => { req.destroy(); reject(new Error('Timeout')); });
        if (body) req.write(body);
        req.end();
    });
}

ipcMain.handle('test-api-credential', async (_event, request: APITestRequest): Promise<APITestResponse> => {
    console.log('[API-Tester] Received test request for:', request.service);
    console.log('[API-Tester] API Key (first 10):', request.apiKey?.substring(0, 10));

    const { service, apiKey, secretKey, passphrase } = request;

    try {
        switch (service.toLowerCase()) {
            case 'binance': {
                if (!secretKey) {
                    return { success: false, active: false, service, message: 'Secret key required for Binance', error: 'Missing secret key' };
                }
                const timestamp = Date.now();
                const queryString = `timestamp=${timestamp}`;
                const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');

                const result = await makeRequest({
                    hostname: 'api.binance.com',
                    path: `/api/v3/account?${queryString}&signature=${signature}`,
                    method: 'GET',
                    headers: { 'X-MBX-APIKEY': apiKey }
                });

                if (result.status === 200) {
                    const data = JSON.parse(result.data);
                    const balances = data.balances?.filter((b: any) => parseFloat(b.free) > 0 || parseFloat(b.locked) > 0) || [];
                    return {
                        success: true, active: true, service: 'Binance',
                        message: 'API key is active',
                        accountInfo: { canTrade: data.canTrade, canWithdraw: data.canWithdraw },
                        permissions: data.permissions || [],
                        balance: balances.length > 0 ? `${balances.length} assets with balance` : 'No balance'
                    };
                } else if (result.status === 401 || result.status === 403) {
                    return { success: true, active: false, service: 'Binance', message: 'Invalid API key or secret' };
                }
                return { success: true, active: false, service: 'Binance', message: `API returned status ${result.status}` };
            }

            case 'coinbase': {
                // Coinbase API v2 with API key
                const timestamp = Math.floor(Date.now() / 1000).toString();
                const method = 'GET';
                const requestPath = '/v2/user';
                const message = timestamp + method + requestPath;
                const signature = secretKey ? crypto.createHmac('sha256', secretKey).update(message).digest('hex') : '';

                const result = await makeRequest({
                    hostname: 'api.coinbase.com',
                    path: requestPath,
                    method: 'GET',
                    headers: {
                        'CB-ACCESS-KEY': apiKey,
                        'CB-ACCESS-SIGN': signature,
                        'CB-ACCESS-TIMESTAMP': timestamp,
                        'CB-VERSION': '2021-08-03'
                    }
                });

                if (result.status === 200) {
                    const data = JSON.parse(result.data);
                    return {
                        success: true, active: true, service: 'Coinbase',
                        message: 'API key is active',
                        accountInfo: { name: data.data?.name, email: data.data?.email }
                    };
                }
                return { success: true, active: false, service: 'Coinbase', message: `API returned status ${result.status}` };
            }

            case 'kraken': {
                if (!secretKey) {
                    return { success: false, active: false, service, message: 'Private key required for Kraken', error: 'Missing private key' };
                }
                const nonce = Date.now() * 1000;
                const postData = `nonce=${nonce}`;
                const urlPath = '/0/private/Balance';
                const hash = crypto.createHash('sha256').update(nonce + postData).digest();
                const secretBuffer = Buffer.from(secretKey, 'base64');
                const hmac = crypto.createHmac('sha512', secretBuffer);
                hmac.update(urlPath);
                hmac.update(hash);
                const signature = hmac.digest('base64');

                const result = await makeRequest({
                    hostname: 'api.kraken.com',
                    path: urlPath,
                    method: 'POST',
                    headers: {
                        'API-Key': apiKey,
                        'API-Sign': signature,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }, postData);

                if (result.status === 200) {
                    const data = JSON.parse(result.data);
                    if (data.error && data.error.length > 0) {
                        return { success: true, active: false, service: 'Kraken', message: data.error.join(', ') };
                    }
                    const balances = Object.entries(data.result || {}).filter(([_, v]) => parseFloat(v as string) > 0);
                    return {
                        success: true, active: true, service: 'Kraken',
                        message: 'API key is active',
                        balance: balances.length > 0 ? `${balances.length} assets with balance` : 'No balance'
                    };
                }
                return { success: true, active: false, service: 'Kraken', message: `API returned status ${result.status}` };
            }

            case 'kucoin': {
                if (!secretKey || !passphrase) {
                    return { success: false, active: false, service, message: 'Secret key and passphrase required for KuCoin', error: 'Missing credentials' };
                }
                const timestamp = Date.now().toString();
                const method = 'GET';
                const endpoint = '/api/v1/accounts';
                const strToSign = timestamp + method + endpoint;
                const signature = crypto.createHmac('sha256', secretKey).update(strToSign).digest('base64');
                const passphraseSign = crypto.createHmac('sha256', secretKey).update(passphrase).digest('base64');

                const result = await makeRequest({
                    hostname: 'api.kucoin.com',
                    path: endpoint,
                    method: 'GET',
                    headers: {
                        'KC-API-KEY': apiKey,
                        'KC-API-SIGN': signature,
                        'KC-API-TIMESTAMP': timestamp,
                        'KC-API-PASSPHRASE': passphraseSign,
                        'KC-API-KEY-VERSION': '2'
                    }
                });

                if (result.status === 200) {
                    const data = JSON.parse(result.data);
                    if (data.code === '200000') {
                        const accounts = data.data || [];
                        const withBalance = accounts.filter((a: any) => parseFloat(a.balance) > 0);
                        return {
                            success: true, active: true, service: 'KuCoin',
                            message: 'API key is active',
                            balance: withBalance.length > 0 ? `${withBalance.length} accounts with balance` : 'No balance'
                        };
                    }
                    return { success: true, active: false, service: 'KuCoin', message: data.msg || 'Invalid response' };
                }
                return { success: true, active: false, service: 'KuCoin', message: `API returned status ${result.status}` };
            }

            case 'bybit': {
                if (!secretKey) {
                    return { success: false, active: false, service, message: 'Secret key required for Bybit', error: 'Missing secret key' };
                }
                const timestamp = Date.now().toString();
                const recvWindow = '5000';
                const queryString = `api_key=${apiKey}&recv_window=${recvWindow}&timestamp=${timestamp}`;
                const signature = crypto.createHmac('sha256', secretKey).update(queryString).digest('hex');

                const result = await makeRequest({
                    hostname: 'api.bybit.com',
                    path: `/v5/account/wallet-balance?accountType=UNIFIED`,
                    method: 'GET',
                    headers: {
                        'X-BAPI-API-KEY': apiKey,
                        'X-BAPI-SIGN': signature,
                        'X-BAPI-TIMESTAMP': timestamp,
                        'X-BAPI-RECV-WINDOW': recvWindow
                    }
                });

                if (result.status === 200) {
                    const data = JSON.parse(result.data);
                    if (data.retCode === 0) {
                        return {
                            success: true, active: true, service: 'Bybit',
                            message: 'API key is active',
                            balance: data.result?.list?.[0]?.totalEquity || 'Unknown'
                        };
                    }
                    return { success: true, active: false, service: 'Bybit', message: data.retMsg || 'Invalid key' };
                }
                return { success: true, active: false, service: 'Bybit', message: `API returned status ${result.status}` };
            }

            case 'github': {
                const result = await makeRequest({
                    hostname: 'api.github.com',
                    path: '/user',
                    method: 'GET',
                    headers: {
                        'Authorization': `token ${apiKey}`,
                        'User-Agent': 'API-Tester',
                        'Accept': 'application/vnd.github.v3+json'
                    }
                });

                if (result.status === 200) {
                    const data = JSON.parse(result.data);
                    return {
                        success: true, active: true, service: 'GitHub',
                        message: 'Token is active',
                        accountInfo: { login: data.login, name: data.name, type: data.type }
                    };
                } else if (result.status === 401) {
                    return { success: true, active: false, service: 'GitHub', message: 'Invalid or expired token' };
                }
                return { success: true, active: false, service: 'GitHub', message: `API returned status ${result.status}` };
            }

            case 'stripe': {
                const auth = Buffer.from(`${apiKey}:`).toString('base64');
                const result = await makeRequest({
                    hostname: 'api.stripe.com',
                    path: '/v1/balance',
                    method: 'GET',
                    headers: { 'Authorization': `Basic ${auth}` }
                });

                if (result.status === 200) {
                    const data = JSON.parse(result.data);
                    return {
                        success: true, active: true, service: 'Stripe',
                        message: 'API key is active',
                        balance: data.available?.[0]?.amount ? `${data.available[0].amount / 100} ${data.available[0].currency}` : 'Unknown'
                    };
                }
                return { success: true, active: false, service: 'Stripe', message: `API returned status ${result.status}` };
            }

            case 'etherscan':
            case 'polygonscan':
            case 'bscscan':
            case 'arbiscan': {
                const hostMap: Record<string, string> = {
                    'etherscan': 'api.etherscan.io',
                    'polygonscan': 'api.polygonscan.com',
                    'bscscan': 'api.bscscan.com',
                    'arbiscan': 'api.arbiscan.io'
                };
                const hostname = hostMap[service.toLowerCase()] || 'api.etherscan.io';

                const result = await makeRequest({
                    hostname,
                    path: `/api?module=account&action=balance&address=0x0000000000000000000000000000000000000000&apikey=${apiKey}`,
                    method: 'GET'
                });

                if (result.status === 200) {
                    const data = JSON.parse(result.data);
                    if (data.status === '1' || data.message === 'OK') {
                        return { success: true, active: true, service: service, message: 'API key is active' };
                    }
                    return { success: true, active: false, service, message: data.message || 'Invalid key' };
                }
                return { success: true, active: false, service, message: `API returned status ${result.status}` };
            }

            default:
                return { success: false, active: false, service, message: `Unknown service: ${service}`, error: 'Unsupported service' };
        }
    } catch (e: any) {
        return { success: false, active: false, service, message: `Error: ${e.message}`, error: e.message };
    }
});

// ----------------------------------------------------------------------
// Window Management
// ----------------------------------------------------------------------

function createWindow() {
    // Icon path - use build/icon.ico if it exists, otherwise use a default
    const iconPath = app.isPackaged
        ? path.join(__dirname, '../build/icon.ico')
        : path.join(__dirname, '../build/icon.ico');

    const iconExists = fs.existsSync(iconPath);

    win = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#171717',
        icon: iconExists ? iconPath : undefined, // Only set icon if file exists
        show: false, // show only after content loads to avoid black flash
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            webSecurity: true,
        },
    })

    // Show window when page is ready (avoids black screen flash)
    let shown = false
    const showWin = () => {
        if (shown || !win) return
        shown = true
        win.show()
    }
    win.once('ready-to-show', showWin)
    // Fallback: show after 12s so user isn't stuck with a hidden window if load never "ready"
    setTimeout(showWin, 12000)

    // Test active push message to React
    win.webContents.on('did-finish-load', () => {
        if (!app.isPackaged) console.log('[Electron] Page did-finish-load')
        win?.webContents.send('main-process-message', (new Date).toLocaleString())
    })

    // Log load failures (helps debug black screen)
    win.webContents.on('did-fail-load', (_event, errorCode, errorDescription, validatedURL) => {
        console.error('[Electron] Load failed:', errorCode, errorDescription, validatedURL)
    })

    // In development, load from Vite dev server; in production, load built file
    if (!app.isPackaged) {
        const devUrl = process.env.VITE_DEV_SERVER_URL || 'http://localhost:5174'
        // Clear cache before load to avoid ERR_CACHE_READ_FAILURE (Electron cache + 304)
        win.webContents.session.clearCache().then(() => {
            win?.loadURL(devUrl).catch((err: unknown) => console.error('[Electron] loadURL failed:', err))
        })
    } else {
        win.loadFile(path.join(__dirname, '../dist/index.html'))
    }
}

app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit()
        win = null
    }
})

app.on('activate', () => {
    if (win === null) {
        createWindow()
    }
})


// ----------------------------------------------------------------------
// Web Scanner IPC Handlers
// ----------------------------------------------------------------------

ipcMain.removeHandler('web-scan-fetch');

ipcMain.handle('web-scan-fetch', async (_event, { url, options }) => {
    const { net, session } = require('electron');

    return new Promise(async (resolve, reject) => {
        try {
            // Determine session to use
            let requestSession = session.defaultSession;

            // If proxy is requested, use a dedicated partition to avoid global impact
            if (options?.proxy) {
                const proxyUrl = options.proxy.url; // e.g., "http://127.0.0.1:8080"

                // Parse proxy string to separate auth if provided in URL, though UI provides separate fields
                // UI provides: url, username, password.

                requestSession = session.fromPartition('scanner-proxy-' + Date.now());

                const proxyConfig: any = {
                    proxyRules: proxyUrl
                };

                await requestSession.setProxy(proxyConfig);

                // Handle Proxy Auth if username/password are provided
                // setProxy doesn't directly take auth, we need to handle the 'login' event
                if (options.proxy.username && options.proxy.password) {
                    // This is complex for a one-off request. 
                    // Alternate strategy: Embed auth in the proxy URL if it's HTTP basic
                    // http://user:pass@host:port
                    // But Electron often strips this.
                    // Proper way:
                    /*
                    requestSession.on('will-download', (event, item, webContents) => { ... })
                    // 'login' event is on app or webContents, slightly tricky for headless net.request
                    */
                }
            }

            const req = electronNet.request({
                method: options?.method || 'GET',
                url,
                session: requestSession,
                useSessionCookies: true
            });

            // Set Headers
            if (options?.headers) {
                for (const [key, value] of Object.entries(options.headers)) {
                    req.setHeader(key, value as string);
                }
            }

            // Set Body
            if (options?.body) {
                req.write(options.body);
            }

            const timeout = options?.timeout || 15000;
            const timeoutTimer = setTimeout(() => {
                req.abort();
                resolve({
                    success: false,
                    ok: false,
                    error: `Request timed out after ${timeout}ms`
                });
            }, timeout);

            req.on('response', (response: any) => {
                const chunks: any[] = [];

                response.on('data', (chunk: any) => {
                    chunks.push(chunk);
                });

                response.on('end', () => {
                    clearTimeout(timeoutTimer);
                    const body = Buffer.concat(chunks).toString();
                    const headers: Record<string, string> = {};
                    // Electron headers are strictly string[] | string. normalize.
                    for (const [k, v] of Object.entries(response.headers)) {
                        headers[k] = Array.isArray(v) ? (v as string[]).join(', ') : (v as string);
                    }

                    resolve({
                        success: true,
                        ok: response.statusCode >= 200 && response.statusCode < 300,
                        status: response.statusCode,
                        statusText: response.statusMessage,
                        headers,
                        body: body
                    });
                });

                response.on('error', (err: any) => {
                    clearTimeout(timeoutTimer);
                    resolve({ success: false, ok: false, error: err.message || 'Response error' });
                });
            });

            req.on('error', (err: any) => {
                clearTimeout(timeoutTimer);
                resolve({ success: false, ok: false, error: err.message || 'Request connection error' });
            });

            // Handle Login (Proxy Auth)
            // net.request usually emits 'login' event if auth is needed
            req.on('login', (authInfo: any, callback: any) => {
                if (options?.proxy?.username && options?.proxy?.password) {
                    callback(options.proxy.username, options.proxy.password);
                } else {
                    // Cancel auth if we don't have creds
                    // We can't really "cancel" easily here without context, providing empty might fail
                    callback('', '');
                }
            });

            req.end();

        } catch (error: any) {
            console.error('Web Scan Fetch Error:', error);
            resolve({
                success: false,
                ok: false,
                error: error.message || 'Internal scanner error'
            });
        }
    });
});

app.whenReady().then(createWindow)
