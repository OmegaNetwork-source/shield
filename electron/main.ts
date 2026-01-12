import { app, BrowserWindow, ipcMain, desktopCapturer, dialog } from 'electron'
import path from 'node:path'
import { exec } from 'node:child_process'
import fs from 'node:fs'

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

// 1. Run PowerShell Command
ipcMain.handle('run-command', async (event, command) => {
    return new Promise((resolve, reject) => {
        // SECURITY: strictly strictly strictly for prototype. 
        // In prod, use specific switch cases or signed scripts.
        exec(`powershell.exe -Command "${command}"`, (error, stdout, stderr) => {
            if (error) {
                resolve({ success: false, output: stderr || error.message })
            } else {
                resolve({ success: true, output: stdout })
            }
        })
    })
})


// 2. Save Evidence (structured data with optional screenshot)
ipcMain.handle('save-evidence', async (event, data: {
    ruleId: string;
    ruleTitle: string;
    command: string;
    output: string;
    status: string;
    captureScreenshot: boolean;
}) => {
    try {
        const evidenceDir = path.join(app.getPath('userData'), 'evidence')
        if (!fs.existsSync(evidenceDir)) {
            fs.mkdirSync(evidenceDir, { recursive: true })
        }

        const timestamp = new Date()
        const dateStr = timestamp.toISOString().replace(/[:.]/g, '-')
        const baseFilename = `${data.ruleId}_${dateStr}`

        let screenshotPath = null
        let screenshotUrl = null

        // Capture screenshot if requested
        if (data.captureScreenshot) {
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
            timestamp: timestamp.toISOString(),
            timestampReadable: timestamp.toLocaleString(),
            screenshotPath,
            screenshotUrl
        }

        const jsonFilename = `${baseFilename}.json`
        const jsonPath = path.join(evidenceDir, jsonFilename)
        fs.writeFileSync(jsonPath, JSON.stringify(evidenceData, null, 2))

        return { success: true, evidenceData, jsonPath }
    } catch (error: any) {
        return { success: false, error: error.message }
    }
})

// 3. Get All Evidence (reads JSON files)
ipcMain.handle('get-evidence', async () => {
    const evidenceDir = path.join(app.getPath('userData'), 'evidence')
    if (!fs.existsSync(evidenceDir)) return []

    const files = fs.readdirSync(evidenceDir).filter(f => f.endsWith('.json'))
    const evidenceItems = []

    for (const file of files) {
        try {
            const content = fs.readFileSync(path.join(evidenceDir, file), 'utf-8')
            const data = JSON.parse(content)
            evidenceItems.push(data)
        } catch (e) {
            // Skip malformed files
        }
    }

    // Sort by timestamp descending
    return evidenceItems.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
})

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
// Window Management
// ----------------------------------------------------------------------

function createWindow() {
    win = new BrowserWindow({
        width: 1200,
        height: 800,
        backgroundColor: '#020617',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
        },
    })

    // Test active push message to React
    win.webContents.on('did-finish-load', () => {
        win?.webContents.send('main-process-message', (new Date).toLocaleString())
    })

    // In development, normally we wouldn't see VITE_DEV_SERVER_URL without a plugin. 
    // We'll rely on app.isPackaged to determine dev mode.
    if (!app.isPackaged) {
        win.loadURL('http://localhost:5173')
        win.webContents.openDevTools()
    } else {
        // win.loadFile('dist/index.html')
        // Correct path for production build
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

app.whenReady().then(createWindow)
