import { app, BrowserWindow, ipcMain, desktopCapturer, dialog } from 'electron'
import path from 'node:path'
import { spawn } from 'node:child_process';
import fs from 'node:fs'
import os from 'node:os'

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
        win.loadURL('http://localhost:5174')
        // Dev tools disabled - uncomment to enable during development
        // win.webContents.openDevTools()
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
