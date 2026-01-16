# Desktop Icon Setup

To add a desktop icon for STIG Ops:

1. Create or obtain an icon file named `icon.ico` (Windows ICO format)
2. Place it in this `build/` directory
3. The icon should be at least 256x256 pixels for best quality
4. Common sizes included in ICO files: 16x16, 32x32, 48x48, 256x256

The application is configured to use `build/icon.ico` for:
- Desktop shortcut icon
- Window icon
- Installer icon
- Uninstaller icon

If the icon file doesn't exist, the app will still work but use the default Electron icon.
