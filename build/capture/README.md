# Bundled packet capture (optional)

To bundle packet capture with the app so users don't need to install it separately:

1. **Windows**: Download the [Wireshark Windows x64 Installer](https://www.wireshark.org/download.html) or the portable build, then copy `tshark.exe` from the install directory (e.g. `C:\Program Files\Wireshark\tshark.exe`) into this folder: `build/capture/tshark.exe`.
2. **macOS/Linux**: Copy the `tshark` binary (from your package manager or Wireshark build) into `build/capture/tshark` and ensure it is executable.

Then run `npm run build` (or your Electron packager). The binary will be copied into the app's resources and used for live packet capture.

Note: Npcap (Windows) or libpcap (macOS/Linux) may still be required for raw capture. The bundled binary is used when present; otherwise the app looks for the capture tool in the default install location or PATH.
