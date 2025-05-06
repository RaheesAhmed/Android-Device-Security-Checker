# Android Health Check - Detailed Usage Guide

This guide provides detailed instructions on how to use the Android Health Check tool effectively.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Setup](#setup)
- [Running the Tool](#running-the-tool)
- [Understanding the Output](#understanding-the-output)
- [Interpreting Security Results](#interpreting-security-results)
- [Report Files](#report-files)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before using the Android Health Check tool, ensure you have:

1. **Python 3.6+** installed on your computer
2. **Android Debug Bridge (ADB)** installed
3. An **Android device** with USB debugging enabled
4. A **USB cable** to connect your device to the computer

## Setup

### Installing ADB

1. Download Android Platform Tools from [developer.android.com](https://developer.android.com/studio/releases/platform-tools)
2. Extract the downloaded ZIP file to a location on your computer
3. Add the extracted directory to your system PATH:
   - **Windows**: Edit environment variables and add the path to the Platform Tools directory
   - **macOS/Linux**: Add `export PATH=$PATH:/path/to/platform-tools` to your `.bash_profile` or `.zshrc`

### Enabling USB Debugging on Your Android Device

1. Go to **Settings** > **About phone**
2. Tap **Build number** 7 times until you see "You are now a developer!"
3. Go back to **Settings** > **System** > **Developer options**
4. Enable **USB debugging**
5. Connect your device to your computer
6. When prompted on your device, tap **Allow** to authorize the computer

## Running the Tool

1. Open a terminal or command prompt
2. Navigate to the directory containing `android_health_check.py`
3. Run the script:

```bash
python android_health_check.py
```

4. The tool will automatically:
   - Check for ADB installation
   - Connect to your device
   - Collect and analyze device information
   - Display results in the console
   - Save reports to files

## Understanding the Output

The tool's output is organized into several color-coded sections:

### Device Information

- **ADB Connection**: Shows connected devices
- **CPU Usage**: Displays top processes using CPU
- **Memory Info**: Shows memory usage statistics
- **Installed Apps**: Lists a sample of installed applications
- **Battery Stats**: Shows battery status and health
- **Network Stats**: Displays network usage information
- **Running Services**: Lists active services on the device

### Security Analysis

- **Root Status**: Indicates if the device is rooted
- **Process Analysis**: Identifies suspicious processes
- **Network Analysis**: Checks for suspicious connections
- **VPN Applications**: Lists any VPN apps installed
- **Permission Analysis**: Checks for apps with dangerous permissions
- **Security Summary**: Provides an overview of security concerns

## Interpreting Security Results

### Root Detection

- **Green** output indicates no root detected (more secure)
- **Yellow/Red** output indicates the device is rooted (potential security risk)

### Suspicious Processes

The tool flags processes that match suspicious keywords. Not all flagged processes are malicious - review them carefully.

Common false positives:
- System processes with unusual names
- Manufacturer-specific services
- Development or debugging tools

### Suspicious Apps

Apps are flagged based on keywords in their package names. Review flagged apps to determine if they are legitimate.

### Dangerous Permissions

The tool checks for apps with permissions that could potentially compromise privacy or security:
- SMS read/send permissions
- Call log access
- Location tracking
- Camera/microphone access

## Report Files

The tool generates two files:

1. **android_health_report_[timestamp].txt**:
   - Complete health and security report
   - Includes all information displayed in the console
   - Organized by sections for easy reference

2. **installed_apps.txt**:
   - Complete list of all installed applications
   - Package names of all apps on the device
   - Useful for auditing installed software

## Advanced Usage

### Customizing the Tool

You can modify the script to customize its behavior:

- Edit the `SUSPICIOUS_KEYWORDS` list to change what's flagged as suspicious
- Modify the `COMMON_SYSTEM_APPS` list to reduce false positives
- Add additional security checks by extending the script

### Automating Health Checks

You can schedule regular health checks using:
- Windows Task Scheduler
- Cron jobs on Linux/macOS
- Batch scripts that run the tool and archive reports

## Troubleshooting

### ADB Connection Issues

If the tool cannot connect to your device:

1. Ensure USB debugging is enabled
2. Try disconnecting and reconnecting the device
3. Check if the device appears when running `adb devices` manually
4. Try restarting ADB with `adb kill-server` followed by `adb start-server`
5. Try a different USB cable or port

### Permission Denied Errors

If you see permission errors:

1. Check if you've authorized the computer on your device
2. Try running the tool with administrator/root privileges
3. Check USB debugging is still enabled (it can be disabled automatically after updates)

### ADB Not Found

If ADB is not found:

1. Enter the full path to ADB when prompted
2. Ensure ADB is correctly added to your PATH
3. Restart your terminal/command prompt after updating PATH

---

For additional help or to report issues, please open an issue on the repository.
