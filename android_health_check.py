import subprocess
import os
import sys
import time
from datetime import datetime

# ANSI color codes for colorful console output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    """Print a formatted header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{text.center(60)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")

def print_section(text):
    """Print a section header"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}[*] {text}{Colors.ENDC}")

def print_success(text):
    """Print a success message"""
    print(f"{Colors.GREEN}[+] {text}{Colors.ENDC}")

def print_warning(text):
    """Print a warning message"""
    print(f"{Colors.WARNING}[!] {text}{Colors.ENDC}")

def print_error(text):
    """Print an error message"""
    print(f"{Colors.RED}[-] {text}{Colors.ENDC}")

def print_info(text):
    """Print an info message"""
    print(f"{Colors.CYAN}[*] {text}{Colors.ENDC}")

def print_data(text):
    """Print data output"""
    print(f"{Colors.ENDC}{text}{Colors.ENDC}")

def print_progress(current, total, prefix='Progress:', suffix='Complete', bar_length=50):
    """Print a progress bar"""
    filled_length = int(round(bar_length * current / float(total)))
    percents = round(100.0 * current / float(total), 1)
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    sys.stdout.write(f'\r{Colors.CYAN}{prefix} {Colors.GREEN}{bar} {percents}% {Colors.CYAN}{suffix}{Colors.ENDC}')
    sys.stdout.flush()
    if current == total:
        print()

# Path to ADB executable - update this to your ADB location
ADB_PATH = "adb"  # Default to just "adb" if in PATH

# Try to find ADB in common locations
if sys.platform == "win32":
    common_locations = [
        os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk", "platform-tools", "adb.exe"),
        os.path.join(os.environ.get("PROGRAMFILES", ""), "Android", "android-sdk", "platform-tools", "adb.exe"),
        os.path.join(os.environ.get("PROGRAMFILES(X86)", ""), "Android", "android-sdk", "platform-tools", "adb.exe"),
        # Add your custom path here if needed
    ]

    for location in common_locations:
        if os.path.exists(location):
            ADB_PATH = location
            break

def run_adb_command(cmd, ignore_errors=False):
    try:
        result = subprocess.run([ADB_PATH] + cmd.split(), capture_output=True, text=True)
        if result.returncode != 0 and not ignore_errors:
            error_msg = result.stderr.strip()
            print(f"Error executing ADB command: {error_msg}")
            if "java.lang.SecurityException" in error_msg:
                print("This appears to be a permission issue. Try running as a different user or with elevated privileges.")
            return f"Error: {error_msg}"
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"[-] Error: ADB executable not found at '{ADB_PATH}'")
        print("Please install Android SDK Platform Tools or update the ADB_PATH in the script.")
        sys.exit(1)

# List of potentially suspicious app keywords
SUSPICIOUS_KEYWORDS = [
    "spy", "track", "monitor", "keylog", "hack", "crack", "steal",
    "trojan", "malware", "virus", "backdoor", "exploit", "inject",
    "phish", "fraud", "fake", "hidden", "secret", "surveillance"
]

# List of common system apps that are safe
COMMON_SYSTEM_APPS = [
    "com.google.", "com.android.", "com.samsung.", "com.sec.",
    "com.facebook.", "com.whatsapp", "com.instagram", "com.twitter",
    "com.linkedin", "com.spotify", "com.netflix", "com.amazon"
]

def get_installed_apps():
    """Try different methods to get installed apps"""
    # Try multiple methods to get installed apps
    methods = [
        "shell pm list packages",
        "shell cmd package list packages",
        "shell ls -la /data/app",
        "shell ls -la /system/app",
        "shell dumpsys package | grep 'Package \\[' | cut -d '[' -f 2 | cut -d ']' -f 1"
    ]

    all_apps = []

    for method in methods:
        result = run_adb_command(method, ignore_errors=True)
        if not result.startswith("Error:") and result.strip():
            # Process the output based on the method
            if "package:" in result:
                # For pm list packages and cmd package list packages
                apps = [line.replace("package:", "").strip() for line in result.splitlines() if line.strip()]
                all_apps.extend(apps)
            elif "/data/app" in method or "/system/app" in method:
                # For directory listings, extract app names
                for line in result.splitlines():
                    if ".apk" in line or "base.apk" in line:
                        parts = line.split()
                        if len(parts) >= 8:  # Standard ls -la output format
                            app_name = parts[-1]
                            if app_name not in all_apps:
                                all_apps.append(app_name)
            else:
                # For dumpsys output
                apps = [line.strip() for line in result.splitlines() if line.strip()]
                all_apps.extend(apps)

    # Remove duplicates and sort
    all_apps = sorted(list(set(all_apps)))

    if not all_apps:
        # If all methods fail, try a more direct approach
        print("[-] Standard methods failed, trying direct file system access...")
        result = run_adb_command("shell find /data/app -name base.apk | sort", ignore_errors=True)
        if not result.startswith("Error:") and result.strip():
            all_apps = [line.split("/")[-3] for line in result.splitlines() if line.strip()]

    if not all_apps:
        return "Failed to retrieve installed apps. This may be due to permission restrictions."

    return "\n".join(all_apps)

def analyze_apps_for_security(apps_list):
    """Analyze installed apps for potential security issues"""
    if not apps_list or len(apps_list.strip()) == 0:
        return "No apps data available for analysis."

    app_lines = apps_list.splitlines()
    suspicious_apps = []

    for app in app_lines:
        app = app.strip()
        if not app:
            continue

        # Check if app matches any suspicious keywords
        is_suspicious = False
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in app.lower():
                # Check if it's a common system app (which would be a false positive)
                is_common_system_app = False
                for safe_app in COMMON_SYSTEM_APPS:
                    if app.startswith(safe_app):
                        is_common_system_app = True
                        break

                if not is_common_system_app:
                    is_suspicious = True
                    break

        if is_suspicious:
            suspicious_apps.append(app)

    result = []
    if suspicious_apps:
        result.append(f"[!] Found {len(suspicious_apps)} potentially suspicious apps:")
        for app in suspicious_apps:
            result.append(f"    - {app}")
    else:
        result.append("[+] No obviously suspicious apps detected.")

    return "\n".join(result)

def get_running_processes():
    """Get list of running processes"""
    return run_adb_command("shell ps -A")

def analyze_running_processes():
    """Analyze running processes for suspicious activity"""
    processes = get_running_processes()
    if not processes or processes.startswith("Error"):
        return "Could not retrieve process information."

    process_lines = processes.splitlines()
    suspicious_processes = []

    # Skip header line
    if len(process_lines) > 0:
        process_lines = process_lines[1:]

    for process in process_lines:
        parts = process.split()
        if len(parts) < 8:
            continue

        # The last part is usually the process name
        process_name = parts[-1]

        # Check if process matches any suspicious keywords
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword.lower() in process_name.lower():
                # Check if it's a common system process
                is_common_system_app = False
                for safe_app in COMMON_SYSTEM_APPS:
                    if process_name.startswith(safe_app):
                        is_common_system_app = True
                        break

                if not is_common_system_app:
                    suspicious_processes.append(process)
                    break

    result = []
    if suspicious_processes:
        result.append(f"[!] Found {len(suspicious_processes)} potentially suspicious processes:")
        for process in suspicious_processes[:10]:  # Limit to first 10 for readability
            result.append(f"    - {process}")
        if len(suspicious_processes) > 10:
            result.append(f"    ... and {len(suspicious_processes) - 10} more")
    else:
        result.append("[+] No obviously suspicious processes detected.")

    return "\n".join(result)

def check_network_connections():
    """Check for suspicious network connections"""
    # Get network stats
    netstat = run_adb_command("shell netstat", ignore_errors=True)
    if netstat.startswith("Error"):
        # Try alternative command
        netstat = run_adb_command("shell cat /proc/net/tcp", ignore_errors=True)
        if netstat.startswith("Error"):
            return "Could not retrieve network connection information."

    # Look for suspicious connections
    suspicious_connections = []
    known_safe_ports = [80, 443, 8080, 8443]  # HTTP, HTTPS, alternate HTTP/HTTPS

    for line in netstat.splitlines():
        # Very basic check for non-standard ports in established connections
        if "ESTABLISHED" in line:
            parts = line.split()
            if len(parts) >= 6:
                remote_addr = parts[5]
                if ":" in remote_addr:
                    try:
                        port = int(remote_addr.split(":")[-1])
                        if port not in known_safe_ports and port < 1024:
                            suspicious_connections.append(line)
                    except ValueError:
                        pass

    result = []
    if suspicious_connections:
        result.append(f"[!] Found {len(suspicious_connections)} potentially suspicious network connections:")
        for conn in suspicious_connections[:5]:  # Limit to first 5 for readability
            result.append(f"    - {conn}")
        if len(suspicious_connections) > 5:
            result.append(f"    ... and {len(suspicious_connections) - 5} more")
    else:
        result.append("[+] No obviously suspicious network connections detected.")

    return "\n".join(result)

def check_root_status():
    """Check if the device is rooted"""
    # Check for su binary
    su_check = run_adb_command("shell which su", ignore_errors=True)
    if not su_check.startswith("Error") and len(su_check.strip()) > 0:
        return "[!] Device appears to be rooted (su binary found)"

    # Check for common root apps
    root_apps = ["com.noshufou.android.su", "com.koushikdutta.superuser",
                "eu.chainfire.supersu", "com.topjohnwu.magisk"]

    for app in root_apps:
        check = run_adb_command(f"shell pm list packages {app}", ignore_errors=True)
        if not check.startswith("Error") and app in check:
            return f"[!] Device appears to be rooted (root app found: {app})"

    return "[+] No evidence of root detected"

def main():
    # Create a list to store all report sections
    report_sections = []

    try:
        # Display welcome banner
        print_header("ANDROID DEVICE HEALTH & SECURITY CHECK")
        print(f"\n{Colors.CYAN}Starting scan at: {Colors.GREEN}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.ENDC}")

        # Show a small animation to indicate the tool is starting
        for i in range(10):
            print_progress(i+1, 10, prefix='Initializing:', suffix='')
            time.sleep(0.1)

        print_section("Checking ADB connection")
        devices = run_adb_command("devices")
        print_data(devices)
        report_sections.append(f"ADB DEVICES:\n{devices}\n")

        if "device" not in devices:
            print_error("No device detected. Please connect your phone with USB debugging enabled.")
            print(f"{Colors.RED}    Make sure:{Colors.ENDC}")
            print(f"{Colors.RED}    1. USB debugging is enabled in Developer options{Colors.ENDC}")
            print(f"{Colors.RED}    2. Your phone is connected via USB{Colors.ENDC}")
            print(f"{Colors.RED}    3. You've authorized the computer on your phone if prompted{Colors.ENDC}")
            return

        print_section("Fetching CPU Usage")
        cpu_usage = run_adb_command("shell top -n 1 -m 10")
        print_data(cpu_usage)
        report_sections.append(f"CPU USAGE:\n{cpu_usage}\n")

        print_section("Fetching Memory Info")
        # Try different methods to get memory info
        print_info("Trying multiple methods to get memory information...")
        memory_info = run_adb_command("shell cat /proc/meminfo", ignore_errors=True)
        if memory_info.startswith("Error:"):
            memory_info = run_adb_command("shell free", ignore_errors=True)
            if memory_info.startswith("Error:"):
                memory_info = run_adb_command("shell dumpsys meminfo", ignore_errors=True)

        print_data(memory_info)
        report_sections.append(f"MEMORY INFO:\n{memory_info}\n")

        print_section("Fetching Installed Apps")
        print_info("This may take a moment...")

        # Show progress animation
        for i in range(5):
            print_progress(i+1, 5, prefix='Scanning apps:', suffix='')
            time.sleep(0.3)

        apps = get_installed_apps()
        app_lines = apps.splitlines() if "\n" in apps else [apps]
        app_count = len(app_lines) if app_lines and app_lines[0] else 0

        if app_count > 0:
            print_success(f"Retrieved {app_count} apps")
        else:
            print_error("Could not retrieve apps list")

        # Save all apps to file
        with open("installed_apps.txt", "w", encoding="utf-8") as f:
            f.write(apps)
        print_success(f"Installed apps saved to {Colors.UNDERLINE}installed_apps.txt{Colors.ENDC}{Colors.GREEN}")

        # Display first 20 apps in console
        if app_count > 0:
            print(f"\n{Colors.CYAN}Sample of installed apps:{Colors.ENDC}")
            for i, app in enumerate(app_lines[:20]):
                if app.strip():
                    print(f"  {Colors.CYAN}{i+1}.{Colors.ENDC} {app.strip()}")
            if app_count > 20:
                print(f"  {Colors.CYAN}... and {app_count - 20} more (see installed_apps.txt for complete list){Colors.ENDC}")

        # Security analysis of apps
        print_section("Analyzing apps for security concerns")
        security_analysis = analyze_apps_for_security(apps)
        print_data(security_analysis)

        # Add to report
        report_sections.append(f"INSTALLED APPS: (Total: {app_count}, saved to installed_apps.txt)\n")
        report_sections.append(f"SECURITY ANALYSIS:\n{security_analysis}\n")

        print_section("Fetching Battery Stats")
        battery_stats = run_adb_command("shell dumpsys battery")
        print_data(battery_stats)
        report_sections.append(f"BATTERY STATS:\n{battery_stats}\n")

        print_section("Fetching Network Stats")
        network_stats = run_adb_command("shell dumpsys netstats | head -n 10")
        print_data(network_stats)
        report_sections.append(f"NETWORK STATS:\n{network_stats}\n")

        print_section("Fetching Running Services")
        running_services = run_adb_command("shell dumpsys activity services | grep ServiceRecord")
        print_data(running_services)
        report_sections.append(f"RUNNING SERVICES:\n{running_services}\n")

        # SECURITY ANALYSIS SECTION
        print_header("SECURITY ANALYSIS")

        # Check for root
        print_section("Checking if device is rooted")
        root_status = check_root_status()
        if "[!]" in root_status:
            print_warning(root_status.replace("[!] ", ""))
        else:
            print_success(root_status.replace("[+] ", ""))
        report_sections.append(f"ROOT STATUS:\n{root_status}\n")

        # Check running processes
        print_section("Analyzing running processes for suspicious activity")
        process_analysis = analyze_running_processes()
        if "[!]" in process_analysis:
            print_warning(process_analysis.replace("[!] ", ""))
            for line in process_analysis.splitlines()[1:]:
                if line.strip():
                    print(f"{Colors.WARNING}    {line.strip()}{Colors.ENDC}")
        else:
            print_success(process_analysis.replace("[+] ", ""))
        report_sections.append(f"PROCESS ANALYSIS:\n{process_analysis}\n")

        # Check network connections
        print_section("Checking for suspicious network connections")
        network_analysis = check_network_connections()
        if "[!]" in network_analysis:
            print_warning(network_analysis.replace("[!] ", ""))
            for line in network_analysis.splitlines()[1:]:
                if line.strip():
                    print(f"{Colors.WARNING}    {line.strip()}{Colors.ENDC}")
        else:
            print_success(network_analysis.replace("[+] ", ""))
        report_sections.append(f"NETWORK ANALYSIS:\n{network_analysis}\n")

        # Check for VPN apps
        print_section("Checking for VPN applications")
        vpn_check = run_adb_command("shell pm list packages | grep -i vpn", ignore_errors=True)
        if vpn_check and not vpn_check.startswith("Error") and len(vpn_check.strip()) > 0:
            vpn_apps = vpn_check.replace("package:", "").splitlines()
            vpn_result = f"[!] Found {len(vpn_apps)} VPN applications:\n"
            print_warning(f"Found {len(vpn_apps)} VPN applications:")
            for app in vpn_apps:
                vpn_result += f"    - {app.strip()}\n"
                print(f"{Colors.WARNING}    - {app.strip()}{Colors.ENDC}")
        else:
            vpn_result = "[+] No VPN applications detected."
            print_success("No VPN applications detected")
        report_sections.append(f"VPN APPLICATIONS:\n{vpn_result}\n")

        # Check for suspicious permissions
        print_section("Checking for apps with dangerous permissions")
        dangerous_permissions = [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS"
        ]

        # Show progress animation for permissions check
        for i, perm in enumerate(dangerous_permissions):
            print_progress(i+1, len(dangerous_permissions), prefix='Checking permissions:', suffix=perm.split('.')[-1])
            time.sleep(0.2)
        print()

        permission_results = []
        for perm in dangerous_permissions:
            perm_check = run_adb_command(f"shell pm list packages -g -p {perm}", ignore_errors=True)
            if perm_check and not perm_check.startswith("Error") and "package:" in perm_check:
                apps = perm_check.replace("package:", "").splitlines()
                if apps and len(apps) > 0 and apps[0].strip():
                    permission_results.append(f"Apps with {perm}:")
                    for app in apps[:5]:  # Limit to 5 apps per permission
                        permission_results.append(f"    - {app.strip()}")
                    if len(apps) > 5:
                        permission_results.append(f"    ... and {len(apps) - 5} more")

        if permission_results:
            perm_result = "\n".join(permission_results)
            print_warning("Found apps with potentially dangerous permissions:")
            for line in permission_results:
                if line.startswith("Apps with"):
                    print(f"\n{Colors.WARNING}{line}{Colors.ENDC}")
                else:
                    print(f"{Colors.WARNING}{line}{Colors.ENDC}")
        else:
            perm_result = "[+] No apps with dangerous permissions detected."
            print_success("No apps with dangerous permissions detected")

        report_sections.append(f"PERMISSION ANALYSIS:\n{perm_result}\n")

        # Security summary
        print_header("SECURITY CONCERNS SUMMARY")
        security_summary = []
        if "[!]" in root_status:
            security_summary.append("- Device is rooted, which can be a security risk")
        if "[!]" in process_analysis:
            security_summary.append("- Suspicious processes detected")
        if "[!]" in network_analysis:
            security_summary.append("- Suspicious network connections detected")
        if "[!]" in vpn_result:
            security_summary.append("- VPN applications found (may be legitimate but worth noting)")
        if "[!]" in security_analysis:
            security_summary.append("- Suspicious applications detected")

        if security_summary:
            for item in security_summary:
                print_warning(item)
            report_sections.append("SECURITY CONCERNS SUMMARY:\n" + "\n".join(security_summary) + "\n")
        else:
            print_success("No major security concerns detected")
            report_sections.append("SECURITY CONCERNS SUMMARY:\n[+] No major security concerns detected.\n")

        # Save the full report
        print_header("GENERATING REPORT")
        print_info("Creating comprehensive device health and security report...")

        # Show progress animation for report generation
        for i in range(10):
            print_progress(i+1, 10, prefix='Generating report:', suffix='')
            time.sleep(0.1)
        print()

        timestamp = subprocess.run(["powershell", "Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'"],
                                  capture_output=True, text=True).stdout.strip()
        report_filename = f"android_health_report_{timestamp}.txt"

        with open(report_filename, "w", encoding="utf-8") as f:
            f.write("ANDROID DEVICE HEALTH AND SECURITY REPORT\n")
            f.write(f"Generated: {timestamp}\n")
            f.write("=" * 50 + "\n\n")
            f.write("\n\n".join(report_sections))

        print_success(f"Full report saved to {Colors.UNDERLINE}{report_filename}{Colors.ENDC}{Colors.GREEN}")

        print_header("SCAN COMPLETE")
        print(f"\n{Colors.GREEN}{Colors.BOLD}Thank you for using Android Health Check!{Colors.ENDC}")
        print(f"{Colors.CYAN}If you found this tool useful, please consider sharing it with others.{Colors.ENDC}")
        print(f"{Colors.CYAN}For any issues or suggestions, please contact raheesahmed256@gmail.com.{Colors.ENDC}")
    except Exception as e:
        print_error(f"An error occurred: {str(e)}")
        print(f"{Colors.RED}    Please check your device connection and try again.{Colors.ENDC}")

def set_adb_path():
    """Allow user to manually set the ADB path if automatic detection fails"""
    print_header("ADB PATH CONFIGURATION")
    print_error("ADB executable not found in common locations")
    print(f"\n{Colors.CYAN}Please enter the full path to adb.exe (e.g., C:\\Android\\platform-tools\\adb.exe):{Colors.ENDC}")
    custom_path = input(f"{Colors.GREEN}> {Colors.ENDC}").strip()

    if os.path.exists(custom_path):
        global ADB_PATH
        ADB_PATH = custom_path
        print_success(f"ADB path set to: {Colors.UNDERLINE}{ADB_PATH}{Colors.ENDC}{Colors.GREEN}")
        return True
    else:
        print_error(f"File not found at {custom_path}")
        print(f"{Colors.RED}Please make sure you entered the correct path and try again.{Colors.ENDC}")
        return False

if __name__ == "__main__":
    # Display welcome banner
    print("\n")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'ANDROID DEVICE HEALTH & SECURITY CHECK'.center(60)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'v1.0.0'.center(60)}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 60}{Colors.ENDC}")
    print(f"\n{Colors.CYAN}This tool performs a comprehensive health and security check on your Android device.{Colors.ENDC}")
    print(f"{Colors.CYAN}It analyzes system performance, installed apps, and potential security issues.{Colors.ENDC}")
    print(f"{Colors.CYAN}Results will be displayed in the console and saved to a report file.{Colors.ENDC}\n")

    # Check if ADB is accessible
    print_info("Checking ADB installation...")
    try:
        subprocess.run([ADB_PATH, "version"], capture_output=True, text=True)
        print_success("ADB found and accessible")
    except FileNotFoundError:
        print_error(f"ADB not found at {ADB_PATH}")
        if not set_adb_path():
            print_error("Please install Android SDK Platform Tools and try again")
            print(f"{Colors.RED}You can download it from: {Colors.UNDERLINE}https://developer.android.com/studio/releases/platform-tools{Colors.ENDC}")
            sys.exit(1)

    # Start the main process
    print_info("Starting Android device health check...")
    main()
