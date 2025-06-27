import sys
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis
import re

def analyze_apk(apk_path):
    """
    Performs a static analysis of an Android APK file to find malware attributes.
    """
    print(f"[*] Analyzing {apk_path}...")
    
    try:
        a = APK(apk_path)
        d = DalvikVMFormat(a.get_dex())
        dx = Analysis(d)
    except Exception as e:
        print(f"[!] Error processing APK file: {e}")
        return

    print("\n--- Manifest Analysis ---")
    
    # 1. Check for suspicious permissions
    print("[*] Checking Permissions...")
    dangerous_permissions = [
        "android.permission.SEND_SMS",
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_HISTORY_BOOKMARKS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.GET_ACCOUNTS",
        "android.permission.READ_PHONE_STATE",
    ]
    
    permissions = a.get_permissions()
    found_dangerous = False
    for perm in permissions:
        if perm in dangerous_permissions:
            print(f"  [!] Suspicious Permission Found: {perm}")
            found_dangerous = True
    
    if not found_dangerous:
        print("  [-] No obviously dangerous permissions found.")

    print(f"\n[*] Main Activity: {a.get_main_activity()}")
    print(f"[*] Target SDK Version: {a.get_target_sdk_version()}")

    print("\n--- Code Analysis (classes.dex) ---")

    # 2. Check for suspicious API calls
    print("[*] Searching for suspicious API calls...")
    suspicious_api_calls = {
        "Ljavax/crypto/Cipher;": "Cryptography (potential ransomware or data theft)",
        "Ldalvik/system/DexClassLoader;": "Dynamic Code Loading (can download and run new code)",
        "Ljava/lang/reflect/Method;": "Reflection (can be used for obfuscation and hiding behavior)",
        "Landroid/telephony/SmsManager;": "SMS Management (can send premium SMS)",
        "Ljava/net/HttpURLConnection;": "HTTP Connections (check for C&C communication)",
        "Landroid/location/LocationManager;": "Location Tracking"
    }
    
    found_suspicious_api = False
    for class_name in dx.get_classes():
        for api, reason in suspicious_api_calls.items():
            if api in class_name.get_name():
                print(f"  [!] Found API call related to {reason}: {class_name.get_name()}")
                found_suspicious_api = True

    if not found_suspicious_api:
        print("  [-] No common suspicious API calls found in class names.")

    # 3. Find URLs and IP addresses in the code
    print("\n[*] Searching for URLs and IP addresses...")
    # Regex for finding URLs
    url_pattern = re.compile(b'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
    # Regex for finding IP addresses
    ip_pattern = re.compile(b'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

    found_urls = False
    for s in d.get_strings():
        urls = url_pattern.findall(s)
        if urls:
            for url in urls:
                print(f"  [!] Found URL: {url.decode('utf-8', errors='ignore')}")
                found_urls = True
        
        ips = ip_pattern.findall(s)
        if ips:
            for ip in ips:
                # Avoid common private/local IPs
                if ip not in [b'0.0.0.0', b'127.0.0.1']:
                    print(f"  [!] Found IP Address: {ip.decode('utf-8', errors='ignore')}")
                    found_urls = True # Use the same flag

    if not found_urls:
        print("  [-] No URLs or IP addresses found in strings.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_apk.py <path_to_apk_file>")
        sys.exit(1)
    
    apk_file_path = sys.argv[1]
    analyze_apk(apk_file_path)
