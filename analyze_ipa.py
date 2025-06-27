import os
import sys
import zipfile
import subprocess
import tempfile
import shutil
import plistlib

def run_cmd(cmd):
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL)
        return output.decode()
    except subprocess.CalledProcessError:
        return ""

def extract_ipa(ipa_path, extract_to):
    with zipfile.ZipFile(ipa_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

def find_app_dir(payload_path):
    for f in os.listdir(payload_path):
        if f.endswith(".app"):
            return os.path.join(payload_path, f)
    return None

def analyze_info_plist(plist_path):
    print("\n--- Info.plist Analysis ---")
    with open(plist_path, 'rb') as f:
        plist = plistlib.load(f)
    for key in ["CFBundleIdentifier", "CFBundleName", "UIBackgroundModes", "NSCameraUsageDescription", "NSLocationWhenInUseUsageDescription"]:
        if key in plist:
            print(f"[*] {key}: {plist[key]}")

def analyze_binary(binary_path):
    print("\n--- Mach-O Binary Analysis ---")

    print("[*] Linked Dynamic Libraries:")
    libs = run_cmd(["otool", "-L", binary_path])
    for line in libs.splitlines()[1:]:  # Skip the binary path
        print("  " + line.strip())

    print("\n[*] Searching for suspicious symbols:")
    suspicious_keywords = ["_dlopen", "_system", "_strcpy", "_fork", "_exec", "http:", "https:"]
    symbols = run_cmd(["otool", "-Iv", binary_path])
    found = False
    for line in symbols.splitlines():
        if any(k in line for k in suspicious_keywords):
            print(f"  [!] Suspicious Symbol: {line.strip()}")
            found = True
    if not found:
        print("  [-] No suspicious symbols found.")

def analyze_ipa(ipa_path):
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"[*] Extracting {ipa_path}...")
        extract_ipa(ipa_path, tmpdir)

        payload_path = os.path.join(tmpdir, "Payload")
        app_dir = find_app_dir(payload_path)

        if not app_dir:
            print("[!] .app directory not found in IPA.")
            return

        plist_path = os.path.join(app_dir, "Info.plist")
        if os.path.exists(plist_path):
            analyze_info_plist(plist_path)
        else:
            print("[!] Info.plist not found.")

        print(f"[*] Scanning binary in: {app_dir}")
        for fname in os.listdir(app_dir):
            fpath = os.path.join(app_dir, fname)
            if os.access(fpath, os.X_OK) and not os.path.isdir(fpath):
                analyze_binary(fpath)
                break
        else:
            print("[!] No executable binary found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyze_ipa.py <path_to_ipa>")
        sys.exit(1)

    ipa_file = sys.argv[1]
    analyze_ipa(ipa_file)
