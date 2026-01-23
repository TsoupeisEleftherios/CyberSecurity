#!/usr/bin/env python3
import re
import hashlib
import math
import time
from collections import Counter
import os
import requests
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from rich.table import Table

# ---------------- Configuration / IOCs ----------------

VT_API_KEY = "fc3ad81934df44228c8f5c3fec235a3bac1a3f4ab4c38340da9c2d21873ea1f0"  # <-- Put your VirusTotal API key here

SUSPICIOUS_APIS = [
    # Registry Manipulation
    "RegCreateKeyEx", "RegSetValueEx", "RegDeleteKey", "RegDeleteValue",
    "RegOpenKeyEx", "RegQueryValueEx",

    # Process & Thread Injection / Manipulation
    "NtQueueApcThread", "CreateRemoteThread", "WriteProcessMemory",
    "VirtualAllocEx", "OpenProcess", "OpenThread", "QueueUserAPC", "SetWindowsHookEx",

    # Service Control
    "CreateService", "OpenService", "StartService", "ControlService", "DeleteService",

    # Network / HTTP APIs
    "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",

    # Debugging / Anti-Debug
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "AdjustTokenPrivileges", "LookupPrivilegeValue",

    # Token Manipulation / Privilege Escalation
    "OpenProcessToken", "DuplicateTokenEx", "ImpersonateLoggedOnUser", "SetTokenInformation",

    # File Manipulation
    "CreateFile", "DeleteFile", "WriteFile", "ReadFile", "MoveFile", "CopyFile",

    # Process Creation
    "CreateProcess", "CreateProcessAsUser", "ShellExecute", "ShellExecuteEx",

    # Threading & Synchronization
    "WaitForSingleObject", "WaitForMultipleObjects",

    # Anti-VM or Sandbox Evasion
    "GetTickCount", "QueryPerformanceCounter", "GetSystemTime", "GetSystemTimeAsFileTime"
]

SUSPICIOUS_REGISTRY_KEYS = [
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
    r"System\\CurrentControlSet\\Services",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run32",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\StartupFolder",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\ScheduledTask",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
    r"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
    r"AppInit_DLLs",
    r"Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    r"Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    r"Services\\EventLog",
    r"Software\\Policies\\Microsoft\\Windows Defender",
    r"Software\\Microsoft\\Windows Defender\\Real-Time Protection",
    r"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
]

SUSPICIOUS_MUTEX_PATTERNS = [
    r"Global\\\w+Mutex",
    r".*\bMutex\b.*",
    r".*\bLock\b.*",
    r".*\bEvent\b.*",
    r".*\bShutdownEvent\b.*",
    r".*\bSingletonMutex\b.*",
    r".*\bInjectionMutex\b.*",
    r".*\bCryptoLockerMutex\b.*",
    r".*\bRansomwareMutex\b.*",
    r".*\bDebugMutex\b.*",
    r".*\bUpdaterMutex\b.*",
    r".*\bExploitMutex\b.*",
]

IPV4_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
DOMAIN_REGEX = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b"

COMMON_MALICIOUS_FILENAMES = set([
    "setup.exe", "update.exe", "patch.exe", "installer.exe", "keygen.exe", "crack.exe",
    "payload.exe", "backdoor.exe", "trojan.exe", "ransomware.exe", "botnet.exe",
    "exploit.exe", "injector.exe", "loader.exe", "dropper.exe", "minerd.exe",
    "coinminer.exe", "spyware.exe", "adware.exe", "virus.exe", "worm.exe",
    "fakeav.exe", "hacktool.exe", "remoteaccess.exe", "screenlogger.exe",
    "dataexfiltrator.exe", "rootkit.exe", "bot.exe", "ddos.exe",
    "svchost.exe", "svhost.exe", "winupdate.exe", "systemupdate.exe", "svch0st.exe",
    "avp.exe", "msiexec.exe", "cryptonight.exe", "payload.bin", "update.bin",
    "autorun.exe", "security.exe", "netsvcs.exe", "msdtc.exe", "taskhost.exe",
    "explorer.exe", "dllhost.exe", "spoolsv.exe", "wscript.exe", "cscript.exe",
    "iexplore.exe", "firefox.exe", "chrome.exe", "opera.exe",
])

SUSPICIOUS_BYTE_PATTERNS = [
    b"\x90\x90\x90\x90",
    re.compile(rb"\x68....\xC3", re.DOTALL),
    b"\xFC\xE8",
    b"\xE8\x00\x00\x00\x00",
    b"\xCC\xCC\xCC\xCC",
    b"\xEB\xFE",
    b"\x60\x89\xE5",
    b"\x31\xC0\x50\x68",
    re.compile(rb"\x6A\x00\x68....\x64\xA1", re.DOTALL),
]

# *** ADDED: Known malicious threat actor domain names list ***
KNOWN_MALICIOUS_DOMAINS = set([
    "apt29.net", "apt28.com", "darkhotel.com", "fancybear.net", "cozyduke.net",
    "silencegroup.org", "gamaredon.net", "carbanak.net", "fin7.com", "lazarusgroup.net",
    "oilrig.net", "odingroup.net", "cobaltgroup.net", "apt33.com", "charmingkitten.com",
    "molerats.com", "turla.org", "scarletmimic.com", "ke3chang.net", "gamaredon.org",
    "menupass.com", "tropictrooper.com", "apt41.com", "silentlibrarian.com", "darkhydrus.com",
    "havex.net", "cryptolocker.net", "locky-ransomware.com", "ryuk-ransomware.net",
    "wannacry.com", "cerber-ransomware.net", "petya-ransomware.com", "badrabbit.net",
    "sodinokibi.com", "conti-ransomware.net", "evilnum.net", "carbanak.org", "finspy.com",
    "ghostnet.net", "komplex.org", "magicpowers.com", "blackenergy.net", "snowmanattack.com",
    "apt10.net", "apt12.com", "apt34.net", "apt35.com", "apt36.com", "apt37.com",
    "apt38.net", "apt39.net", "apt40.com", "apt41.net", "apt42.net", "turla.net",
    "equationgroup.net", "scarletmimic.net", "cloudatlas.net", "charmingkitten.net",
    "darkhotel.net", "gamaredon.com", "ke3chang.com", "molerats.net", "menupass.net",
    "oilrig.com", "odingroup.com", "scarletmimic.org", "silentlibrarian.net", "turla.com",
    "winnti.net", "w0rm.net", "zebrocy.net", "zeustracker.com", "dridex.net",
    "trickbot.net", "emotet.net", "gandcrab.com", "lockbit.net", "maze-ransomware.net",
    "darkside-ransomware.com", "ryuk.com", "revil-ransomware.net", "clop-ransomware.net",
    "sunburst-malware.com", "solorigate.net", "kimsuky.net", "nobelium.net", "aptgroup.net",
    "hades-ransomware.net", "blackkingdom.net", "karakurt.net", "hellokitty-ransomware.com",
    "goldenspy.net", "turla.org", "fin7.net", "apt29.com",
])

# ---------------- Utilities ----------------

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def extract_strings(data: bytes, min_len: int = 4):
    result = []
    current = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append("".join(current))
            current = []
    if len(current) >= min_len:
        result.append("".join(current))
    return result

def extract_hex_escape_sequences(data: bytes):
    results = set()
    try:
        text = data.decode("latin1", errors="ignore")
    except Exception:
        text = ""
    for match in re.finditer(r'(?:\\x[0-9A-Fa-f]{2}){3,}', text):
        seq = match.group(0)
        try:
            bytes_seq = bytes(int(h, 16) for h in re.findall(r'[0-9A-Fa-f]{2}', seq))
            decoded = bytes_seq.decode('latin1', errors='ignore')
            if len(decoded) >= 3:
                results.add(decoded)
        except Exception:
            pass
    for match in re.finditer(r'(?:(?:\b|^)[0-9A-Fa-f]{2}(?:\s+[0-9A-Fa-f]{2}){3,})', text):
        seq = re.sub(r'[^0-9A-Fa-f]', ' ', match.group(0)).strip()
        parts = seq.split()
        try:
            bytes_seq = bytes(int(h, 16) for h in parts)
            decoded = bytes_seq.decode('latin1', errors='ignore')
            if len(decoded) >= 3:
                results.add(decoded)
        except Exception:
            pass
    return list(results)

def is_pe_file(data: bytes) -> bool:
    if len(data) < 64:
        return False
    if data[:2] != b"MZ":
        return False
    try:
        e_lfanew = int.from_bytes(data[0x3C:0x3C+4], 'little')
        if 0 <= e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew+4] == b"PE\x00\x00":
            return True
    except Exception:
        pass
    return False

def detect_upx_marker(strings):
    return [s for s in strings if re.search(r'\bUPX\b', s, flags=re.I)]

def detect_ascii_shellcode_in_strings(strings):
    hits = []
    for s in strings:
        low = s.lower()
        if r'\x90' in low or '90 90 90' in low or 'nopnop' in low.replace(' ', '') or 'nop nop' in low:
            hits.append(s)
    return hits

def normalize_obfuscated_dot(text: str) -> str:
    t = re.sub(r'\[dot\]|\(dot\)|\{dot\}|\s+dot\s+|d0t', '.', text, flags=re.I)
    t = re.sub(r'hxxp', 'http', t, flags=re.I)
    t = re.sub(r'hxxps', 'https', t, flags=re.I)
    return t

def generate_normalizations(s: str):
    norms = set()
    try:
        raw = s
    except Exception:
        raw = str(s)
    lower = raw.lower()
    norms.add(lower)
    dots_fixed = normalize_obfuscated_dot(lower)
    norms.add(dots_fixed)
    joined = re.sub(r'["\']|\+|\s+', '', lower)
    norms.add(joined)
    alpha_num = re.sub(r'[^a-z0-9]', '', joined)
    norms.add(alpha_num)
    domain_like = re.sub(r'[^a-z0-9\.-]', '', dots_fixed)
    norms.add(domain_like)
    ip_like = re.sub(r'[_\s]', '.', joined)
    norms.add(ip_like)
    return norms

def detect_suspicious_domains(strings):
    found = set()
    suspicious_keywords = ['badactor', 'evil', 'payload', 'stealer', 'dropbox', 'secure-update']
    for s in strings:
        norms = generate_normalizations(s)
        for norm in norms:
            for match in re.findall(DOMAIN_REGEX, norm):
                if any(bad in match for bad in suspicious_keywords):
                    found.add(match)
    return list(found)

def detect_suspicious_ips(strings):
    found = set()
    version_like = re.compile(r'^\d+\.\d+\.\d+\.\d+$')
    version_context = re.compile(
        r'\b(version|ver|v|build|release|patch|update|rev|revision|sdk|fw|firmware|hotfix|beta|alpha|rc|service pack|sp|client|server)\b\s*[:=]?',
        re.I
    )
    for s in strings:
        norms = generate_normalizations(s)
        for norm in norms:
            ips = re.findall(IPV4_REGEX, norm)
            for ip in ips:
                if version_like.match(ip):
                    # Check if version-like keywords appear anywhere in the original string
                    if version_context.search(s):
                        continue  # Ignore this as IP
                found.add(ip)
    return list(found)

def detect_suspicious_apis(strings):
    found = []
    for api in SUSPICIOUS_APIS:
        for s in strings:
            if api.lower() in s.lower():
                found.append(api)
    return list(set(found))

def detect_suspicious_registry(strings):
    found = []
    for key in SUSPICIOUS_REGISTRY_KEYS:
        for s in strings:
            if re.search(key, s, flags=re.I):
                found.append(key)
    return list(set(found))

def detect_suspicious_mutex(strings):
    found = []
    for pattern in SUSPICIOUS_MUTEX_PATTERNS:
        regex = re.compile(pattern, re.I)
        for s in strings:
            if regex.search(s):
                found.append(s)
    return list(set(found))

def detect_suspicious_filenames(filename: str):
    return filename.lower() in COMMON_MALICIOUS_FILENAMES

def detect_suspicious_byte_patterns(data: bytes):
    hits = []
    for pat in SUSPICIOUS_BYTE_PATTERNS:
        if isinstance(pat, bytes):
            if pat in data:
                hits.append(pat)
        elif isinstance(pat, re.Pattern):
            if pat.search(data):
                hits.append(pat.pattern)
    return hits

# *** ADDED: Function to detect known malicious domains exactly ***
def detect_known_malicious_domains(strings):
    found = set()
    for s in strings:
        norms = generate_normalizations(s)
        for norm in norms:
            # Extract domain-like substrings from normalized string
            matches = re.findall(DOMAIN_REGEX, norm)
            for domain in matches:
                domain_lower = domain.lower()
                if domain_lower in KNOWN_MALICIOUS_DOMAINS:
                    found.add(domain_lower)
    return list(found)

# ---------------- VirusTotal Query ----------------

def query_virustotal_sha256(sha256: str) -> dict:
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {
        "x-apikey": VT_API_KEY
    }
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            # Not found
            return {"data": None}
        else:
            print(f"[!] VirusTotal API error: HTTP {response.status_code}")
            return None
    except Exception as e:
        print(f"[!] Exception querying VirusTotal: {e}")
        return None

def vt_detections_count(vt_json: dict) -> int:
    if not vt_json or "data" not in vt_json or vt_json["data"] is None:
        return 0
    try:
        attributes = vt_json["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = malicious + suspicious
        return total
    except Exception:
        return 0

# ---------------- Main Analysis ----------------

def analyze_file(path):
    console = Console()
    table = Table(title="Static File Analysis Report", show_lines=True)
    table.add_column("Check", style="cyan")
    table.add_column("Result", style="white")  # Default white for results

    with open(path, "rb") as f:
        data = f.read()

    filesize = len(data)
    sha256 = hashlib.sha256(data).hexdigest()
    entropy = calculate_entropy(data)
    is_pe = is_pe_file(data)
    filename = os.path.basename(path)
    suspicious_name = detect_suspicious_filenames(filename)

    strings = extract_strings(data, 4)
    strings += extract_hex_escape_sequences(data)

    suspicious_domains = detect_suspicious_domains(strings)
    suspicious_ips = detect_suspicious_ips(strings)
    suspicious_apis = detect_suspicious_apis(strings)
    suspicious_registry = detect_suspicious_registry(strings)
    suspicious_mutexes = detect_suspicious_mutex(strings)
    suspicious_bytes = detect_suspicious_byte_patterns(data)
    upx_markers = detect_upx_marker(strings)
    shellcode_ascii = detect_ascii_shellcode_in_strings(strings)
    known_malicious_domains = detect_known_malicious_domains(strings)

    # Helper to color results: impactful -> orange, else white
    def color_result(value, impactful_condition):
        color = "orange1" if impactful_condition else "white"
        return f"[{color}]{value}[/{color}]"

    # Add rows with conditional coloring for Result column
    table.add_row("File Size (bytes)", color_result(str(filesize), False))
    table.add_row("SHA256", color_result(sha256, False))
    table.add_row("Entropy", color_result(f"{entropy:.3f}", False))
    table.add_row("PE File Detected", color_result(str(is_pe), is_pe))
    table.add_row("Suspicious Filename", color_result(str(suspicious_name), suspicious_name))
    table.add_row("Suspicious Domains Found",
                  color_result(", ".join(suspicious_domains) if suspicious_domains else "None", bool(suspicious_domains)))
    table.add_row("Known Malicious Threat Actor Domains Found",
                  color_result(", ".join(known_malicious_domains) if known_malicious_domains else "None", bool(known_malicious_domains)))
    table.add_row("Suspicious IPs Found",
                  color_result(", ".join(suspicious_ips) if suspicious_ips else "None", bool(suspicious_ips)))
    table.add_row("Suspicious APIs Found",
                  color_result(", ".join(suspicious_apis) if suspicious_apis else "None", bool(suspicious_apis)))
    table.add_row("Suspicious Registry Keys Found",
                  color_result(", ".join(suspicious_registry) if suspicious_registry else "None", bool(suspicious_registry)))
    table.add_row("Suspicious Mutexes Found",
                  color_result(", ".join(suspicious_mutexes) if suspicious_mutexes else "None", bool(suspicious_mutexes)))
    table.add_row("Suspicious Byte Patterns Found",
                  color_result(", ".join(str(b) for b in suspicious_bytes) if suspicious_bytes else "None", bool(suspicious_bytes)))
    table.add_row("UPX Markers Found",
                  color_result(", ".join(upx_markers) if upx_markers else "None", bool(upx_markers)))
    table.add_row("ASCII Shellcode-like Strings Found",
                  color_result(", ".join(shellcode_ascii) if shellcode_ascii else "None", bool(shellcode_ascii)))

    # Risk scoring logic remains unchanged
    risk_score = 0
    reasons = []

    if entropy > 7.5:
        risk_score += 3
        reasons.append("High entropy (>7.5)")
    if suspicious_name:
        risk_score += 2
        reasons.append("Suspicious filename")
    if suspicious_domains:
        risk_score += len(suspicious_domains) * 1
        reasons.append(f"{len(suspicious_domains)} suspicious domain(s)")
    if known_malicious_domains:
        risk_score += len(known_malicious_domains) * 3
        reasons.append(f"{len(known_malicious_domains)} known malicious threat actor domain(s)")
    if suspicious_ips:
        risk_score += len(suspicious_ips) * 1
        reasons.append(f"{len(suspicious_ips)} suspicious IP(s)")
    if suspicious_apis:
        risk_score += len(suspicious_apis) * 2
        reasons.append(f"{len(suspicious_apis)} suspicious API(s)")
    if suspicious_registry:
        risk_score += len(suspicious_registry) * 2
        reasons.append(f"{len(suspicious_registry)} suspicious registry key(s)")
    if suspicious_mutexes:
        risk_score += len(suspicious_mutexes) * 1
        reasons.append(f"{len(suspicious_mutexes)} suspicious mutex(es)")
    if suspicious_bytes:
        risk_score += 2
        reasons.append("Suspicious byte patterns")
    if upx_markers:
        risk_score += 2
        reasons.append("UPX compression markers")
    if shellcode_ascii:
        risk_score += 2
        reasons.append("ASCII shellcode-like strings")

    if risk_score >= 8:
        verdict = "Malicious"
    elif risk_score >= 5:
        verdict = "Suspicious"
    elif risk_score >= 3:
        verdict = "Further Analysis Needed"
    else:
        verdict = "Likely Clean"

    vt_added_entropy = 0
    vt_detections = 0
    
    console.print("[yellow]Querying VirusTotal for SHA256 reputation...[/yellow]")
    vt_json = query_virustotal_sha256(sha256)

    if vt_json is None:
        console.print("[red]VirusTotal API error or no response. Try again later or check API key.[/red]")
    elif "error" in vt_json:
        error_code = vt_json["error"].get("code", "")
        if error_code == "QuotaExceededError":
            console.print("[red]VirusTotal API limit reached. Try again later.[/red]")
        else:
            console.print(f"[red]VirusTotal API error: {vt_json['error'].get('message', 'Unknown error')}[/red]")
    elif "data" not in vt_json or vt_json["data"] is None:
        console.print("[green]No detections found on VirusTotal.[/green]")
    else:
        vt_detections = vt_detections_count(vt_json)
        if vt_detections > 0:
            vt_added_entropy = 3
            risk_score += vt_added_entropy
            reasons.append(f"VirusTotal detections: {vt_detections}")
            if risk_score >= 8:
                verdict = "Malicious (VT)"
            elif risk_score >= 5:
                verdict = "Suspicious (VT)"
            else:
                verdict = "Further Analysis Needed (VT)"
        else:
            console.print("[green]No detections found on VirusTotal.[/green]")

    table.add_row("Calculated Risk Score", color_result(str(risk_score), False))
    table.add_row("Reasons", color_result("; ".join(reasons) if reasons else "None", False))
    table.add_row("Final Verdict", color_result(verdict, verdict.startswith(("Malicious", "Suspicious"))))
    if vt_detections > 0:
        table.add_row("VirusTotal Detections Count", color_result(str(vt_detections), True))

    console.print(table)

    return {
        "filename": filename,
        "filesize": filesize,
        "sha256": sha256,
        "entropy": entropy,
        "risk_score": risk_score,
        "verdict": verdict,
        "virus_total_detections": vt_detections,
        "reasons": reasons,
    }

# ---------------- Main ----------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Static file analysis with VirusTotal integration")
    parser.add_argument("file", help="Path to file to analyze")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        print(f"File not found: {args.file}")
        return

    analyze_file(args.file)

if __name__ == "__main__":
    main()
