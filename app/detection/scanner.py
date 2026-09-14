"""Multi-layer Security Scanner (Hash, PE Structural Analysis, Signatures)."""
import hashlib
import math
import os
from typing import Any, Dict, List, Optional

try:
    import pefile
except ImportError:
    pefile = None

# Known malicious sample test hashes (e.g. EICAR and malware reference signatures)
KNOWN_MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR-Test-Signature (MD5)",
    "c637d527c86186464879dc45e7816c53": "EICAR-Test-Signature (MD5)",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Standard-AV-Test (SHA256)",
    "13db60afb914a2ee9b3649d1947d58046d1a9e9b8e4114d80b1d5c142b4ed7fa": "EICAR-Standard-AV-Test (SHA256)",
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": "Test-Malware-Payload-A (SHA256)",
}


SUSPICIOUS_SECTIONS = {".upx0", ".upx1", ".upx2", ".aspack", ".themida", ".vmp0", ".vmp1", ".packed"}
DANGEROUS_IMPORTS = {
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "SetWindowsHookExA",
    "SetWindowsHookExW",
    "InternetOpenA",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "AdjustTokenPrivileges",
}
SUSPICIOUS_STRINGS = [
    b"powershell -enc",
    b"powershell.exe -encodedcommand",
    b"downloadstring('http",
    b"invoke-webrequest",
    b"your personal files are encrypted",
    b"pay bitcoin to recover",
    b"wannacry",
    b"mimikatz",
]

class SecurityScanner:
    """Multi-layer static inspection engine: Hashes, PE internals, and Heuristic Rules."""

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte sequence (0.0 to 8.0)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def scan_file(cls, file_path: str) -> Dict[str, Any]:
        """Perform comprehensive static analysis on a given file."""
        if not os.path.isfile(file_path):
            return {"file_path": file_path, "is_threat": False, "risk_score": 0, "reason": "File does not exist"}

        try:
            with open(file_path, "rb") as f:
                content = f.read(50 * 1024 * 1024)  # Read up to 50MB
        except Exception as e:
            return {"file_path": file_path, "is_threat": False, "risk_score": 0, "error": str(e)}

        md5 = hashlib.md5(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        overall_entropy = cls.calculate_entropy(content)

        indicators: List[str] = []
        risk_score = 0
        threat_name: Optional[str] = None

        # 1. Known Hash Verification
        if sha256 in KNOWN_MALICIOUS_HASHES:
            threat_name = KNOWN_MALICIOUS_HASHES[sha256]
            indicators.append(f"Matched Known Threat Hash: {threat_name}")
            risk_score = 100
        elif md5 in KNOWN_MALICIOUS_HASHES:
            threat_name = KNOWN_MALICIOUS_HASHES[md5]
            indicators.append(f"Matched Known Threat Hash: {threat_name}")
            risk_score = 100

        # 2. String & Signature Heuristics
        lower_content = content.lower()
        for pat in SUSPICIOUS_STRINGS:
            if pat in lower_content:
                indicators.append(f"Suspicious payload signature detected: {pat.decode(errors='ignore')}")
                risk_score = max(risk_score, 70)

        # 3. High Entropy Detection (> 7.4 indicates encryption/ransomware/packers)
        if overall_entropy >= 7.4 and len(content) > 1024:
            indicators.append(f"Extremely high entropy ({overall_entropy:.2f}/8.0): Likely encrypted or packed")
            risk_score = max(risk_score, 50)

        # 4. PE Inspection (if executable)
        pe_details: Dict[str, Any] = {}
        if pefile and content[:2] == b"MZ":
            try:
                pe = pefile.PE(data=content)
                pe_details["sections"] = []
                for sec in pe.sections:
                    sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00").lower()
                    sec_entropy = sec.get_entropy()
                    pe_details["sections"].append({"name": sec_name, "entropy": sec_entropy})

                    if sec_name in SUSPICIOUS_SECTIONS:
                        indicators.append(f"Packed PE section detected: {sec_name}")
                        risk_score = max(risk_score, 65)

                    if sec_entropy > 7.3:
                        indicators.append(f"High section entropy in '{sec_name}' ({sec_entropy:.2f}): Encrypted code block")
                        risk_score = max(risk_score, 55)

                # Inspect Import Table for process injection / injection APIs
                found_danger_imports = []
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                imp_str = imp.name.decode("utf-8", errors="ignore")
                                if imp_str in DANGEROUS_IMPORTS:
                                    found_danger_imports.append(imp_str)

                if found_danger_imports:
                    indicators.append(f"Process Injection/Manipulation APIs imported: {', '.join(found_danger_imports[:3])}")
                    risk_score = max(risk_score, 60)

                pe.close()
            except Exception:
                pass

        is_threat = risk_score >= 60

        return {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "size_bytes": len(content),
            "md5": md5,
            "sha256": sha256,
            "entropy": round(overall_entropy, 2),
            "is_threat": is_threat,
            "risk_score": risk_score,
            "threat_name": threat_name or ("Suspicious-Heuristic-Sample" if is_threat else "Benign"),
            "indicators": indicators,
            "pe_details": pe_details,
        }
