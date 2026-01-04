import json
import os
import re

def map_severity(impact):
    impact = impact.lower()
    if impact == "high": return "high"
    elif impact == "medium": return "medium"
    elif impact == "low": return "low"
    elif impact == "informational": return "info"
    elif impact == "optimization": return "gas"
    else: return "info"

def get_clean_location(d):
    elements = d.get("elements", [])
    if elements and len(elements) > 0:
        first_elem = elements[0]
        if "source_mapping" in first_elem:
            mapping = first_elem["source_mapping"]
            full_path = mapping.get("filename_relative", "Unknown File")
            clean_filename = os.path.basename(full_path)
            lines = mapping.get("lines", [])
            if len(lines) > 0:
                return f"{clean_filename} : Line {lines[0]}"
            else:
                return clean_filename
    return "Global Issue"

def parse_report(report_path):
    if not os.path.exists(report_path):
        return []

    with open(report_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = []
    detectors = data.get("results", {}).get("detectors", [])

    for d in detectors:
        check_name = d.get("check", "unknown")
        raw_description = d.get("description", "")
        clean_description = re.sub(r'\(.*?\.sol#\d+\)', '', raw_description).replace("uploads/", "").strip()
        
        findings.append({
            "title": check_name,
            "impact": d.get("impact"),
            "description": clean_description,
            "severity": map_severity(d.get("impact", "info")),
            "location": get_clean_location(d)
        })

    return findings

# --- ADVANCED THREAT ENGINE & SLOC COUNTER ---
def analyze_threats(file_path):
    threats = []
    findings_from_threats = [] # We will add these to the main list
    real_lines_of_code = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
            # 1. PROFESSIONAL SLOC COUNTING
            for line in lines:
                stripped = line.strip()
                # Skip empty lines
                if not stripped: continue 
                # Skip comments
                if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"): continue 
                real_lines_of_code += 1
            
            content = "".join(lines)

        def check(pattern): return re.search(pattern, content, re.IGNORECASE) is not None

        # 2. THREAT DETECTION -> CONVERT TO FINDINGS
        
        # MINTING
        if check(r'function\s+(mint|_mint)'):
            t = {"name": "Presence of Minting", "status": "High Risk", "desc": "Mint function detected. Owner can create infinite tokens."}
            threats.append(t)
            findings_from_threats.append({"title": "Minting Functionality", "severity": "high", "description": t["desc"], "location": "Global Check"})
        else:
            threats.append({"name": "Presence of Minting", "status": "No Impact", "desc": "No mint functions detected."})

        # SELF DESTRUCT
        if check(r'selfdestruct'):
            t = {"name": "Self Destruct", "status": "Critical", "desc": "Contract can be destroyed and funds drained."}
            threats.append(t)
            findings_from_threats.append({"title": "Self Destruct Capable", "severity": "critical", "description": t["desc"], "location": "Global Check"})
        else:
            threats.append({"name": "Self Destruct", "status": "No Impact", "desc": "No self-destruct capability found."})

        # OWNERSHIP / BLACKLIST
        if check(r'(blacklist|blocklist)'):
            t = {"name": "Blacklist Capabilities", "status": "High Risk", "desc": "Owner can restrict specific addresses."}
            threats.append(t)
            findings_from_threats.append({"title": "Centralized Blacklist", "severity": "medium", "description": t["desc"], "location": "Global Check"})
        else:
            threats.append({"name": "Blacklist Capabilities", "status": "Beneficial", "desc": "Owners cannot blacklist tokens or users."})

        # PRAGMA VER
        if check(r'pragma\s+solidity\s+(\^|>)?0\.[4-7]'):
            t = {"name": "Old Solidity Version", "status": "Low Risk", "desc": "Contract uses an older Solidity version."}
            threats.append(t)
            findings_from_threats.append({"title": "Outdated Compiler", "severity": "low", "description": t["desc"], "location": "Pragma Statement"})
        else:
            threats.append({"name": "Solidity Pragma Version", "status": "Beneficial", "desc": "Modern Solidity version used."})

        # PAUSABLE
        if check(r'(pausable|whenNotPaused|_pause)'):
            t = {"name": "Pausable Contract", "status": "Moderate Risk", "desc": "Owner can pause the contract."}
            threats.append(t)
            findings_from_threats.append({"title": "Pausable Logic", "severity": "info", "description": t["desc"], "location": "Global Check"})
        else:
            threats.append({"name": "Pausable Contract", "status": "No Impact", "desc": "Not a Pausable contract."})

        # FEES
        if check(r'(fee|tax|deduction)'):
            t = {"name": "Transaction Fees", "status": "Moderate Risk", "desc": "Code contains logic for fees or taxes."}
            threats.append(t)
            findings_from_threats.append({"title": "Fee Logic Detected", "severity": "info", "description": t["desc"], "location": "Global Check"})
        else:
            threats.append({"name": "Transaction Fees", "status": "No Impact", "desc": "Owners can not set or update Fees."})

        return threats, real_lines_of_code, findings_from_threats

    except Exception as e:
        return [], 0, []