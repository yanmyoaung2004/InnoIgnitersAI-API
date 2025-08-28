# tools/threat_intel_tool.py
from typing import List, Dict, Optional
import datetime

class ThreatIntelTool:
    """
    Threat Intel Tool 🚨
    - Provides IOC reputation checks
    - Returns active threats
    - Simulated / safe for chatbot use
    """

    def __init__(self, intel_db: Optional[List[Dict]] = None):
        """
        intel_db: list of threat intelligence entries
        Each entry is a dict like:
        {
            "ioc": "192.168.1.100" or "malicious.com" or SHA256 hash,
            "type": "IP" / "Domain" / "File",
            "reputation": "malicious" / "suspicious" / "clean",
            "last_seen": "2025-08-24T08:00:00",
            "threat_level": "LOW" / "MEDIUM" / "HIGH",
            "description": "Description of the threat"
        }
        """
        self.intel_db = intel_db or []

    def get_ip_reputation(self, ip: str) -> Optional[Dict]:
        """Return reputation info for an IP"""
        print('get_ip_reputation running from ThreatIntelTool')
        for entry in self.intel_db:
            if entry.get("type") == "IP" and entry.get("ioc") == ip:
                return entry
        return {"ioc": ip, "reputation": "unknown", "threat_level": "unknown", "description": "No data"}

    def get_domain_reputation(self, domain: str) -> Optional[Dict]:
        """Return reputation info for a domain"""
        print('get_domain_reputation running from ThreatIntelTool')
        for entry in self.intel_db:
            if entry.get("type") == "Domain" and entry.get("ioc").lower() == domain.lower():
                return entry
        return {"ioc": domain, "reputation": "unknown", "threat_level": "unknown", "description": "No data"}

    def get_file_hash_reputation(self, sha256: str) -> Optional[Dict]:
        """Return reputation info for a file hash"""
        print('get_file_hash_reputation running from ThreatIntelTool')
        for entry in self.intel_db:
            if entry.get("type") == "File" and entry.get("ioc").lower() == sha256.lower():
                return entry
        return {"ioc": sha256, "reputation": "unknown", "threat_level": "unknown", "description": "No data"}

    def get_active_threats(self) -> List[Dict]:
        """Return all threats with reputation 'malicious' or 'high'"""
        print('get_active_threats running from ThreatIntelTool')
        active = [
            entry for entry in self.intel_db
            if entry.get("reputation") == "malicious" or entry.get("threat_level", "").upper() == "HIGH"
        ]
        return active
