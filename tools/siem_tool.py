from typing import List, Dict, Optional
import datetime

class SIEMTool:
    """
    SIEM Tool 🛠️
    - Simulated log analysis for educational / competition use
    - Search logs
    - Fetch alerts
    - Get event details
    - Identify top sources
    - Correlate with IOCs
    - Summarize activity
    """

    def __init__(self, logs: List[Dict]):
        """
        logs: list of log dictionaries with keys like
              event_id, timestamp, source_ip, destination_ip, user, severity, message
        """
        self.logs = logs

    def search_logs(self, keyword: str, limit: int = 10) -> List[Dict]:
        """Search logs by keyword in the message field"""
        print("search_logs running from SIEMTool")
        results = [log for log in self.logs if keyword.lower() in log.get("message", "").lower()]
        return results[:limit]

    def get_alerts(self, severity: Optional[str] = None, timeframe: Optional[int] = None) -> List[Dict]:
        """
        Fetch alerts, optionally filtered by severity and timeframe (minutes)
        """
        print("get_alert running from SIEMTool")
        now = datetime.datetime.now(datetime.timezone.utc)
        filtered = self.logs

        if severity:
            filtered = [log for log in filtered if log.get("severity", "").upper() == severity.upper()]

        if timeframe:
            cutoff = now - datetime.timedelta(minutes=timeframe)
            filtered = [
                log for log in filtered
                if datetime.datetime.fromisoformat(log.get("timestamp")).replace(tzinfo=datetime.timezone.utc) >= cutoff
            ]

        return filtered

    def get_event_details(self, event_id: str) -> Optional[Dict]:
        """Retrieve details for a specific event by ID"""
        print("get_event_details running from SIEMTool")
        for log in self.logs:
            if log.get("event_id") == event_id:
                return log
        return None

    def get_top_sources(self, n: int = 5) -> Dict[str, int]:
        """Return top n source IPs triggering alerts"""
        print("get_top_sources running from SIEMTool")
        source_count = {}
        for log in self.logs:
            src = log.get("source_ip")
            if src:
                source_count[src] = source_count.get(src, 0) + 1
        # Sort by count descending
        sorted_sources = dict(sorted(source_count.items(), key=lambda x: x[1], reverse=True))
        return dict(list(sorted_sources.items())[:n])

    def get_summary(self) -> Dict[str, int]:
        """Return high-level summary of logs by severity"""
        print("get_summary running from SIEMTool")
        summary = {}
        for log in self.logs:
            sev = log.get("severity", "UNKNOWN").upper()
            summary[sev] = summary.get(sev, 0) + 1
        return summary

    def correlate_with_ioc(self, ioc: str) -> Dict[str, object]:
        """
        Correlate logs with a given Indicator of Compromise (IOC).
        - ioc: IP, domain, file hash, username, etc.
        Returns:
            {
                "matches": [list of matching log dicts],
                "count": total number of matches
            }
        """
        print("correlate_with_ioc running from SIEMTool")
        ioc_lower = ioc.lower()
        matches = []

        for log in self.logs:
            # Check common fields: source_ip, destination_ip, user, message
            for field in ["source_ip", "destination_ip", "user", "message"]:
                value = str(log.get(field, "")).lower()
                if ioc_lower in value:
                    matches.append(log)
                    break  # avoid double-counting the same log

        return {"matches": matches, "count": len(matches)}
