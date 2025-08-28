import requests
import os

class DetectionTool:
    def __init__(self):
        pass
        self.vt_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        if not self.vt_api_key:
            print("Warning: VIRUSTOTAL_API_KEY not set. Fallback model will be used.")
        # self.fallback_model = FallbackMLModel()
            
    def detect_url(self, url):
        if not self.vt_api_key:
            pass
        try:
            response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers={'x-apikey': self.vt_api_key},
                data={'url': url}
            )
            if response.status_code == 200:
                analysis_id = response.json()['data']['id']
                report_response = requests.get(
                    f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                    headers={'x-apikey': self.vt_api_key}
                )
                if report_response.status_code == 200:
                    return report_response.json()['data']['attributes']['stats']
            print('fallback')
        except Exception as e:
            print(f"VirusTotal URL scan failed: {str(e)}")
            print('fallback')

    def detect_file(self, file_path: str):
        """
        Uploads a file to VirusTotal for scanning and retrieves the analysis result.
        Falls back gracefully if API is missing or request fails.
        
        Args:
            file_path (str): Path to the file to scan.
        
        Returns:
            dict | None: VirusTotal analysis result (JSON) or None if fallback.
        """
        if not self.vt_api_key:
            print("fallback: VIRUSTOTAL_API_KEY not set")
            return None

        try:
            upload_url = "https://www.virustotal.com/api/v3/files"
            headers = {"accept": "application/json", "x-apikey": self.vt_api_key}

            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f, "application/octet-stream")}
                response = requests.post(upload_url, files=files, headers=headers)

            if response.status_code != 200:
                print("fallback: upload failed ->", response.text)
                return None

            analysis_id = response.json()["data"]["id"]

            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            resp = requests.get(analysis_url, headers=headers)
            if resp.status_code != 200:
                print("fallback: analysis fetch failed ->", resp.text)
                return None
            result = resp.json()
            attributes = result["data"]["attributes"]
            stats = attributes.get("stats", {})
            summary = {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "timeout": stats.get("timeout", 0)
            }
            return summary
        except Exception as e:
            print("fallback: exception ->", str(e))
            return None
        
