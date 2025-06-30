import requests
import logging

VT_API_KEY = 'REPLACE_WITH_MY_API_KEY'

def check_virustotal(file_hash):
    try:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "x-apikey": VT_API_KEY
        }
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            suspicious_count = data['data']['attributes']['last_analysis_stats']['suspicious']
            harmless_count = data['data']['attributes']['last_analysis_stats']['harmless']

            logging.info(f"VirusTotal Report - SHA256: {file_hash} | Malicious: {malicious_count}, Suspicious: {suspicious_count}, Harmless: {harmless_count}")
            return {
                "malicious": malicious_count,
                "suspicious": suspicious_count,
                "harmless": harmless_count
            }
        elif response.status_code == 404:
            logging.info(f"VirusTotal - No match found for SHA256: {file_hash}")
            return None
        else: logging.warning(f"VirusTotal error ({response.status_code}): {response.text}")
    except Exception as e:
        logging.error(f"Error checking VirusTotal: {e}")
        return None