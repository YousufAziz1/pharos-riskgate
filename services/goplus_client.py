import os
import time
import hashlib
import logging
import requests
import urllib3
from typing import Dict, Any, Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("goplus_client")
logging.basicConfig(level=logging.INFO)

class GoPlusClient:
    def __init__(self):
        self.api_key = os.getenv("GOPLUS_API_KEY", "")
        self.api_secret = os.getenv("GOPLUS_API_SECRET", "")
        self.base_url = "https://api.gopluslabs.io"
        self.access_token: Optional[str] = None
        self.token_expiry: float = 0.0

        # We scan these chains for cross-chain malicious address intelligence
        self.reference_chains = {
            "1": "Ethereum Mainnet",
            "56": "BNB Chain",
            "137": "Polygon Mainnet"
        }

    def _get_access_token(self) -> Optional[str]:
        """
        Retrieves a new access token from GoPlus using key/secret signature authentication.
        Caches the token until it is close to expiration.
        """
        if not self.api_key or not self.api_secret:
            return None

        # Return cached token if valid
        if self.access_token and time.time() < self.token_expiry - 60:
            return self.access_token

        current_time = str(int(time.time()))
        # Signature: sha1(app_key + time + app_secret)
        sign_string = f"{self.api_key}{current_time}{self.api_secret}"
        signature = hashlib.sha1(sign_string.encode('utf-8')).hexdigest()

        payload = {
            "app_key": self.api_key,
            "time": int(current_time),
            "sign": signature
        }

        try:
            logger.info("Requesting fresh GoPlus access token...")
            response = requests.post(f"{self.base_url}/api/v1/token", json=payload, timeout=10, verify=False)
            if response.status_code == 200:
                data = response.json()
                if data.get("code") == 1 and "result" in data:
                    self.access_token = data["result"].get("access_token")
                    expires_in = data["result"].get("expires_in", 7200)
                    self.token_expiry = time.time() + expires_in
                    logger.info("GoPlus token authenticated successfully.")
                    return self.access_token
                else:
                    logger.error(f"GoPlus authentication failed with message: {data.get('message')}")
            else:
                logger.error(f"GoPlus token endpoint returned HTTP status {response.status_code}")
        except Exception as e:
            logger.error(f"Error authenticating with GoPlus API: {e}")

        return None

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json"
        }
        token = self._get_access_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def check_address_security(self, address: str) -> Dict[str, Any]:
        """
        Queries GoPlus Address Security API for the address across multiple major reference chains.
        Merges results to identify cross-chain threats.
        """
        address_lower = address.lower()
        
        merged_result = {
            "goplus_flag": False,
            "blacklisted": False,
            "flagged_contract_interaction": False,
            "detected_risks": [],
            "reasons": []
        }

        headers = self._get_headers()
        queried_any = False

        for chain_id, chain_name in self.reference_chains.items():
            url = f"{self.base_url}/api/v1/address_security/{address_lower}?chain_id={chain_id}"
            try:
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("code") == 1 and "result" in data:
                        result = data["result"]
                        queried_any = True
                        
                        # Helper to check string or int status of GoPlus response fields
                        def is_flagged(field_name: str) -> bool:
                            val = result.get(field_name, "0")
                            return str(val) == "1" or val is True or val == 1

                        # Blacklist check
                        if is_flagged("sanction") or is_flagged("blacklist_doubt"):
                            merged_result["blacklisted"] = True
                            risk_msg = f"Sanctioned or Blacklisted on {chain_name}"
                            if risk_msg not in merged_result["reasons"]:
                                merged_result["reasons"].append(risk_msg)

                        # Malicious wallet tags
                        malicious_fields = [
                            ("cybercrime", "Cybercrime Involvement"),
                            ("money_laundering", "Money Laundering"),
                            ("financial_crime", "Financial Crime"),
                            ("darkweb_transactions", "Darkweb Transactions"),
                            ("phishing_activities", "Phishing Activities"),
                            ("stealing_attack", "Theft/Exploit Association"),
                            ("honeypot_related_address", "Honeypot-related Activity"),
                            ("mixer", "Tornado Cash/Mixer interactions")
                        ]

                        for field, label in malicious_fields:
                            if is_flagged(field):
                                merged_result["goplus_flag"] = True
                                risk_msg = f"{label} detected on {chain_name}"
                                if risk_msg not in merged_result["reasons"]:
                                    merged_result["reasons"].append(risk_msg)

                        # Contract security
                        if is_flagged("contract_address"):
                            num_malicious = int(result.get("number_of_malicious_contracts_created", 0))
                            if num_malicious > 0:
                                merged_result["flagged_contract_interaction"] = True
                                risk_msg = f"Created {num_malicious} malicious contracts on {chain_name}"
                                if risk_msg not in merged_result["reasons"]:
                                    merged_result["reasons"].append(risk_msg)
                else:
                    logger.warning(f"GoPlus returned HTTP {response.status_code} for chain {chain_id}")
            except Exception as e:
                logger.error(f"Error querying GoPlus API on chain {chain_id}: {e}")

        # If we failed to fetch GoPlus data or no flags were found
        if not queried_any:
            logger.warning("Could not contact GoPlus API for any reference chain. Continuing with local on-chain evaluation.")
            merged_result["reasons"].append("GoPlus Security API unreachable (Offline Mode)")
        elif not merged_result["reasons"]:
            merged_result["reasons"].append("Clean security status on GoPlus reference networks")

        return merged_result
