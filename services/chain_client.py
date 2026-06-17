import os
import logging
from datetime import datetime, timezone
import requests
import urllib3
from web3 import Web3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("chain_client")
logging.basicConfig(level=logging.INFO)

class ChainClient:
    def __init__(self):
        self.rpc_url = os.getenv("PHAROS_RPC_URL", "https://testnet.dplabs-internal.com")
        self.chain_id = int(os.getenv("PHAROS_CHAIN_ID", 688688))
        self.explorer_url = os.getenv("PHAROS_EXPLORER_URL", "https://pharos-testnet.socialscan.io").rstrip('/')
        self.fallback_explorer_url = os.getenv("PHAROS_EXPLORER_FALLBACK_URL", "https://testnet.pharosscan.xyz").rstrip('/')

        # Initialize web3 with a 2-second timeout and SSL verification disabled
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 2.0, "verify": False}))
        self.rpc_connected = True

    def get_wallet_basic_info(self, address: str) -> dict:
        """
        Retrieves native token balance (PHRS), transaction count (nonce), and checks if target is a contract.
        """
        checksum_address = Web3.to_checksum_address(address)
        
        # Defaults if RPC is down
        info = {
            "native_balance": "0",
            "transaction_count": 0,
            "is_contract": False
        }

        try:
            balance_wei = self.w3.eth.get_balance(checksum_address)
            balance_phrs = self.w3.from_wei(balance_wei, "ether")
            # Format nicely
            info["native_balance"] = f"{balance_phrs:.4f}"
            
            # Nonce / Transaction count
            tx_count = self.w3.eth.get_transaction_count(checksum_address)
            info["transaction_count"] = tx_count
            
            # Code detection
            code = self.w3.eth.get_code(checksum_address)
            info["is_contract"] = len(code) > 0
        except Exception as e:
            logger.error(f"Error fetching basic info from RPC for {address}: {e}")

        return info

    def get_gas_analysis(self, address: str) -> dict:
        """
        Retrieves gas price and estimates transfer/interaction cost in PHRS.
        """
        # Defaults
        gas_info = {
            "gas_price_gwei": "0.00",
            "estimated_cost_native": "0.000000"
        }

        if not self.rpc_connected:
            return gas_info

        try:
            gas_price_wei = self.w3.eth.gas_price
            gas_price_gwei = self.w3.from_wei(gas_price_wei, "gwei")
            gas_info["gas_price_gwei"] = f"{gas_price_gwei:.4f}"

            # Standard Transfer gas limit: 21000. Contract interactions: 100000.
            checksum_address = Web3.to_checksum_address(address)
            try:
                code = self.w3.eth.get_code(checksum_address)
                gas_limit = 100000 if len(code) > 0 else 21000
            except Exception:
                gas_limit = 21000

            cost_wei = gas_limit * gas_price_wei
            cost_phrs = self.w3.from_wei(cost_wei, "ether")
            gas_info["estimated_cost_native"] = f"{cost_phrs:.8f} PHRS"
        except Exception as e:
            logger.error(f"Error calculating gas analysis: {e}")

        return gas_info

    def get_recent_transactions_and_age(self, address: str) -> tuple[int, list[dict]]:
        """
        Fetches up to 20 transactions from primary Blockscout API, falls back to alternative Blockscout API if down.
        Calculates estimated activity age in days.
        """
        address_lower = address.lower()
        
        # Try primary first, then fallback
        explorers = [self.explorer_url, self.fallback_explorer_url]
        data = None
        used_url = None

        for explorer in explorers:
            if not explorer:
                continue
            # Blockscout v2 addresses transactions endpoint
            url = f"{explorer}/api/v2/addresses/{address_lower}/transactions"
            try:
                logger.info(f"Querying transaction history from {url}...")
                response = requests.get(url, timeout=8, verify=False)
                if response.status_code == 200:
                    data = response.json()
                    used_url = url
                    break
                else:
                    logger.warning(f"Explorer API {url} returned HTTP {response.status_code}")
            except Exception as e:
                logger.error(f"Failed to query transactions from {url}: {e}")

        # If both explorers fail or return nothing, return empty
        if not data or "items" not in data:
            logger.warning(f"Could not retrieve transactions from any explorer for address {address}")
            return 0, []

        items = data.get("items", [])
        transactions = []
        earliest_timestamp = None

        # Parse transactions
        for item in items[:20]:
            tx_hash = item.get("hash", "")
            from_hash = item.get("from", {}).get("hash", "") if isinstance(item.get("from"), dict) else ""
            to_hash = item.get("to", {}).get("hash", "") if isinstance(item.get("to"), dict) else ""
            
            # Format value
            raw_val = item.get("value", "0")
            try:
                # Convert value from wei to PHRS for readability
                val_eth = self.w3.from_wei(int(raw_val), "ether")
                value_str = f"{val_eth:.4f} PHRS"
            except Exception:
                value_str = f"{raw_val} wei"
                
            timestamp_str = item.get("timestamp", "")
            
            transactions.append({
                "hash": tx_hash,
                "from": from_hash,
                "to": to_hash,
                "value": value_str,
                "timestamp": timestamp_str
            })

        # Calculate estimated wallet age (activity age)
        # Blockscout list is descending (newest first). Let's check the oldest transaction available.
        # If there are items, the oldest one is the last in the array.
        # If the explorer returns a next_page_params, we know the wallet is older, but this is a solid heuristic.
        all_returned_items = items
        if all_returned_items:
            oldest_item = all_returned_items[-1]
            oldest_time_str = oldest_item.get("timestamp")
            if oldest_time_str:
                try:
                    # Parse timestamp format (e.g. "2023-07-03T20:09:59.000000Z")
                    # Remove trailing Z for processing or use timezone-aware parser
                    time_clean = oldest_time_str.replace("Z", "+00:00")
                    oldest_dt = datetime.fromisoformat(time_clean)
                    now_dt = datetime.now(timezone.utc)
                    age_delta = now_dt - oldest_dt
                    
                    # If page params exist, the wallet age is at least this old, possibly older.
                    # This is a safe lower bound.
                    estimated_days = max(0, age_delta.days)
                    
                    # If next_page_params exists, add 30 days buffer as it indicates older txs exist
                    if "next_page_params" in data and data["next_page_params"]:
                        estimated_days = max(estimated_days, 30)
                        
                    return estimated_days, transactions
                except Exception as e:
                    logger.error(f"Error parsing transaction timestamp {oldest_time_str}: {e}")

        return 0, transactions
