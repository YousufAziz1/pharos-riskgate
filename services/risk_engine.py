import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

logger = logging.getLogger("risk_engine")
logging.basicConfig(level=logging.INFO)

class RiskEngine:
    """
    Evaluates transaction risk factors, computes a normalized risk score (0-100),
    and determines a verdict: ALLOW, FLAG, or BLOCK.
    
    Risk Calculation Formula:
      raw_score = sum(active_risk_factor_weights)
      normalized_score = min(raw_score, 100)
      
    Verdicts:
      - 0 to 29:   ALLOW
      - 30 to 69:  FLAG
      - 70 to 100: BLOCK
    """

    def __init__(self):
        # Define strict risk weights
        self.weights = {
            "malicious_wallet": 60,              # Flagged by security registries
            "blacklisted": 80,                   # Appears on sanction lists/OFAC
            "flagged_contract_interaction": 25,   # Interacts with malicious code
            "wallet_age_under_7_days": 20,       # Brand new wallet
            "wallet_age_under_30_days": 10,      # Young wallet
            "high_transaction_velocity": 15,     # High volume within short span
            "suspicious_patterns": 20            # Transaction/balance anomalies
        }

    def evaluate(
        self,
        address: str,
        wallet_info: Dict[str, Any],
        goplus_results: Dict[str, Any],
        transactions: List[Dict[str, Any]],
        intended_amount: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyzes wallet attributes and GoPlus safety data to generate risk score and verdict.
        """
        active_factors = []
        raw_score = 0
        reasons = []

        # 1. Blacklist check (OFAC, Sanctions, exchange blacklists)
        if goplus_results.get("blacklisted", False):
            raw_score += self.weights["blacklisted"]
            active_factors.append("blacklisted")
            reasons.append("Wallet appears on international sanction or blacklist registry (+80 Risk)")

        # 2. Malicious wallet check
        if goplus_results.get("goplus_flag", False):
            raw_score += self.weights["malicious_wallet"]
            active_factors.append("malicious_wallet")
            reasons.append("Wallet is marked as malicious (cybercrime/phishing/exploit) in security indices (+60 Risk)")

        # 3. Contract security check
        if goplus_results.get("flagged_contract_interaction", False):
            raw_score += self.weights["flagged_contract_interaction"]
            active_factors.append("flagged_contract_interaction")
            reasons.append("Wallet has created or interacted with flagged malicious contract code (+25 Risk)")

        # 4. Wallet age checks
        wallet_age = wallet_info.get("wallet_age_days", 0)
        # Check if the wallet is brand new
        if wallet_age < 7:
            raw_score += self.weights["wallet_age_under_7_days"]
            active_factors.append("wallet_age_under_7_days")
            reasons.append(f"Wallet estimated activity age is under 7 days ({wallet_age} days) (+20 Risk)")
        # Check if wallet is relatively young
        elif wallet_age < 30:
            raw_score += self.weights["wallet_age_under_30_days"]
            active_factors.append("wallet_age_under_30_days")
            reasons.append(f"Wallet estimated activity age is under 30 days ({wallet_age} days) (+10 Risk)")

        # 5. High transaction velocity check
        # Defined as more than 5 transactions in the last 24 hours (from the recent transaction history list)
        recent_tx_count_24h = 0
        now = datetime.now(timezone.utc)
        for tx in transactions:
            ts_str = tx.get("timestamp", "")
            if ts_str:
                try:
                    time_clean = ts_str.replace("Z", "+00:00")
                    tx_dt = datetime.fromisoformat(time_clean)
                    if now - tx_dt < timedelta(hours=24):
                        recent_tx_count_24h += 1
                except Exception:
                    pass

        if recent_tx_count_24h > 5:
            raw_score += self.weights["high_transaction_velocity"]
            active_factors.append("high_transaction_velocity")
            reasons.append(f"High transaction velocity detected: {recent_tx_count_24h} txs in the last 24h (+15 Risk)")

        # 6. Suspicious patterns check
        # Example patterns: 
        # - Wallet is a contract but has no transactions / code flagged (high risk for direct transfers)
        # - Intended amount exceeds balance by a huge factor for an inactive address
        # - High nonce count but zero native balance
        has_suspicious_pattern = False
        tx_count = wallet_info.get("transaction_count", 0)
        native_bal_str = wallet_info.get("native_balance", "0")
        try:
            native_bal = float(native_bal_str)
        except Exception:
            native_bal = 0.0

        # Pattern A: EOA wallet with 0 transactions but age is 0 (brand new, empty wallet)
        if tx_count == 0 and wallet_age == 0 and not wallet_info.get("is_contract", False):
            has_suspicious_pattern = True
            reasons.append("Brand new wallet with zero historical transactions (+20 Risk)")
            
        # Pattern B: Contract destination with no known verification details
        if wallet_info.get("is_contract", False) and not goplus_results.get("flagged_contract_interaction", False):
            # General warning for contract interactions if not specifically allowed
            has_suspicious_pattern = True
            reasons.append("Target is a contract address; direct token transfers may lock funds (+20 Risk)")

        # Pattern C: Intended amount validation
        if intended_amount:
            try:
                amount = float(intended_amount)
                if amount > 0 and native_bal == 0.0:
                    has_suspicious_pattern = True
                    reasons.append(f"Destination balance is empty (0 PHRS) for intended transfer of {intended_amount} PHRS (+20 Risk)")
            except ValueError:
                pass

        if has_suspicious_pattern:
            raw_score += self.weights["suspicious_patterns"]
            active_factors.append("suspicious_patterns")

        # Normalize score
        normalized_score = min(raw_score, 100)

        # Determine verdict and recommended action
        if normalized_score >= 70:
            verdict = "BLOCK"
            recommended_action = "Reject transaction. High risk profile detected."
        elif normalized_score >= 30:
            verdict = "FLAG"
            recommended_action = "Proceed with caution. Manual verification or multisig approval required."
        else:
            verdict = "ALLOW"
            recommended_action = "Safe to proceed. Low risk profile detected."

        if not reasons:
            reasons.append("No active risk factors identified. Wallet exhibits standard on-chain behavior.")

        # Confidence calculation
        # If we successfully queried GoPlus and RPC, confidence is high.
        # If GoPlus was offline, confidence decreases.
        confidence = 95
        if "GoPlus Security API unreachable (Offline Mode)" in goplus_results.get("reasons", []):
            confidence = 60

        return {
            "verdict": verdict,
            "risk_score": normalized_score,
            "confidence": confidence,
            "reason": "; ".join(reasons),
            "risk_factors": {
                "goplus_flag": "malicious_wallet" in active_factors,
                "blacklisted": "blacklisted" in active_factors,
                "high_velocity": "high_transaction_velocity" in active_factors,
                "flagged_contract_interaction": "flagged_contract_interaction" in active_factors
            },
            "recommended_action": recommended_action
        }
