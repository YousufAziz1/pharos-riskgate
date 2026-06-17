import logging
from typing import Dict, Any

logger = logging.getLogger("reputation_engine")
logging.basicConfig(level=logging.INFO)

class ReputationEngine:
    """
    Evaluates the trustworthiness of an address, returning a score from 0 (low reputation)
    to 100 (high reputation).
    
    This score enables autonomous AI agents to gauge the credibility and historical
    reliability of target payment destinations.
    """

    def calculate_reputation(
        self,
        wallet_info: Dict[str, Any],
        goplus_results: Dict[str, Any]
    ) -> int:
        """
        Calculates a 0-100 reputation score based on activity, security status, and balances.
        """
        # Start with a baseline score of 100 (perfect trust)
        reputation = 100

        # 1. Security deductions (Major impact)
        if goplus_results.get("blacklisted", False):
            reputation -= 80
        if goplus_results.get("goplus_flag", False):
            reputation -= 60
        if goplus_results.get("flagged_contract_interaction", False):
            reputation -= 40

        # 2. Wallet age deductions
        wallet_age = wallet_info.get("wallet_age_days", 0)
        if wallet_age == 0:
            reputation -= 25  # Brand new or completely inactive
        elif wallet_age < 7:
            reputation -= 15
        elif wallet_age < 30:
            reputation -= 8
        elif wallet_age >= 180:
            reputation += 5  # Age bonus for mature wallets

        # 3. Transaction volume deductions/bonuses
        tx_count = wallet_info.get("transaction_count", 0)
        if tx_count == 0:
            reputation -= 20
        elif tx_count < 10:
            reputation -= 10
        elif tx_count > 500:
            reputation += 5  # High activity bonus
            
        # 4. Native balance deductions/bonuses
        balance_str = wallet_info.get("native_balance", "0")
        try:
            balance = float(balance_str)
            if balance == 0.0:
                reputation -= 10
            elif balance >= 100.0:
                reputation += 5  # Financial backing bonus
        except ValueError:
            pass

        # 5. Contract safety assessment
        if wallet_info.get("is_contract", False):
            if not goplus_results.get("flagged_contract_interaction", False):
                # Well-behaved contract (e.g. established protocols) gets a minor boost
                reputation += 5
            else:
                # Malicious contracts get severely penalized
                reputation -= 30

        # Keep the score strictly bounded between 0 and 100
        normalized_reputation = max(0, min(reputation, 100))
        
        logger.info(f"Calculated reputation score: {normalized_reputation}/100")
        return normalized_reputation
