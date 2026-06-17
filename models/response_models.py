from pydantic import BaseModel, Field
from typing import List, Optional

class TransactionModel(BaseModel):
    hash: str
    from_address: str = Field(..., alias="from")
    to_address: str = Field(..., alias="to")
    value: str
    timestamp: str

    class Config:
        populate_by_name = True
        json_encoders = {
            # Ensure proper string/numeric conversion if needed
        }

class WalletAnalysisModel(BaseModel):
    wallet_age_days: int
    native_balance: str
    transaction_count: int
    recent_transactions: List[TransactionModel] = []

class RiskFactorsModel(BaseModel):
    goplus_flag: bool
    blacklisted: bool
    high_velocity: bool
    flagged_contract_interaction: bool

class GasAnalysisModel(BaseModel):
    gas_price_gwei: str
    estimated_cost_native: str

class PaymentSafetyGateResponse(BaseModel):
    address: str
    verdict: str  # ALLOW, FLAG, BLOCK
    risk_score: int
    confidence: int
    reason: str
    agent_reputation: int
    wallet_analysis: WalletAnalysisModel
    risk_factors: RiskFactorsModel
    gas_analysis: GasAnalysisModel
    recommended_action: str
