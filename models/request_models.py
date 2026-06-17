from pydantic import BaseModel, Field, field_validator
from typing import Optional
from utils.validators import validate_evm_address

class PaymentSafetyGateRequest(BaseModel):
    address: str = Field(..., description="The EVM wallet address to evaluate.", examples=["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"])
    chain: str = Field("pharos-testnet", description="The target chain (e.g., pharos-testnet, pharos-atlantic).")
    intended_amount: Optional[str] = Field(None, description="Optional intended payment amount in PHRS.")

    @field_validator('address')
    @classmethod
    def check_address(cls, v: str) -> str:
        try:
            return validate_evm_address(v)
        except ValueError as e:
            raise ValueError(str(e))
