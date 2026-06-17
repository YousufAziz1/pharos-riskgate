import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

@pytest.fixture
def mock_chain_client():
    with patch("app.main.chain_client") as mock:
        yield mock

@pytest.fixture
def mock_goplus_client():
    with patch("app.main.goplus_client") as mock:
        yield mock

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_mcp_schema_endpoint():
    response = client.get("/mcp/tool-schema")
    assert response.status_code == 200
    assert "name" in response.json()
    assert response.json()["name"] == "payment_safety_gate"

def test_payment_safety_gate_invalid_address():
    # Test with non-hex string
    response = client.post(
        "/skill/payment-safety-gate",
        json={"address": "invalid-address-format", "chain": "pharos-testnet"}
    )
    assert response.status_code == 422
    assert "Invalid EVM address" in response.text

def test_payment_safety_gate_allow_scenario(mock_chain_client, mock_goplus_client):
    # Setup mock data for standard safe EOA wallet
    mock_chain_client.get_wallet_basic_info.return_value = {
        "native_balance": "250.5000",
        "transaction_count": 142,
        "is_contract": False
    }
    mock_chain_client.get_recent_transactions_and_age.return_value = (
        120,  # 120 days old
        [
            {
                "hash": "0xtxhash1",
                "from": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "to": "0xrecipient1",
                "value": "1.5000 PHRS",
                "timestamp": "2026-06-16T12:00:00Z"
            }
        ]
    )
    mock_chain_client.get_gas_analysis.return_value = {
        "gas_price_gwei": "1.5000",
        "estimated_cost_native": "0.00003150 PHRS"
    }

    mock_goplus_client.check_address_security.return_value = {
        "goplus_flag": False,
        "blacklisted": False,
        "flagged_contract_interaction": False,
        "reasons": ["Clean security status on GoPlus reference networks"]
    }

    # Execute request
    response = client.post(
        "/skill/payment-safety-gate",
        json={"address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "chain": "pharos-testnet"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "ALLOW"
    assert data["risk_score"] < 30
    assert data["agent_reputation"] > 80
    assert data["wallet_analysis"]["wallet_age_days"] == 120
    assert data["risk_factors"]["goplus_flag"] is False
    assert data["risk_factors"]["blacklisted"] is False

def test_payment_safety_gate_flag_scenario(mock_chain_client, mock_goplus_client):
    # Setup mock data for a young but clean wallet (0 days old, 0 txs)
    mock_chain_client.get_wallet_basic_info.return_value = {
        "native_balance": "0.0500",
        "transaction_count": 0,
        "is_contract": False
    }
    mock_chain_client.get_recent_transactions_and_age.return_value = (
        0,  # 0 days old
        [
            {
                "hash": "0xtxhash2",
                "from": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
                "to": "0xrecipient2",
                "value": "0.0100 PHRS",
                "timestamp": "2026-06-16T12:00:00Z"
            }
        ]
    )
    mock_chain_client.get_gas_analysis.return_value = {
        "gas_price_gwei": "2.0000",
        "estimated_cost_native": "0.00004200 PHRS"
    }

    mock_goplus_client.check_address_security.return_value = {
        "goplus_flag": False,
        "blacklisted": False,
        "flagged_contract_interaction": False,
        "reasons": ["Clean security status on GoPlus reference networks"]
    }

    # Execute request
    response = client.post(
        "/skill/payment-safety-gate",
        json={"address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "chain": "pharos-testnet"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "FLAG"  # Because wallet age is < 7 days (+20 risk) + zero tx pattern warning (+20 risk)
    assert 30 <= data["risk_score"] < 70
    assert data["risk_factors"]["goplus_flag"] is False

def test_payment_safety_gate_block_scenario(mock_chain_client, mock_goplus_client):
    # Setup mock data for a blacklisted wallet
    mock_chain_client.get_wallet_basic_info.return_value = {
        "native_balance": "1000.0000",
        "transaction_count": 500,
        "is_contract": False
    }
    mock_chain_client.get_recent_transactions_and_age.return_value = (
        400,
        []
    )
    mock_chain_client.get_gas_analysis.return_value = {
        "gas_price_gwei": "1.5000",
        "estimated_cost_native": "0.00003150 PHRS"
    }

    # GoPlus flags wallet as blacklisted
    mock_goplus_client.check_address_security.return_value = {
        "goplus_flag": True,
        "blacklisted": True,
        "flagged_contract_interaction": False,
        "reasons": ["Sanctioned or Blacklisted on Ethereum Mainnet"]
    }

    # Execute request
    response = client.post(
        "/skill/payment-safety-gate",
        json={"address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "chain": "pharos-testnet"}
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "BLOCK"
    assert data["risk_score"] >= 70
    assert data["risk_factors"]["blacklisted"] is True
    assert data["agent_reputation"] < 30
