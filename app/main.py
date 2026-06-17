import os
import json
import logging
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

# Import models & services
from models.request_models import PaymentSafetyGateRequest
from models.response_models import PaymentSafetyGateResponse, WalletAnalysisModel, RiskFactorsModel, GasAnalysisModel, TransactionModel
from services.chain_client import ChainClient
from services.goplus_client import GoPlusClient
from services.risk_engine import RiskEngine
from services.reputation_engine import ReputationEngine

# Initialize FastAPI app
app = FastAPI(
    title="Pharos RiskGate – Agent Payment Safety Skill",
    description="Reusable security and risk validation skill for autonomous AI agent transactions on the Pharos Network.",
    version="1.0.0"
)

# Enable CORS for cross-origin integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Setup templates directory
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))

# Mount static files directory
app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")

# Initialize services
chain_client = ChainClient()
goplus_client = GoPlusClient()
risk_engine = RiskEngine()
reputation_engine = ReputationEngine()

@app.get("/", response_class=HTMLResponse)
async def serve_playground(request: Request):
    """
    Serves the professional, dark-themed playground dashboard for hackathon judges to verify transaction safety.
    """
    return templates.TemplateResponse(
        request,
        "index.html", 
        {
            "rpc_url": chain_client.rpc_url,
            "chain_id": chain_client.chain_id,
            "explorer_url": chain_client.explorer_url
        }
    )

@app.get("/health")
async def health_check():
    """
    Standard health check endpoint for monitoring and cloud deployment.
    """
    return {
        "status": "healthy",
        "rpc_connected": chain_client.rpc_connected,
        "chain_id": chain_client.chain_id,
        "version": "1.0.0"
    }

@app.get("/mcp/tool-schema")
async def get_mcp_schema():
    """
    Exposes the Model Context Protocol (MCP) tool schema for agentic platforms.
    """
    schema_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "mcp", "tool_schema.json")
    try:
        with open(schema_path, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="MCP tool schema file not found.")

@app.post("/skill/payment-safety-gate", response_model=PaymentSafetyGateResponse)
async def payment_safety_gate(payload: PaymentSafetyGateRequest):
    """
    The main payment safety evaluation endpoint called by AI Agents prior to initiating transactions.
    """
    address = payload.address
    chain = payload.chain
    intended_amount = payload.intended_amount

    logger.info(f"Evaluating payment safety for address {address} on chain {chain}...")

    # 1. Fetch live chain status via RPC & explorer
    wallet_info = chain_client.get_wallet_basic_info(address)
    age_days, transactions = chain_client.get_recent_transactions_and_age(address)
    wallet_info["wallet_age_days"] = age_days
    
    # 2. Query GoPlus for malicious cross-chain intelligence
    goplus_results = goplus_client.check_address_security(address)
    
    # 3. Analyze Gas fee requirements
    gas_info = chain_client.get_gas_analysis(address)

    # 4. Evaluate risk score and verdict
    risk_evaluation = risk_engine.evaluate(
        address=address,
        wallet_info=wallet_info,
        goplus_results=goplus_results,
        transactions=transactions,
        intended_amount=intended_amount
    )

    # 5. Compute reputation score
    reputation_score = reputation_engine.calculate_reputation(
        wallet_info=wallet_info,
        goplus_results=goplus_results
    )

    # 6. Format transaction sub-models
    formatted_transactions = [
        TransactionModel(
            hash=tx["hash"],
            from_address=tx["from"],
            to_address=tx["to"],
            value=tx["value"],
            timestamp=tx["timestamp"]
        ) for tx in transactions
    ]

    # Assemble and return response
    return PaymentSafetyGateResponse(
        address=address,
        verdict=risk_evaluation["verdict"],
        risk_score=risk_evaluation["risk_score"],
        confidence=risk_evaluation["confidence"],
        reason=risk_evaluation["reason"],
        agent_reputation=reputation_score,
        wallet_analysis=WalletAnalysisModel(
            wallet_age_days=wallet_info["wallet_age_days"],
            native_balance=wallet_info["native_balance"],
            transaction_count=wallet_info["transaction_count"],
            recent_transactions=formatted_transactions
        ),
        risk_factors=RiskFactorsModel(
            goplus_flag=risk_evaluation["risk_factors"]["goplus_flag"],
            blacklisted=risk_evaluation["risk_factors"]["blacklisted"],
            high_velocity=risk_evaluation["risk_factors"]["high_velocity"],
            flagged_contract_interaction=risk_evaluation["risk_factors"]["flagged_contract_interaction"]
        ),
        gas_analysis=GasAnalysisModel(
            gas_price_gwei=gas_info["gas_price_gwei"],
            estimated_cost_native=gas_info["estimated_cost_native"]
        ),
        recommended_action=risk_evaluation["recommended_action"]
    )
