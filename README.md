# Pharos RiskGate – Agent Payment Safety Skill

Pharos RiskGate is a production-ready, reusable AI Agent Skill built for the **Pharos Skill-to-Agent Dual Cascade Hackathon (Phase 1)**. 

RiskGate acts as a security verification layer that autonomous AI agents call before executing payments. It evaluates the destination wallet or contract, runs real-time EVM RPC scans on the Pharos Testnet, queries the GoPlus Security network, and returns a transaction verdict: `ALLOW`, `FLAG`, or `BLOCK` along with detailed risk intelligence and trustworthiness scoring.

---

## 🔴 The Problem

As the AI Agent Economy grows, autonomous agents will routinely send funds, pay invoices, interact with smart contracts, and trade assets without human supervision. However:
* **No Transaction Validation**: AI agents currently lack a dedicated, programmatic transaction safety gate.
* **Fraud & Phishing**: If an agent is fed a malicious recipient address (via prompt injection, hacked data streams, or hijacked memory), it will blindly execute the transaction, leading to permanent loss of treasury funds.
* **Lack of Context**: Standard blockchain RPC nodes only return raw state (balances, nonces) and cannot tell whether a wallet is a known scam address, a newly created burner wallet, or a sanctioned account.

---

## 🟢 The Solution

**Pharos RiskGate** provides a security validation API that agents can query before initiating a payment.

```
Agent A (Wants to Pay) 
   │
   ▼
Pharos RiskGate API ────────► 1. Web3 RPC Scan (Nonce, Code, Balance)
   │                         2. GoPlus AML & Threat Registry Query
   │                         3. Risk Engine (Normalized Weight Scoring)
   │                         4. Reputation Engine (0-100 Trust Score)
   ▼
Verdict (ALLOW | FLAG | BLOCK)
   │
   ▼
Agent A Decides: Proceed / Request Human / Halt
```

---

## ⚡ Why It Matters

* **Protects Agent-to-Agent Payments**: Establishes a zero-trust model for autonomous commerce.
* **Reduces Fraud Risk**: Instantly stops transactions destined for known malicious accounts or high-risk contracts.
* **Supports Autonomous Workflows**: Allows agents to confidently automate payments up to specific risk and reputation thresholds.
* **Pharos Vision Alignment**: Integrates with the Pharos Network's focus on high-throughput, institutional-grade decentralized infrastructure.

---

## 🏗️ Technical Architecture

RiskGate executes a multi-stage security pipeline:

1. **Address Validation**: Validates and checksums the EVM address using `web3.py`.
2. **On-Chain Scan (Pharos Testnet RPC)**: Fetches the target address's native balance (in `PHRS`), total transaction count (nonce), and bytecode (to identify if the address is a contract).
3. **GoPlus Cross-Chain Scan**: Since Pharos Testnet is a newer network, RiskGate queries the official GoPlus Security API across major indexed reference networks (Ethereum, BNB Chain, and Polygon) to check if the address is flagged for scams, phishing, mixer usage, or global sanctions.
4. **Explorer Scraper (SocialScan/Pharosscan)**: Queries Blockscout-compatible explorer APIs to retrieve the last 20 transaction details and estimate the wallet's activity age.
5. **Risk Engine**: Applies weighted deductions and computes a normalized score (0-100) to output a security verdict.
6. **Reputation Engine**: Generates a 0-100 trustworthiness score to help agents decide whether to whitelist the recipient.
7. **Decision Explanation**: Returns a structured JSON payload with human-readable rationale.

---

## 🛠️ MCP Integration

Pharos RiskGate is compatible with the **Model Context Protocol (MCP)**. Autonomous agents (like Claude Desktop, Windsurf, or custom LangChain/LlamaIndex frameworks) can import the tool schema to call RiskGate natively.

* **Schema Path**: `mcp/tool_schema.json`
* **Tool Name**: `payment_safety_gate`
* **Input Schema**:
  ```json
  {
    "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "chain": "pharos-testnet",
    "intended_amount": "10.0"
  }
  ```

---

## 🔒 Security Properties (Read-Only)

RiskGate enforces a strict security posture. It is a **read-only** infrastructure service:
* **No Private Keys**: RiskGate does not require, accept, or store private keys, seed phrases, or credentials.
* **No Signing Capability**: It cannot sign transactions or interact with user wallets.
* **No Custody**: It never holds, locks, or moves funds.
* **Strict Sanitization**: All incoming inputs are validated and sanitized to prevent injection attacks.

---

## ⚙️ Core API Specification

### Endpoint: `POST /skill/payment-safety-gate`

#### Request Payload
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "chain": "pharos-testnet",
  "intended_amount": "50.0"
}
```

#### Response Payload
```json
{
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "verdict": "ALLOW",
  "risk_score": 12,
  "confidence": 95,
  "reason": "No active risk factors identified. Wallet exhibits standard on-chain behavior.",
  "agent_reputation": 95,
  "wallet_analysis": {
    "wallet_age_days": 120,
    "native_balance": "250.5000",
    "transaction_count": 142,
    "recent_transactions": [
      {
        "hash": "0x4e6e665ba...",
        "from": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "to": "0xrecipientaddress...",
        "value": "1.5000 PHRS",
        "timestamp": "2026-06-16T12:00:00.000000Z"
      }
    ]
  },
  "risk_factors": {
    "goplus_flag": false,
    "blacklisted": false,
    "high_velocity": false,
    "flagged_contract_interaction": false
  },
  "gas_analysis": {
    "gas_price_gwei": "1.5000",
    "estimated_cost_native": "0.00003150 PHRS"
  },
  "recommended_action": "Safe to proceed. Low risk profile detected."
}
```

---

## 🚀 Deployment Instructions

### 1. Local Setup
Ensure you have Python 3.11 installed.

```bash
# Clone the repository
git clone <your-repo-url>
cd agent-payment-safety-skill

# Install dependencies
pip install -r requirements.txt

# Copy and update the environment settings
cp .env.example .env

# Run the FastAPI server
uvicorn app.main:app --reload
```
Open `http://localhost:8000` in your browser to access the developer playground.

### 2. Docker & Docker Compose
```bash
# Build and spin up the service
docker-compose up --build -d

# Check logs
docker-compose logs -f
```

### 3. Deploy to Railway
1. Sign up on [Railway.app](https://railway.app).
2. Click **New Project** -> **Deploy from GitHub repository**.
3. Select this repository.
4. Add the following environment variables in the settings tab:
   * `PHAROS_RPC_URL` = `https://testnet.dplabs-internal.com`
   * `PHAROS_CHAIN_ID` = `688688`
   * `PHAROS_EXPLORER_URL` = `https://pharos-testnet.socialscan.io`
   * `PHAROS_EXPLORER_FALLBACK_URL` = `https://testnet.pharosscan.xyz`
   * `GOPLUS_API_KEY` = (Optional)
   * `GOPLUS_API_SECRET` = (Optional)
5. Railway will automatically build the service using the `Dockerfile` and expose it.

### 4. Deploy to Render
1. Sign up on [Render.com](https://render.com).
2. Select **New** -> **Web Service**.
3. Link your GitHub repository.
4. Set the **Build Command** to: `pip install -r requirements.txt`
5. Set the **Start Command** to: `python -m uvicorn app.main:app --host 0.0.0.0 --port $PORT`
6. Add the environment variables under the **Environment** tab.
7. Click **Deploy Web Service**.

---

## 🔮 Future Extensions

RiskGate can be directly integrated into various AI agent architectures:
* **Treasury Agents**: Validating high-volume DAO allocation updates and protocol rebalances.
* **Payroll Agents**: Automating recurring developer compensations on-chain while cross-verifying team member wallets.
* **DAO Agents**: Filtering proposed proposal recipient addresses before queuing execution transactions.
* **Marketplace & Commerce Agents**: Acting as an automated checkout safety guard for e-commerce agents purchasing real-world items using native token payments.
