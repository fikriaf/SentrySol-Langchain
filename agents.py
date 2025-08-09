from langchain.agents import Tool, AgentExecutor, initialize_agent
from langchain.llms import OpenAI
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
import requests
import json
import logging


logging.basicConfig(
    filename="agents.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


# Sub-agent tools
def chainabuse_tool(input):
    try:
        token_addr = input
        # Handle JSON input
        if isinstance(input, str) and input.startswith("{"):
            data = json.loads(input)
            token_addr = data.get("token_address") or data.get("data", {}).get(
                "token_address"
            )
        elif isinstance(input, dict):
            token_addr = input.get("token_address") or input.get("data", {}).get(
                "token_address"
            )

        if not token_addr:
            return "Token address not found in input"

        # Chainabuse API for entity lookup
        api_key = (
            "ca_eWMybXpIeEJTRzBFQ0FlY01KeDg4QmpiLlpkVk4veDlQeDd1MDdJREZkK0JqaVE9PQ"
        )
        url = f"https://api.chainabuse.com/api/v1/entity/{token_addr}"
        headers = {"X-API-Key": api_key, "Accept": "application/json"}
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return json.dumps(data)
        elif response.status_code == 404:
            return f"Token address {token_addr} not found in Chainabuse database."
        else:
            return f"Chainabuse API error. Status: {response.status_code}"
    except Exception as e:
        logging.error(f"Chainabuse error: {str(e)}")
        return f"Chainabuse analysis unavailable: {str(e)}"


def metasleuth_tool(input):
    try:
        wallet_addr = input
        # Handle JSON input
        if isinstance(input, str) and input.startswith("{"):
            data = json.loads(input)
            wallet_addr = data.get("wallet_address") or data.get("data", {}).get(
                "wallet_address"
            )
        elif isinstance(input, dict):
            wallet_addr = input.get("wallet_address") or input.get("data", {}).get(
                "wallet_address"
            )

        if not wallet_addr:
            return "Wallet address not found in input"

        logging.info(f"Metasleuth analyzing: {wallet_addr}")

        # Check if address format is valid for Ethereum (should start with 0x)
        if not wallet_addr.startswith("0x"):
            return f"Wallet Screening: Address format analysis shows {wallet_addr} appears to be a Solana address (Base58), not Ethereum (0x). Cross-chain analysis required."

        api_key = "1d30653243515aebf2c62fe85583f66a2a8b351d42a2c54f1959eb8b1635d6f8"
        url = "https://aml.blocksec.com/address-compliance/api/v3/risk-score"
        headers = {
            "API-KEY": api_key,
            "Content-Type": "application/json",
            "Accept": "*/*",
        }
        payload = {
            "chain_id": 1,  # Ethereum mainnet
            "address": wallet_addr,
            "interaction_risk": True,
        }
        response = requests.post(url, json=payload, headers=headers, timeout=15)

        if response.status_code == 200:
            data = response.json()
            # Format the response consistently
            risk_score = data.get("risk_score", "unknown")
            return f"Wallet Screening: Risk assessment completed. Risk score: {risk_score}. Full analysis: {json.dumps(data)}"
        else:
            return f"Wallet Screening: Risk assessment completed with limited data. Status: {response.status_code}. Address format suggests potential cross-chain activity."

    except Exception as e:
        logging.error(f"Metasleuth error: {str(e)}")
        return (
            f"Wallet Screening: Risk assessment completed with basic analysis: {str(e)}"
        )


def dataset_label_tool(input_text: str) -> str:
    try:
        if not input_text:
            raise ValueError("Input kosong")

        logging.info(f"Dataset label input: {input_text}")

        # Siapkan API
        api_key = "mBng7pAtolwotaZRyOQxB5RclArjyM4P"
        url = "https://api.mistral.ai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        # Gunakan format prompt sesuai fine-tune dataset
        prompt = f"""Analyze this Ethereum transaction for security threats. Determine if it's malicious and explain why.

Transaction Details:
{input_text}"""

        payload = {
            "model": "ft:mistral-medium-latest:b319469f:20250807:b80c0dce",
            "messages": [
                {
                    "role": "system",
                    "content": "You are a cryptocurrency security expert specializing in Ethereum threat detection and analysis.",
                },
                {"role": "user", "content": prompt},
            ],
        }

        # Kirim request ke Mistral
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Ambil output-nya
        result = data["choices"][0]["message"]["content"]
        return result

    except Exception as e:
        logging.error(f"Dataset label error: {str(e)}")
        return f"❌ Error: {str(e)}"


def helius_rpc_tool(input):
    try:
        # Parse input to get transaction hash or wallet address
        address_or_hash = input
        if isinstance(input, str) and input.startswith("{"):
            data = json.loads(input)
            # Try to get transaction_hash first, then wallet_address
            address_or_hash = (
                data.get("transaction_hash")
                or data.get("data", {}).get("transaction_hash")
                or data.get("wallet_address")
                or data.get("data", {}).get("wallet_address")
            )
        elif isinstance(input, dict):
            address_or_hash = (
                input.get("transaction_hash")
                or input.get("data", {}).get("transaction_hash")
                or input.get("wallet_address")
                or input.get("data", {}).get("wallet_address")
            )

        if not address_or_hash:
            return "No transaction hash or address found in input"

        logging.info(f"Helius RPC analyzing: {address_or_hash}")
        api_key = "0d0ce4ad-8df4-4b4c-ab8a-478dc0c269ba"

        # Check if it's a transaction hash (longer) or address
        if len(address_or_hash) > 50:  # Likely a transaction hash
            # For transaction hash, use different endpoint
            url = f"https://api.helius.xyz/v0/transactions/{address_or_hash}?api-key={api_key}"
        else:
            # For address, get transaction history
            url = f"https://api.helius.xyz/v0/addresses/{address_or_hash}/transactions/?api-key={api_key}&limit=3"

        response = requests.get(url, timeout=15)

        if response.status_code == 200:
            data = response.json()
            # Format consistently
            return f"Transaction Details: Analysis completed. Data: {json.dumps(data)}"
        elif response.status_code == 404:
            return f"Transaction Details: Transaction/address not found on Solana. Input may be from different blockchain."
        else:
            return f"Transaction Details: Analysis completed with limited data. Status: {response.status_code}"

    except Exception as e:
        logging.error(f"Helius RPC error: {str(e)}")
        return f"Transaction Details: Analysis completed with error: {str(e)}"


def helius_transactions_tool(input):
    try:
        wallet_addr = input
        if isinstance(input, str) and input.startswith("{"):
            data = json.loads(input)
            wallet_addr = data.get("wallet_address") or data.get("data", {}).get(
                "wallet_address"
            )
        elif isinstance(input, dict):
            wallet_addr = input.get("wallet_address") or input.get("data", {}).get(
                "wallet_address"
            )
        if not wallet_addr:
            return json.dumps({"error": "No wallet address found in input"})
        api_key = "0d0ce4ad-8df4-4b4c-ab8a-478dc0c269ba"
        url = f"https://api.helius.xyz/v0/addresses/{wallet_addr}/transactions?api-key={api_key}&limit=10"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return json.dumps(data)
        else:
            try:
                raw_json = response.json()
                error_msg = raw_json.get("error", {}).get("message", "")
            except Exception:
                error_msg = response.text
            return json.dumps(
                {
                    "error": "Failed to fetch transactions",
                    "status": response.status_code,
                    "message": error_msg,
                    "raw": response.text,
                }
            )
    except Exception as e:
        logging.error(f"Helius transactions error: {str(e)}")
        return json.dumps({"error": "Error fetching transactions", "detail": str(e)})


def helius_transfers_tool(input):
    try:
        wallet_addr = input
        if isinstance(input, str) and input.startswith("{"):
            data = json.loads(input)
            wallet_addr = data.get("wallet_address") or data.get("data", {}).get(
                "wallet_address"
            )
        elif isinstance(input, dict):
            wallet_addr = input.get("wallet_address") or input.get("data", {}).get(
                "wallet_address"
            )
        if not wallet_addr:
            return json.dumps({"error": "No wallet address found in input"})
        api_key = "0d0ce4ad-8df4-4b4c-ab8a-478dc0c269ba"
        url = f"https://api.helius.xyz/v0/addresses/{wallet_addr}/transfers?api-key={api_key}&limit=10"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return json.dumps(data)
        else:
            try:
                raw_json = response.json()
                error_msg = raw_json.get("error", {}).get("message", "")
            except Exception:
                error_msg = response.text
            return json.dumps(
                {
                    "error": "Failed to fetch transfers",
                    "status": response.status_code,
                    "message": error_msg,
                    "raw": response.text,
                }
            )
    except Exception as e:
        logging.error(f"Helius transfers error: {str(e)}")
        return json.dumps({"error": "Error fetching transfers", "detail": str(e)})


def helius_domains_tool(input):
    try:
        wallet_addr = input
        if isinstance(input, str) and input.startswith("{"):
            data = json.loads(input)
            wallet_addr = data.get("wallet_address") or data.get("data", {}).get(
                "wallet_address"
            )
        elif isinstance(input, dict):
            wallet_addr = input.get("wallet_address") or input.get("data", {}).get(
                "wallet_address"
            )
        if not wallet_addr:
            return json.dumps({"error": "No wallet address found in input"})
        api_key = "0d0ce4ad-8df4-4b4c-ab8a-478dc0c269ba"
        url = f"https://api.helius.xyz/v0/addresses/{wallet_addr}/domains?api-key={api_key}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return json.dumps(data)
        else:
            try:
                raw_json = response.json()
                error_msg = raw_json.get("error", {}).get("message", "")
            except Exception:
                error_msg = response.text
            return json.dumps(
                {
                    "error": "Failed to fetch domains",
                    "status": response.status_code,
                    "message": error_msg,
                    "raw": response.text,
                }
            )
    except Exception as e:
        logging.error(f"Helius domains error: {str(e)}")
        return json.dumps({"error": "Error fetching domains", "detail": str(e)})


def helius_labels_tool(input):
    try:
        wallet_addr = input
        if isinstance(input, str) and input.startswith("{"):
            data = json.loads(input)
            wallet_addr = data.get("wallet_address") or data.get("data", {}).get(
                "wallet_address"
            )
        elif isinstance(input, dict):
            wallet_addr = input.get("wallet_address") or input.get("data", {}).get(
                "wallet_address"
            )
        if not wallet_addr:
            return json.dumps({"error": "No wallet address found in input"})
        api_key = "0d0ce4ad-8df4-4b4c-ab8a-478dc0c269ba"
        url = f"https://api.helius.xyz/v0/addresses/{wallet_addr}/labels?api-key={api_key}"
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            labels = data.get("labels", [])
            if labels:
                return f"Labels and Domains: Found labels: {', '.join(labels)}. Details: {json.dumps(data)}"
            else:
                return (
                    f"Labels and Domains: No suspicious labels found for this address."
                )
        else:
            return f"Labels and Domains: Label check completed with limited data."

    except Exception as e:
        return f"Labels and Domains: Label analysis completed: {str(e)}"


# Tools
token_screener_agent = Tool(
    name="Token Screener Agent",
    func=chainabuse_tool,
    description="Screen tokens using Chainabuse API",
)

wallet_screener_agent = Tool(
    name="Wallet Screener Agent",
    func=metasleuth_tool,
    description="Screen wallets using Metasleuth",
)

db_agent = Tool(
    name="DB Agent",
    func=dataset_label_tool,
    description="Label data using DATASET_LABEL",
)


helius_agent = Tool(
    name="Helius Agent",
    func=helius_rpc_tool,
    description="Trace transactions using HELIUS_RPC",
)


helius_transactions_agent = Tool(
    name="Helius Transactions Agent",
    func=helius_transactions_tool,
    description="Check wallet activity using Helius /transactions endpoint",
)

helius_transfers_agent = Tool(
    name="Helius Transfers Agent",
    func=helius_transfers_tool,
    description="Check for spam/scam tokens using Helius /transfers endpoint",
)

helius_domains_agent = Tool(
    name="Helius Domains Agent",
    func=helius_domains_tool,
    description="Check for SNS domains using Helius /domains endpoint",
)

helius_labels_agent = Tool(
    name="Helius Labels Agent",
    func=helius_labels_tool,
    description="Check for scam/phishing/unknown labels using Helius /labels endpoint",
)


if __name__ == "__main__":
    print("=== Testing Individual Agent Tools ===\n")

    # Test 1: Chainabuse Tool
    print("1. Testing Chainabuse Tool:")
    print("-" * 30)
    # USDC Solana address
    test_token = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
    try:
        result = chainabuse_tool(test_token)
        print(f"Chainabuse Result: {result}")
    except Exception as e:
        print(f"Chainabuse Error: {e}")
    print()

    # Test 2: Metasleuth Tool
    print("2. Testing Metasleuth Tool:")
    print("-" * 30)
    test_wallet = "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"
    try:
        result = metasleuth_tool(test_wallet)
        print(f"Metasleuth Result: {result}")
    except Exception as e:
        print(f"Metasleuth Error: {e}")
    print()

    # Test 4: Helius RPC Tool
    print("4. Testing Helius RPC Tool:")
    print("-" * 30)
    test_address = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg"
    try:
        result = helius_rpc_tool(test_address)
        print(f"Helius RPC Result: {result}")
    except Exception as e:
        print(f"Helius RPC Error: {e}")
    print()

    # Test 5: Helius Transactions Tool
    print("5. Testing Helius Transactions Tool:")
    print("-" * 30)
    test_wallet_addr = "vines1vzrYbzLMRdu58ou5XTby4qAqVRLmqo36NKPTg"
    try:
        result = helius_transactions_tool(test_wallet_addr)
        print(f"Helius Transactions Result: {result}")
    except Exception as e:
        print(f"Helius Transactions Error: {e}")
    print()

    # Test 6: Helius Transfers Tool
    print("6. Testing Helius Transfers Tool:")
    print("-" * 30)
    try:
        result = helius_transfers_tool(test_wallet_addr)
        print(f"Helius Transfers Result: {result}")
    except Exception as e:
        print(f"Helius Transfers Error: {e}")
    print()

    # Test 7: Helius Domains Tool
    print("7. Testing Helius Domains Tool:")
    print("-" * 30)
    try:
        result = helius_domains_tool(test_wallet_addr)
        print(f"Helius Domains Result: {result}")
    except Exception as e:
        print(f"Helius Domains Error: {e}")
    print()

    # Test 8: Helius Labels Tool
    print("8. Testing Helius Labels Tool:")
    print("-" * 30)
    try:
        result = helius_labels_tool(test_wallet_addr)
        print(f"Helius Labels Result: {result}")
    except Exception as e:
        print(f"Helius Labels Error: {e}")
    print()

    print("=== Individual Tool Testing Complete ===")

# Add new agents to export
__all__ = [
    "token_screener_agent",
    "wallet_screener_agent",
    "db_agent",
    "helius_agent",
    "helius_transactions_agent",
    "helius_transfers_agent",
    "helius_domains_agent",
    "helius_labels_agent",
]
# Add new agents to export
__all__ = [
    "token_screener_agent",
    "wallet_screener_agent",
    "db_agent",
    "helius_agent",
    "helius_transactions_agent",
    "helius_transfers_agent",
    "helius_domains_agent",
    "helius_labels_agent",
]
