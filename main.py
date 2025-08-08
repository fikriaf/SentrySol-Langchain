import json
import logging
from pydantic import BaseModel
from typing import Optional, List, Any, Dict
from supervisor import run_supervisor, run_supervisor_batch

# Setup logging
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


class AnalyzeInput(BaseModel):
    data: Any
    params: Optional[Dict[str, Any]] = None


class BatchInput(BaseModel):
    batch: List[Any]
    params: Optional[Dict[str, Any]] = None


def analyze(
    input_data: AnalyzeInput,
    param1: Optional[str] = None,
    param2: Optional[str] = None,
):
    params = input_data.params or {}
    if param1 is not None:
        params["param1"] = param1
    if param2 is not None:
        params["param2"] = param2
    input_payload = {
        "data": input_data.data,
        "params": params if params else None,
    }
    logging.info(f"Input diterima: {input_payload}")
    try:
        result = run_supervisor(input_payload)
        logging.info(f"Hasil analisa: {result}")
        if hasattr(result, "content"):
            content = result.content
        elif hasattr(result, "data"):
            content = result.data
        elif isinstance(result, str):
            content = result
        else:
            content = json.dumps(result)
        return json.loads(content)
    except Exception as e:
        logging.error(f"Error analisa: {str(e)}")
        raise Exception(str(e))


def batch(
    body: list,
    param1: Optional[str] = None,
    param2: Optional[str] = None,
):
    try:
        if not isinstance(body, list):
            raise ValueError("Input batch harus berupa list JSON.")
        params = {}
        if param1 is not None:
            params["param1"] = param1
        if param2 is not None:
            params["param2"] = param2
        batch_input = [
            {"data": item, "params": params if params else None} for item in body
        ]
        logging.info(f"Batch input diterima: {batch_input}")
        results = run_supervisor_batch(batch_input)
        logging.info(f"Hasil batch: {results}")
        return [json.loads(r) for r in results]
    except ValueError as e:
        raise Exception(f"Input batch error: {str(e)}")
    except Exception as e:
        logging.error(f"Error batch analisa: {str(e)}")
        raise


if __name__ == "__main__":
    # Contoh input test untuk supervisor
    # Untuk test transaction analysis
    test_input = AnalyzeInput(
        data={
            "wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas", # ← Tools bisa extract ini
            "transaction_hash": "some_tx_hash_here",  # ← Tools bisa extract ini
            "transaction_details": """
            From: DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas
            To: SomeOtherAddress
            Value: 0.00012 ETH
            """,
            "chain": "ethereum"
        },
        params={"analysis_type": "transaction_analysis"}
    )

    try:
        result = analyze(test_input, param1="tx_trace", param2="risk_check")
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")

# if __name__ == "__main__":
#     # Web3 Test Cases
    
#     # Test 1: Token Analysis (Solana USDC)
#     print("=== Test 1: Token Analysis ===")
#     usdc_token = AnalyzeInput(
#         data={"token_address": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "chain": "solana"}, 
#         params={"analysis_type": "token_screen"}
#     )
    
#     try:
#         result = analyze(usdc_token, param1="rugcheck_analysis", param2="solana")
#         print("Token Analysis Result:", result)
#     except Exception as e:
#         print(f"Token Analysis Error: {e}")
    
#     # Test 2: Wallet Risk Assessment
#     print("\n=== Test 2: Wallet Risk Assessment ===")
#     wallet_analysis = AnalyzeInput(
#         data={"wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas", "chain": "solana"}, 
#         params={"analysis_type": "wallet_screen"}
#     )
    
#     try:
#         result = analyze(wallet_analysis, param1="risk_assessment", param2="aml_check")
#         print("Wallet Risk Result:", result)
#     except Exception as e:
#         print(f"Wallet Analysis Error: {e}")
    
#     # Test 3: Transaction Tracing
#     print("\n=== Test 3: Transaction Tracing ===")
#     tx_trace = AnalyzeInput(
#         data={
#             "transaction_hash": "5VqJZ8fjhk8gn8MXvXvVcVvXvVcVvXvVcVvXvVcVvXvVcVvXvVcVvXvVcVvXvV",
#             "wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"
#         }, 
#         params={"analysis_type": "tx_trace"}
#     )
    
#     try:
#         result = analyze(tx_trace, param1="helius_trace", param2="deep_analysis")
#         print("Transaction Trace Result:", result)
#     except Exception as e:
#         print(f"Transaction Trace Error: {e}")
    
#     # Test 4: Batch Web3 Analysis
#     print("\n=== Test 4: Batch Web3 Analysis ===")
#     web3_batch = [
#         {"token_address": "So11111111111111111111111111111111111111112", "type": "token"},  # SOL
#         {"wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas", "type": "wallet"},
#         {"token_address": "mSoLzYCxHdYgdzU16g5QSh3i5K3z3KZK7ytfqcJm7So", "type": "token"}  # mSOL
#     ]
    
#     try:
#         batch_results = batch(web3_batch, param1="web3_batch", param2="comprehensive")
#         print("Batch Web3 Results:", batch_results)
#     except Exception as e:
#         print(f"Batch Web3 Error: {e}")
    
#     # Test 5: Suspicious Activity Detection
#     print("\n=== Test 5: Suspicious Activity Detection ===")
#     suspicious_analysis = AnalyzeInput(
#         data={
#             "wallet_address": "suspicious_wallet_here", 
#             "recent_txs": ["tx1", "tx2", "tx3"],
#             "token_interactions": ["token1", "token2"]
#         }, 
#         params={"analysis_type": "fraud_detection", "sensitivity": "high"}
#     )
    
#     try:
#         result = analyze(suspicious_analysis, param1="fraud_detect", param2="ml_analysis")
#         print("Fraud Detection Result:", result)
#     except Exception as e:
#         print(f"Fraud Detection Error: {e}")