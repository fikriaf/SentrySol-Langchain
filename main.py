import json
import logging
from pydantic import BaseModel
from typing import Optional, Any, Dict
from supervisor import run_supervisor
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
import uvicorn

from agents import (
    helius_transactions_agent,
    helius_transfers_agent,
    helius_domains_agent,
    helius_labels_agent,
)

# Setup logging
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


class AnalyzeInput(BaseModel):
    data: Any


def analyze(
    input_data: AnalyzeInput,
    param1: Optional[str] = None,
    param2: Optional[str] = None,
):
    # Build payload sesuai format yang diminta
    data = input_data.data or {}
    payload = {
        "wallet_address": data.get("wallet_address", None),
        "transaction_hash": data.get("transaction_hash", None),
        "transaction_details": data.get("transaction_details", None),
        "chain": data.get("chain", None),
    }

    # Extract direct_tool_execution parameter from input data
    direct_tool_execution = data.get("direct_tool_execution", True)  # Default to True

    logging.info(
        f"Input diterima: {payload}, direct_tool_execution: {direct_tool_execution}"
    )
    try:
        result = run_supervisor(
            payload, auth_token=None, direct_tool_execution=direct_tool_execution
        )
        logging.info(f"Hasil analisa: {result}")

        # Parse JSON string result from supervisor
        if isinstance(result, str):
            parsed_result = json.loads(result)
        elif hasattr(result, "content"):
            parsed_result = json.loads(result.content)
        elif hasattr(result, "data"):
            parsed_result = json.loads(result.data)
        else:
            parsed_result = result

        # Clean up the analysis fields for better presentation
        if "analysis" in parsed_result:
            analysis = parsed_result["analysis"]

            # Clean up wallet_screening
            if (
                analysis.get("wallet_screening")
                and "Sender address analysis:" in analysis["wallet_screening"]
            ):
                analysis["wallet_screening"] = analysis["wallet_screening"].replace(
                    "Sender address analysis: ", ""
                )

            # Clean up transaction_details
            if (
                analysis.get("transaction_details")
                and "Transaction Details:" in analysis["transaction_details"]
            ):
                analysis["transaction_details"] = analysis[
                    "transaction_details"
                ].replace("Transaction Details: ", "")

            # Clean up labels_and_domains
            if (
                analysis.get("labels_and_domains")
                and "Labels and Domains:" in analysis["labels_and_domains"]
            ):
                analysis["labels_and_domains"] = analysis["labels_and_domains"].replace(
                    "Labels and Domains: ", ""
                )

            # Parse token_transfers if it's JSON error string
            if (
                analysis.get("token_transfers")
                and isinstance(analysis["token_transfers"], str)
                and analysis["token_transfers"].startswith("{")
            ):
                try:
                    token_error = json.loads(analysis["token_transfers"])
                    if "error" in token_error:
                        analysis["token_transfers"] = (
                            f"Token transfer analysis failed: {token_error.get('message', 'API error')}"
                        )
                except:
                    pass

            # Truncate conclusion if too long
            if analysis.get("conclusion") and len(analysis["conclusion"]) > 200:
                analysis["conclusion"] = (
                    analysis["conclusion"][:200] + "... (truncated)"
                )

            # Add professional formatting for security scores
            if "security_scores" in analysis:
                scores = analysis["security_scores"]

                # Format scores for better readability
                analysis["security_summary"] = {
                    "overall_grade": analysis.get("professional_summary", {})
                    .get("key_metrics", {})
                    .get("security_grade", "N/A"),
                    "risk_level": scores.get("risk_level", "UNKNOWN"),
                    "confidence": f"{scores.get('confidence_level', 0)}%",
                    "security_score": f"{scores.get('overall_security_score', 0)}/100",
                }

                # Add quick metrics overview
                analysis["quick_metrics"] = {
                    "wallet_score": f"{scores.get('wallet_security_score', 0)}/100",
                    "transaction_score": f"{scores.get('transaction_security_score', 0)}/100",
                    "token_score": f"{scores.get('token_security_score', 0)}/100",
                    "domain_score": f"{scores.get('domain_security_score', 0)}/100",
                    "positive_indicators": len(scores.get("positive_indicators", [])),
                    "threat_indicators": len(scores.get("threat_indicators", [])),
                }

        return parsed_result

    except json.JSONDecodeError as e:
        logging.error(f"JSON parsing error: {str(e)}")
        return {
            "status": "error",
            "error": f"Invalid JSON response: {str(e)}",
            "raw_result": result if isinstance(result, str) else str(result),
        }
    except Exception as e:
        logging.error(f"Error analisa: {str(e)}")
        return {"status": "error", "error": str(e), "input": payload}


app = FastAPI()


@app.post("/analyze")
async def analyze_endpoint(
    input_data: AnalyzeInput,
    param1: Optional[str] = Query(None),
    param2: Optional[str] = Query(None),
    direct_tool_execution: Optional[bool] = Query(
        True,
        description="Use direct tool execution (True) or agent-based execution (False)",
    ),
):
    try:
        # Add direct_tool_execution to input data if provided as query parameter
        if hasattr(input_data, "data") and input_data.data:
            input_data.data["direct_tool_execution"] = direct_tool_execution
        else:
            input_data.data = {"direct_tool_execution": direct_tool_execution}

        result = analyze(input_data, param1, param2)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/transactions")
async def get_transactions(wallet_address: str = Query(...)):
    try:
        result = helius_transactions_agent.run({"wallet_address": wallet_address})
        try:
            return JSONResponse(content=json.loads(result))
        except Exception:
            return JSONResponse(content={"error": "Invalid JSON", "raw": result})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/transfers")
async def get_transfers(wallet_address: str = Query(...)):
    try:
        result = helius_transfers_agent.run({"wallet_address": wallet_address})
        try:
            return JSONResponse(content=json.loads(result))
        except Exception:
            return JSONResponse(content={"error": "Invalid JSON", "raw": result})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/domains")
async def get_domains(wallet_address: str = Query(...)):
    try:
        result = helius_domains_agent.run({"wallet_address": wallet_address})
        try:
            return JSONResponse(content=json.loads(result))
        except Exception:
            return JSONResponse(content={"error": "Invalid JSON", "raw": result})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/labels")
async def get_labels(wallet_address: str = Query(...)):
    try:
        result = helius_labels_agent.run({"wallet_address": wallet_address})
        try:
            return JSONResponse(content=json.loads(result))
        except Exception:
            return JSONResponse(content={"error": "Invalid JSON", "raw": result})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/pre-transaction")
async def pre_transaction_analysis(
    input_data: AnalyzeInput,
    direct_tool_execution: Optional[bool] = Query(
        True,
        description="Use direct tool execution (True) or agent-based execution (False)",
    ),
):
    """
    Analyze transaction data before execution for security screening
    """
    try:
        # Ensure the analysis is marked as pre-transaction
        if hasattr(input_data, "data") and input_data.data:
            input_data.data["analysis_type"] = "pre_transaction"
            input_data.data["direct_tool_execution"] = direct_tool_execution
        else:
            input_data.data = {
                "analysis_type": "pre_transaction",
                "direct_tool_execution": direct_tool_execution,
            }

        result = analyze(input_data)

        # Add pre-transaction specific recommendations
        if "analysis" in result:
            if "recommendations" not in result["analysis"]:
                result["analysis"]["recommendations"] = []

            # Add pre-transaction specific recommendations
            pre_tx_recommendations = []
            if (
                result.get("analysis", {}).get("security_scores", {}).get("risk_level")
                == "HIGH"
            ):
                pre_tx_recommendations.extend(
                    [
                        "🚫 DO NOT PROCEED with this transaction",
                        "⚠️ High risk detected - manual review required",
                    ]
                )
            elif (
                result.get("analysis", {}).get("security_scores", {}).get("risk_level")
                == "CRITICAL"
            ):
                pre_tx_recommendations.extend(
                    [
                        "🛑 CRITICAL RISK - BLOCK TRANSACTION IMMEDIATELY",
                        "🔒 Contact security team before any action",
                    ]
                )
            else:
                pre_tx_recommendations.extend(
                    [
                        "✅ Transaction appears safe to proceed",
                        "📋 Continue with standard security protocols",
                    ]
                )

            result["analysis"]["pre_transaction_recommendations"] = (
                pre_tx_recommendations
            )

        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/check-wallet")
async def check_wallet_only(
    wallet_address: str = Query(..., description="Wallet address to analyze"),
    chain: Optional[str] = Query(
        "solana", description="Blockchain network (solana, ethereum, etc.)"
    ),
    direct_tool_execution: Optional[bool] = Query(
        True,
        description="Use direct tool execution (True) or agent-based execution (False)",
    ),
):
    """
    Check wallet security status only (no transaction analysis)
    """
    try:
        # Create input data for wallet-only analysis
        wallet_input = AnalyzeInput(
            data={
                "wallet_address": wallet_address,
                "chain": chain,
                "analysis_type": "wallet_only",
                "direct_tool_execution": direct_tool_execution,
            }
        )

        result = analyze(wallet_input)

        # Filter result to focus on wallet-specific information
        if "analysis" in result:
            wallet_focused_result = {
                "status": result.get("status"),
                "wallet_address": wallet_address,
                "chain": chain,
                "wallet_analysis": {
                    "wallet_screening": result["analysis"].get("wallet_screening"),
                    "labels_and_domains": result["analysis"].get("labels_and_domains"),
                    "security_scores": {
                        "wallet_security_score": result["analysis"]
                        .get("security_scores", {})
                        .get("wallet_security_score"),
                        "domain_security_score": result["analysis"]
                        .get("security_scores", {})
                        .get("domain_security_score"),
                        "overall_security_score": result["analysis"]
                        .get("security_scores", {})
                        .get("overall_security_score"),
                        "risk_level": result["analysis"]
                        .get("security_scores", {})
                        .get("risk_level"),
                        "confidence_level": result["analysis"]
                        .get("security_scores", {})
                        .get("confidence_level"),
                    },
                    "wallet_recommendations": [
                        rec
                        for rec in result["analysis"].get("recommendations", [])
                        if "wallet" in rec.lower() or "address" in rec.lower()
                    ],
                    "verification_status": result["analysis"].get(
                        "verification_status"
                    ),
                    "professional_summary": result["analysis"].get(
                        "professional_summary"
                    ),
                },
                "meta": result.get("meta", {}),
                "analysis_timestamp": result["analysis"].get("analysis_timestamp"),
            }

            # Add wallet-specific summary
            wallet_focused_result["wallet_summary"] = {
                "is_safe": result["analysis"]
                .get("security_scores", {})
                .get("risk_level")
                in ["VERY_LOW", "LOW"],
                "risk_level": result["analysis"]
                .get("security_scores", {})
                .get("risk_level"),
                "confidence": f"{result['analysis'].get('security_scores', {}).get('confidence_level', 0)}%",
                "recommendation": "APPROVED"
                if result["analysis"].get("security_scores", {}).get("risk_level")
                in ["VERY_LOW", "LOW"]
                else "CAUTION"
                if result["analysis"].get("security_scores", {}).get("risk_level")
                == "MODERATE"
                else "REJECTED",
            }

            return JSONResponse(content=wallet_focused_result)
        else:
            return JSONResponse(content=result)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    # Contoh input test untuk supervisor dengan professional scoring
    # Untuk test transaction analysis
    test_input = AnalyzeInput(
        data={
            "wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas",
            "transaction_hash": "0x5e2b8e2e4f8c8a1e8b8e2e4f8c8a1e8b8e2e4f8c8a1e8b8e2e4f8c8a1e8b8e2e",
            "transaction_details": """
            From: DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas
            To: BQjmJq8EVptiTn5XbWHDA6FyeXC6qkijAjN6UojED1Mf
            Value: 0.00012 ETH
            """,
            "chain": "solana",  # Changed to solana since addresses are Solana format
            "direct_tool_execution": False,  # Test agent-based execution
        }
    )

    try:
        result = analyze(test_input, param1="tx_trace", param2="risk_check")
        print("=== PROFESSIONAL ANALYSIS RESULT WITH SCORING ===")

        # Display key metrics first
        if "analysis" in result and "security_summary" in result["analysis"]:
            print("\n🎯 SECURITY SUMMARY:")
            summary = result["analysis"]["security_summary"]
            print(f"   Grade: {summary.get('overall_grade', 'N/A')}")
            print(f"   Risk Level: {summary.get('risk_level', 'N/A')}")
            print(f"   Confidence: {summary.get('confidence', 'N/A')}")
            print(f"   Security Score: {summary.get('security_score', 'N/A')}")

        if "analysis" in result and "quick_metrics" in result["analysis"]:
            print("\n📊 DETAILED SCORES:")
            metrics = result["analysis"]["quick_metrics"]
            print(f"   Wallet Security: {metrics.get('wallet_score', 'N/A')}")
            print(f"   Transaction Security: {metrics.get('transaction_score', 'N/A')}")
            print(f"   Token Security: {metrics.get('token_score', 'N/A')}")
            print(f"   Domain Security: {metrics.get('domain_score', 'N/A')}")
            print(f"   Positive Signals: {metrics.get('positive_indicators', 0)}")
            print(f"   Risk Signals: {metrics.get('threat_indicators', 0)}")

        print("\n📋 FULL ANALYSIS:")
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error: {e}")

    # Uncomment below to run FastAPI server
    # uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

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
#         params={"analysis_type": "fraud_detection", "sensitivity": "high"}
#     )

#     try:
#         result = analyze(suspicious_analysis, param1="fraud_detect", param2="ml_analysis")
#         print("Fraud Detection Result:", result)
#     except Exception as e:
#         print(f"Fraud Detection Error: {e}")
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
