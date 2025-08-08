import json, re
import logging
from langchain_mistralai.chat_models import ChatMistralAI
from langchain.agents import initialize_agent
from agents import token_screener_agent, wallet_screener_agent, db_agent, helius_agent
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(
    filename="supervisor.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

llm = ChatMistralAI(api_key="mBng7pAtolwotaZRyOQxB5RclArjyM4P", model="mistral-medium")

tools = [token_screener_agent, wallet_screener_agent, db_agent, helius_agent]

supervisor_agent = initialize_agent(
    tools,
    llm,
    agent="zero-shot-react-description",
    verbose=False,
    handle_parsing_errors=True,
    max_iterations=3,
    early_stopping_method="generate",
)

template = """
You are a Web3 security analyst. For the given input, you MUST use the appropriate tools to gather real data before providing analysis.

Input: {input}

MANDATORY TOOL USAGE:
- If input contains token_address: Use Token Screener Agent
- If input contains wallet_address: Use Wallet Screener Agent  
- If input contains transaction data: Use Helius Agent
- Always use DB Agent for final ML analysis

After using tools, provide analysis in this exact JSON format (no markdown, no backticks):
{{
  "what": "Description of what was analyzed",
  "how": "Tools and methods used with actual results", 
  "who": "Target audience or use case"
}}

IMPORTANT: Your final answer must be ONLY the JSON object above, nothing else.
"""

prompt = PromptTemplate(input_variables=["input"], template=template)
chain = prompt | llm


def detect_input_type(data):
    """Detect what type of Web3 analysis this is"""
    if isinstance(data, dict):
        if "token_address" in data:
            return "token_analysis"
        elif "wallet_address" in data:
            return "wallet_analysis"
        elif "transaction_hash" in data:
            return "transaction_analysis"
        elif "transaction_details" in data:
            return "transaction_analysis"
    return "general_analysis"


def parse_transaction_details(text):
    # Ambil From, To, Value, dll. pakai regex
    details = {}
    from_match = re.search(r"From:\s*(\S+)", text)
    to_match = re.search(r"To:\s*(\S+)", text)
    value_match = re.search(r"Value:\s*([\d.]+)\s*ETH", text)

    if from_match:
        details["from"] = from_match.group(1)
    if to_match:
        details["to"] = to_match.group(1)
    if value_match:
        details["value"] = float(value_match.group(1))

    return details


def run_supervisor(user_input, auth_token=None):
    if isinstance(user_input, dict):
        input_str = json.dumps(user_input, ensure_ascii=False)
        parsed = user_input
    else:
        input_str = str(user_input)
        try:
            parsed = json.loads(input_str)
        except:
            parsed = {"raw_input": input_str}

    logging.info(f"Analisa input: {input_str}")

    input_type = detect_input_type(parsed.get("data", parsed))
    logging.info(f"Detected input type: {input_type}")

    try:
        # Use invoke instead of run for better error handling
        result = supervisor_agent.invoke({"input": input_str})

        # Extract output from the result
        if isinstance(result, dict) and "output" in result:
            content = result["output"]
        elif hasattr(result, "content"):
            content = result.content
        elif hasattr(result, "text"):
            content = result.text
        else:
            content = str(result)

        # Clean the content more thoroughly
        cleaned = content.strip()

        # Remove common markdown formatting
        if cleaned.startswith("```json"):
            cleaned = cleaned[7:]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = (
            cleaned.replace("```json", "").replace("```", "").replace("`", "").strip()
        )

        # Try to extract JSON from the content
        try:
            # Look for JSON object in the content
            start_idx = cleaned.find("{")
            end_idx = cleaned.rfind("}") + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = cleaned[start_idx:end_idx]
                analysis = json.loads(json_str)
            else:
                raise json.JSONDecodeError("No JSON found", cleaned, 0)
        except json.JSONDecodeError:
            # If JSON parsing fails, create structured response from the content
            analysis = {
                "what": f"Analysis completed for {input_type}",
                "how": "Used LangChain agent with Web3 tools - " + content[:200],
                "who": "Web3 security analysis system",
                "raw_output": content,
            }

    except Exception as e:
        logging.error(f"Error in supervisor execution: {str(e)}")
        # Create fallback analysis using direct tool calls
        analysis = create_fallback_analysis(parsed, input_type)

    output = {
        "status": "success" if "error" not in analysis else "error",
        "input": parsed,
        "analysis": analysis,
        "meta": {
            "agent": "supervisor",
            "tools_used": [tool.name for tool in tools],
            "auth": bool(auth_token),
        },
    }
    logging.info(f"Hasil analisa: {output}")
    return json.dumps(output, ensure_ascii=False, indent=2)


def create_fallback_analysis(parsed_input, input_type):
    """Create analysis by directly calling tools when agent fails"""
    try:
        data = parsed_input.get("data", {})
        results = []
        analysis_details = {"tools_called": [], "findings": [], "recommendations": []}

        # Call appropriate tools based on input type
        if "wallet_address" in data:
            wallet_result = wallet_screener_agent.run(data["wallet_address"])
            results.append(f"Wallet screening: {wallet_result}")
            analysis_details["tools_called"].append("Wallet Screener")

            # Extract key findings from wallet screening
            if "cross-chain" in wallet_result.lower():
                analysis_details["findings"].append(
                    "Address format suggests cross-chain activity"
                )
            if "risk" in wallet_result.lower():
                analysis_details["findings"].append("Risk assessment completed")

        if "token_address" in data:
            token_result = token_screener_agent.run(data["token_address"])
            results.append(f"Token screening: {token_result}")
            analysis_details["tools_called"].append("Token Screener")

        if "transaction_hash" in data or "transaction_details" in data:
            tx_data = data.get("transaction_hash", data.get("transaction_details", ""))
            helius_result = helius_agent.run(tx_data)
            results.append(f"Transaction tracing: {helius_result}")
            analysis_details["tools_called"].append("Transaction Tracer")

            # Extract key findings from transaction tracing
            if "different blockchain" in helius_result.lower():
                analysis_details["findings"].append(
                    "Transaction may be from different blockchain"
                )

        # Always run ML analysis
        ml_input = json.dumps(data)
        ml_result = db_agent.run(ml_input)
        results.append(f"ML analysis: {ml_result}")
        analysis_details["tools_called"].append("ML Analyzer")

        # Extract recommendations from ML analysis
        if "malicious" in ml_result.lower():
            analysis_details["recommendations"].append(
                "Exercise caution - potential malicious indicators detected"
            )
        if "investigation" in ml_result.lower():
            analysis_details["recommendations"].append(
                "Further investigation recommended"
            )

        return {
            "what": f"Comprehensive {input_type.replace('_', ' ')} using multiple security tools",
            "how": f"Tools used: {', '.join(analysis_details['tools_called'])}. Key findings: {'; '.join(analysis_details['findings']) if analysis_details['findings'] else 'Analysis completed'}",
            "who": "Web3 security analysis system with fallback processing",
            "details": {
                "tools_executed": analysis_details["tools_called"],
                "findings": analysis_details["findings"],
                "recommendations": analysis_details["recommendations"],
                "full_results": results,
            },
        }
    except Exception as e:
        return {
            "what": "Error in security analysis",
            "how": f"Analysis failed: {str(e)}",
            "who": "Error handler",
            "error": str(e),
        }


def run_supervisor_batch(inputs, auth_token=None):
    results = []
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(run_supervisor, inp, auth_token) for inp in inputs]
        for future in futures:
            try:
                results.append(future.result())
            except Exception as e:
                logging.error(f"Error batch: {str(e)}")
                results.append(json.dumps({"status": "error", "error": str(e)}))
    return results
