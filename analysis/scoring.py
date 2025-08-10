import json
import re
import logging
from langchain.prompts import PromptTemplate


def calculate_security_scores_llm(analysis_results, input_type, tools_used, scoring_chain):
    """Calculate security scores using LLM instead of hardcoded logic"""
    try:
        # Prepare input for LLM scoring
        llm_input = {
            "wallet_screening": analysis_results.get("wallet_screening", "Not analyzed")[:300],
            "transaction_details": analysis_results.get("transaction_details", "Not analyzed")[
                :300
            ],
            "labels_domains": analysis_results.get("labels_and_domains", "Not analyzed")[:300],
            "token_transfers": analysis_results.get("token_transfers", "Not analyzed")[:300],
            "security_assessment": analysis_results.get("security_assessment", "Not completed")[
                :300
            ],
            "analysis_type": input_type.replace("_", " ").title(),
            "tools_used": ", ".join(tools_used) if tools_used else "Standard security tools",
        }

        # Generate scores using LLM
        scoring_response = scoring_chain.invoke(llm_input)
        scoring_text = (
            scoring_response.content
            if hasattr(scoring_response, "content")
            else str(scoring_response)
        )

        logging.info(f"LLM scoring response: {scoring_text[:200]}...")

        # Parse JSON response
        try:
            # Extract JSON from response
            json_match = re.search(r"\{.*\}", scoring_text, re.DOTALL)
            if json_match:
                scores_json = json_match.group(0)
                scores = json.loads(scores_json)

                # Validate required fields
                required_fields = [
                    "overall_security_score",
                    "wallet_security_score",
                    "transaction_security_score",
                    "token_security_score",
                    "domain_security_score",
                    "confidence_level",
                    "risk_level",
                    "threat_indicators",
                    "positive_indicators",
                    "compliance_score",
                    "reputation_score",
                ]

                for field in required_fields:
                    if field not in scores:
                        if field in ["threat_indicators", "positive_indicators"]:
                            scores[field] = []
                        elif field == "risk_level":
                            scores[field] = "MODERATE"
                        else:
                            scores[field] = 75

                # Ensure scores are integers and within range
                for score_field in [
                    "overall_security_score",
                    "wallet_security_score",
                    "transaction_security_score",
                    "token_security_score",
                    "domain_security_score",
                    "confidence_level",
                    "compliance_score",
                    "reputation_score",
                ]:
                    if score_field in scores:
                        scores[score_field] = max(0, min(100, int(scores[score_field])))

                # Validate risk level
                valid_risk_levels = ["VERY_LOW", "LOW", "MODERATE", "HIGH", "CRITICAL"]
                if scores["risk_level"] not in valid_risk_levels:
                    scores["risk_level"] = "MODERATE"

                logging.info(
                    f"LLM scores parsed successfully: Overall={scores['overall_security_score']}, Risk={scores['risk_level']}"
                )
                return scores

            else:
                raise ValueError("No JSON found in LLM response")

        except (json.JSONDecodeError, ValueError) as e:
            logging.error(f"Failed to parse LLM scoring JSON: {str(e)}")
            raise e

    except Exception as e:
        logging.error(f"LLM scoring failed: {str(e)}")
        # Fallback to basic scores
        return {
            "overall_security_score": 75,
            "wallet_security_score": 75,
            "transaction_security_score": 75,
            "token_security_score": 75,
            "domain_security_score": 75,
            "confidence_level": 60,
            "risk_level": "MODERATE",
            "threat_indicators": [f"LLM scoring error: {str(e)}"],
            "positive_indicators": ["Fallback scoring applied"],
            "compliance_score": 70,
            "reputation_score": 70,
        }


def calculate_security_scores(analysis_results, input_type):
    """Calculate comprehensive security scores and risk metrics (legacy method)"""
    scores = {
        "overall_security_score": 0,
        "wallet_security_score": 0,
        "transaction_security_score": 0,
        "token_security_score": 0,
        "domain_security_score": 0,
        "confidence_level": 0,
        "risk_level": "UNKNOWN",
        "threat_indicators": [],
        "positive_indicators": [],
        "compliance_score": 0,
        "reputation_score": 0,
    }

    # Initialize scoring weights
    weights = {
        "wallet": 0.3,
        "transaction": 0.25,
        "token": 0.2,
        "domain": 0.15,
        "ml_assessment": 0.1,
    }

    total_weighted_score = 0
    confidence_factors = []
    min_agent_score = 65

    # ...existing code for scoring logic...

    return scores
