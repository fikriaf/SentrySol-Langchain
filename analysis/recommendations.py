import re
import logging


def generate_security_recommendations(scores, analysis_results):
    """Generate professional security recommendations based on scores"""
    recommendations = []
    risk_level = scores["risk_level"]
    overall_score = scores["overall_security_score"]

    # Risk-based recommendations
    if risk_level == "CRITICAL":
        recommendations.extend(
            [
                "⚠️ CRITICAL: Do not proceed with this transaction/interaction",
                "🔍 Conduct immediate manual review of all security indicators",
                "🚫 Block all interactions until security concerns are resolved",
                "📞 Contact security team for emergency assessment",
            ]
        )
    elif risk_level == "HIGH":
        recommendations.extend(
            [
                "⚡ HIGH RISK: Exercise extreme caution",
                "🔍 Perform additional due diligence before proceeding",
                "💰 Consider reducing transaction amounts",
                "👥 Seek secondary approval for transactions",
            ]
        )
    elif risk_level == "MODERATE":
        recommendations.extend(
            [
                "⚠️ MODERATE RISK: Standard security protocols apply",
                "✅ Verify transaction details carefully",
                "📊 Monitor for unusual activity patterns",
                "🔄 Regular security reassessment recommended",
            ]
        )
    elif risk_level == "LOW":
        recommendations.extend(
            [
                "✅ LOW RISK: Standard security measures sufficient",
                "📈 Continue normal monitoring procedures",
                "🔍 Periodic security reviews recommended",
                "💡 Consider for whitelist if applicable",
            ]
        )
    else:  # VERY_LOW
        recommendations.extend(
            [
                "🟢 VERY LOW RISK: Minimal security concerns",
                "✅ Approved for normal operations",
                "🏆 High confidence in security assessment",
                "📋 Add to trusted entities list",
            ]
        )

    # Score-specific recommendations
    if scores["wallet_security_score"] < 70:
        recommendations.append("🔐 Wallet security requires attention - verify address legitimacy")
    if scores["transaction_security_score"] < 70:
        recommendations.append("💸 Transaction patterns need review - check for anomalies")
    if scores["token_security_score"] < 70:
        recommendations.append("🪙 Token security concerns - verify token contracts")
    if scores["confidence_level"] < 60:
        recommendations.append("📊 Low confidence score - additional verification recommended")

    # Positive reinforcements
    if overall_score >= 85:
        recommendations.append("🎯 High security score indicates trustworthy interaction")
    if len(scores["positive_indicators"]) >= 3:
        recommendations.append("✨ Multiple positive security indicators confirmed")

    return recommendations[:8]  # Limit to 8 recommendations for readability


def generate_professional_summary(scores, input_type, analysis_results):
    """Generate executive summary with key metrics"""
    risk_emoji = {
        "VERY_LOW": "🟢",
        "LOW": "🟡",
        "MODERATE": "🟠",
        "HIGH": "🔴",
        "CRITICAL": "⚫",
    }

    summary = {
        "executive_summary": f"{risk_emoji.get(scores['risk_level'], '⚪')} Security Assessment Complete: {scores['risk_level']} risk level identified with {scores['confidence_level']}% confidence. Overall security score: {scores['overall_security_score']}/100.",
        "key_metrics": {
            "security_grade": "A+"
            if scores["overall_security_score"] >= 95
            else "A"
            if scores["overall_security_score"] >= 90
            else "B+"
            if scores["overall_security_score"] >= 85
            else "B"
            if scores["overall_security_score"] >= 80
            else "C+"
            if scores["overall_security_score"] >= 75
            else "C"
            if scores["overall_security_score"] >= 70
            else "D",
            "threat_level": scores["risk_level"],
            "confidence_rating": "High"
            if scores["confidence_level"] >= 80
            else "Medium"
            if scores["confidence_level"] >= 60
            else "Low",
            "positive_signals": len(scores["positive_indicators"]),
            "risk_signals": len(scores["threat_indicators"]),
            "compliance_status": "COMPLIANT"
            if scores["compliance_score"] >= 70
            else "NON_COMPLIANT",
        },
        "risk_breakdown": {
            "wallet_risk": "Low"
            if scores["wallet_security_score"] >= 80
            else "Medium"
            if scores["wallet_security_score"] >= 60
            else "High",
            "transaction_risk": "Low"
            if scores["transaction_security_score"] >= 80
            else "Medium"
            if scores["transaction_security_score"] >= 60
            else "High",
            "token_risk": "Low"
            if scores["token_security_score"] >= 80
            else "Medium"
            if scores["token_security_score"] >= 60
            else "High",
            "domain_risk": "Low"
            if scores["domain_security_score"] >= 80
            else "Medium"
            if scores["domain_security_score"] >= 60
            else "High",
        },
    }

    return summary


def generate_dynamic_summary(
    analysis_results, input_data, analysis_type, tools_used, summary_chain
):
    """Generate dynamic what/who/how using LLM based on analysis results"""
    try:
        # Prepare input for LLM
        llm_input = {
            "analysis_type": analysis_type.replace("_", " ").title(),
            "input_data": str(input_data)[:200] + "..."
            if len(str(input_data)) > 200
            else str(input_data),
            "wallet_screening": analysis_results.get("wallet_screening", "Not analyzed")[:150],
            "transaction_details": analysis_results.get("transaction_details", "Not analyzed")[
                :150
            ],
            "labels_domains": analysis_results.get("labels_and_domains", "Not analyzed")[:150],
            "token_transfers": analysis_results.get("token_transfers", "Not analyzed")[:150],
            "security_assessment": analysis_results.get("security_assessment", "Not completed")[
                :150
            ],
            "tools_used": ", ".join(tools_used) if tools_used else "Standard security tools",
        }

        # Generate summary using LLM
        summary_response = summary_chain.invoke(llm_input)
        summary_text = (
            summary_response.content
            if hasattr(summary_response, "content")
            else str(summary_response)
        )

        logging.info(f"LLM summary response: {summary_text[:200]}...")

        # Clean up the response text - remove any markdown formatting
        summary_text = summary_text.replace("**", "").replace("*", "")

        # More robust parsing with improved regex patterns
        what_match = re.search(
            r"WHAT:\s*([^\\n]+?)(?=(?:\n|$|WHO:|HOW:))",
            summary_text,
            re.IGNORECASE | re.DOTALL,
        )
        who_match = re.search(
            r"WHO:\s*([^\\n]+?)(?=(?:\n|$|WHAT:|HOW:))",
            summary_text,
            re.IGNORECASE | re.DOTALL,
        )
        how_match = re.search(
            r"HOW:\s*([^\\n]+?)(?=(?:\n|$|WHAT:|WHO:))",
            summary_text,
            re.IGNORECASE | re.DOTALL,
        )

        # Extract and clean the matched content
        what_text = what_match.group(1).strip() if what_match else None
        who_text = who_match.group(1).strip() if who_match else None
        how_text = how_match.group(1).strip() if how_match else None

        # Clean up any remaining formatting issues
        for text_var in [what_text, who_text, how_text]:
            if text_var:
                text_var = re.sub(r"^[*\s]+", "", text_var)  # Remove leading * or whitespace
                text_var = re.sub(r"[*\s]+$", "", text_var)  # Remove trailing * or whitespace
                text_var = text_var.split("\n")[0]  # Take only first line

        # Generate fallback summaries if parsing failed
        if not what_text or len(what_text) < 10:
            what_text = (
                f"Comprehensive {analysis_type.replace('_', ' ')} security analysis performed"
            )

        if not who_text or len(who_text) < 10:
            who_text = "SentrySol Web3 security analysis system with integrated ML models"

        if not how_text or len(how_text) < 10:
            how_text = f"Multi-tool analysis using {len(tools_used)} specialized security agents with positive verification results"

        # Ensure lengths are reasonable (fallback truncation)
        what_text = what_text[:200] if len(what_text) > 200 else what_text
        who_text = who_text[:150] if len(who_text) > 150 else who_text
        how_text = how_text[:200] if len(how_text) > 200 else how_text

        result = {"what": what_text, "who": who_text, "how": how_text}

        logging.info(f"Parsed dynamic summary: {result}")
        return result

    except Exception as e:
        logging.error(f"Dynamic summary generation failed: {str(e)}")
        # Enhanced fallback summaries with more context
        return {
            "what": f"Comprehensive {analysis_type.replace('_', ' ')} security analysis completed with multi-layered verification",
            "who": "SentrySol Web3 security analysis system powered by specialized AI agents and ML models",
            "how": f"Multi-tool verification using {len(tools_used) if tools_used else 8} specialized security agents with comprehensive risk assessment",
        }
