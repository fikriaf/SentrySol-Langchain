import os
import logging
from dotenv import load_dotenv
from langchain_mistralai.chat_models import ChatMistralAI
from langchain.prompts import PromptTemplate

load_dotenv()


def initialize_llm():
    """Initialize and return the LLM instance"""
    mistral_api_key = os.getenv("MISTRAL_API_KEY")
    mistral_model = os.getenv("MISTRAL_MODEL", "mistral-medium")

    if not mistral_api_key:
        logging.error("MISTRAL_API_KEY not set in environment.")
        raise ValueError("Missing MISTRAL_API_KEY environment variable")

    return ChatMistralAI(api_key=mistral_api_key, model=mistral_model)


def get_supervisor_template():
    """Return the supervisor agent template"""
    return """
You are a Web3 security analyst. For the given input, you MUST use the appropriate tools to gather real data before providing analysis.

Input: {input}

MANDATORY TOOL USAGE:
- If input contains token_address: Use Token Screener Agent
- If input contains wallet_address: Use Wallet Screener Agent  
- If input contains transaction data: Use Helius Agent
- Always use DB Agent for final ML analysis

After using tools, provide analysis in this EXACT format with these sections:

1. **Wallet Screening:**
   - [Analysis results from wallet screening]

2. **Transaction Details:**
   - [Analysis results from transaction analysis]

3. **Labels and Domains:**
   - [Analysis results from labels/domains check]

4. **Token Transfers:**
   - [Analysis results from token/transfer analysis]

**Conclusion:**
[Overall assessment and final verdict]

IMPORTANT: Always use the exact section headers above. Do not deviate from this format.
"""


def get_summary_template():
    """Return the dynamic summary template"""
    return """
Based on the following Web3 security analysis results, generate concise and professional summaries:

Analysis Type: {analysis_type}
Input Data: {input_data}

Analysis Results:
- Wallet Screening: {wallet_screening}
- Transaction Details: {transaction_details}  
- Labels and Domains: {labels_domains}
- Token Transfers: {token_transfers}
- Security Assessment: {security_assessment}
- Tools Used: {tools_used}

Generate responses in EXACTLY this format (no extra formatting or ** symbols):

WHAT: [One concise sentence describing what analysis was performed - max 40 words]
WHO: [One sentence describing the system/components that performed the analysis - max 30 words]
HOW: [One sentence describing the methodology and key findings - max 35 words]

Rules:
- Start each line with WHAT:, WHO:, or HOW: exactly
- No markdown formatting, no ** symbols
- Keep responses concise and professional
- Each response must be a single sentence
"""


def get_scoring_template():
    """Return the security scoring template"""
    return """
You are a Web3 security scoring expert. Based on the analysis results provided, generate comprehensive security scores.

Analysis Results:
- Wallet Screening: {wallet_screening}
- Transaction Details: {transaction_details}
- Labels and Domains: {labels_domains}
- Token Transfers: {token_transfers}
- Security Assessment: {security_assessment}

Analysis Type: {analysis_type}
Tools Used: {tools_used}

Generate security scores in EXACTLY this JSON format (no extra text):

{{
    "overall_security_score": [0-100 integer],
    "wallet_security_score": [0-100 integer],
    "transaction_security_score": [0-100 integer],
    "token_security_score": [0-100 integer],
    "domain_security_score": [0-100 integer],
    "confidence_level": [0-100 integer],
    "risk_level": "[VERY_LOW/LOW/MODERATE/HIGH/CRITICAL]",
    "threat_indicators": ["indicator1", "indicator2"],
    "positive_indicators": ["indicator1", "indicator2"],
    "compliance_score": [0-100 integer],
    "reputation_score": [0-100 integer]
}}

Scoring Guidelines:
- 90-100: Excellent/Very Low Risk
- 80-89: Good/Low Risk  
- 70-79: Moderate/Moderate Risk
- 60-69: Below Average/High Risk
- 0-59: Poor/Critical Risk

Focus on:
- Legitimate activities should score 80+ 
- No suspicious activity = higher scores
- Cross-chain activities are normal
- API errors are neutral (75 points)
- Clear malicious indicators = low scores
"""
