import re


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
    """Parse transaction details from text using regex"""
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


def validate_input_data(data):
    """Validate input data structure and content"""
    if not isinstance(data, dict):
        return False, "Input must be a dictionary"

    # Check for at least one required field
    required_fields = [
        "wallet_address",
        "transaction_hash",
        "transaction_details",
        "token_address",
    ]
    if not any(field in data for field in required_fields):
        return (
            False,
            f"Input must contain at least one of: {', '.join(required_fields)}",
        )

    # Validate wallet address format if present
    if "wallet_address" in data and data["wallet_address"]:
        wallet_addr = data["wallet_address"]
        if not isinstance(wallet_addr, str) or len(wallet_addr) < 20:
            return False, "Invalid wallet address format"

    return True, "Valid input"
