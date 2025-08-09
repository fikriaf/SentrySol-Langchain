import requests

BASE_URL = "http://localhost:8000"


def safe_json(resp):
    try:
        return resp.json()
    except Exception:
        return resp.text


def test_analyze():
    payload = {
        "data": {
            "wallet_addrAess": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas",
            "transaction_hash": "0x5e2b8e2e4f8c8a1e8b8e2e4f8c8a1e8b8e2e4f8c8a1e8b8e2e4f8c8a1e8b8e2e",
            "transaction_details": "From: DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas\nTo: SomeOtherAddress\nValue: 0.00012 ETH\n",
            "chain": "ethereum"
        }
    }
    r = requests.post(f"{BASE_URL}/analyze", json=payload)
    print("/analyze:", r.status_code, safe_json(r))


def test_transactions():
    params = {"wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"}
    r = requests.get(f"{BASE_URL}/transactions", params=params)
    print("/transactions:", r.status_code, safe_json(r))


def test_transfers():
    params = {"wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"}
    r = requests.get(f"{BASE_URL}/transfers", params=params)
    print("/transfers:", r.status_code, safe_json(r))


def test_domains():
    params = {"wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"}
    r = requests.get(f"{BASE_URL}/domains", params=params)
    print("/domains:", r.status_code, safe_json(r))


def test_labels():
    params = {"wallet_address": "DRiP2Pn2K6fuMLKQmt5rZWyHiUZ6zDvNrjggrE3wTBas"}
    r = requests.get(f"{BASE_URL}/labels", params=params)
    print("/labels:", r.status_code, safe_json(r))


if __name__ == "__main__":
    test_analyze()
    # test_transactions()
    # test_transfers()
    # test_domains()
    # test_labels()
