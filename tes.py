import requests

url = "https://api.mistral.ai/v1/chat/completions"
headers = {
    "Authorization": "Bearer mBng7pAtolwotaZRyOQxB5RclArjyM4P",
    "Content-Type": "application/json",
}
data = {
    "model": "ft:mistral-medium-latest:b319469f:20250807:b80c0dce",
    "messages": [
        {"role": "system", "content": "You are a cryptocurrency security expert specializing in Ethereum threat detection and analysis."},
        {"role": "user", "content": "Analyze this Ethereum transaction for security threats. Determine if it's malicious and explain why.\n\nTransaction Details:\nFrom: 0x123\nTo: 0x456\nValue: 0.05 ETH"},
    ],
}


response = requests.post(url, headers=headers, json=data)
print(response.json()['choices'][0]['message']['content'])
