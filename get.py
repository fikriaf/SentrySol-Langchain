import requests

url = "https://api.chainabuse.com/v0/reports?includePrivate=false&page=1&perPage=50"

headers = {"accept": "application/json"}

response = requests.get(url, headers=headers)

print(response.text)