import httpx

payload = {
    "jsonrpc": "2.0",
    "method": "filesystem/read",
    "params": {"path": "/etc/passwd"},
    "id": 123
}

response = httpx.post("http://localhost:8000/mcp", json=payload)
print("Status Code:", response.status_code)
print("Response:")
print(response.text)
print("\nParsed JSON:")
print(response.json())