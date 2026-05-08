from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import time
import json
import hmac
import hashlib
import base64
import requests
import os  # <-- ADDED THIS

app = FastAPI(title="Billdu Proxy API")

# Pull secrets from Render environment variables
# If they aren't set, this will return None
BILLDU_API_KEY = os.getenv("BILLDU_API_KEY")
BILLDU_API_SECRET = os.getenv("BILLDU_API_SECRET")

def php_convert(obj):
    if isinstance(obj, float):
        return int(obj) if obj == int(obj) else obj
    elif isinstance(obj, dict):
        return {k: php_convert(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [php_convert(i) for i in obj]
    return obj

def generate_signature(api_key, api_secret, data: dict):
    timestamp = int(time.time())

    to_sign = dict(data)
    to_sign['timestamp'] = timestamp
    to_sign['apiKey'] = api_key

    sorted_dict = {k: php_convert(to_sign[k]) for k in sorted(to_sign.keys())}
    json_string = json.dumps(sorted_dict, separators=(',', ':'))
    json_string = json_string.replace('/', '\\/')

    raw_hmac = hmac.new(
        api_secret.encode('utf-8'),
        json_string.encode('utf-8'),
        hashlib.sha512
    ).digest()

    b64_signature = base64.b64encode(raw_hmac).decode('utf-8')
    return b64_signature, timestamp

@app.post("/create-document")
async def create_document(request: Request):
    # 1. Fail fast if the server isn't configured right
    if not BILLDU_API_KEY or not BILLDU_API_SECRET:
        raise HTTPException(
            status_code=500, 
            detail="Server configuration error: API keys are missing in environment variables."
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    # Extract only the data from n8n (no keys anymore!)
    doc_type = body.get("type", "estimates")
    payload = body.get("payload")

    if payload is None or not isinstance(payload, dict):
        raise HTTPException(
            status_code=400, 
            detail="Missing or invalid 'payload' object in request body."
        )

    # 2. Generate signature using the secure environment variables
    signature, timestamp = generate_signature(BILLDU_API_KEY, BILLDU_API_SECRET, payload)
    
    # 3. Send to Billdu
    url = "https://api.billdu.com/documents"
    params = {
        "type": doc_type,
        "apiKey": BILLDU_API_KEY,
        "signature": signature,
        "timestamp": timestamp
    }

    clean_data = php_convert(payload)
    json_body = json.dumps(clean_data, separators=(',', ':'))

    headers = {"Content-Type": "application/json"}
    response = requests.post(url, data=json_body, params=params, headers=headers)

    # 4. Return to n8n
    try:
        return JSONResponse(status_code=response.status_code, content=response.json())
    except ValueError:
        return JSONResponse(
            status_code=response.status_code, 
            content={"error": "Non-JSON response from Billdu", "raw_text": response.text}
        )

@app.get("/")
def read_root():
    return {"status": "online", "message": "Billdu Proxy API is running securely."}