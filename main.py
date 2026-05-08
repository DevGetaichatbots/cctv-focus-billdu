from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import time
import json
import hmac
import hashlib
import base64
import requests
import os

app = FastAPI(title="Billdu Proxy API")

# Pull secrets from Render environment variables
BILLDU_API_KEY = os.getenv("BILLDU_API_KEY")
BILLDU_API_SECRET = os.getenv("BILLDU_API_SECRET")

def php_convert(obj):
    """
    PHP's json_encode converts whole-number floats to ints.
    """
    if isinstance(obj, float):
        return int(obj) if obj == int(obj) else obj
    elif isinstance(obj, dict):
        return {k: php_convert(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [php_convert(i) for i in obj]
    return obj

def generate_signature(api_key, api_secret, data: dict):
    timestamp = int(time.time())

    # 1. Shallow copy of the dictionary
    to_sign = dict(data)
    to_sign['timestamp'] = timestamp
    to_sign['apiKey'] = api_key

    # 2. ksort = sort TOP-LEVEL keys only
    sorted_dict = {k: php_convert(to_sign[k]) for k in sorted(to_sign.keys())}
    
    # 3. JSON encode (Python style without spaces)
    json_string = json.dumps(sorted_dict, separators=(',', ':'))
    
    # 4. Replicate PHP's default forward-slash escaping
    json_string = json_string.replace('/', '\\/')

    # 5. HMAC-SHA512 (raw), then base64
    raw_hmac = hmac.new(
        api_secret.encode('utf-8'),
        json_string.encode('utf-8'),
        hashlib.sha512
    ).digest()

    b64_signature = base64.b64encode(raw_hmac).decode('utf-8')
    
    return b64_signature, timestamp


# ---------------------------------------------------------
# ENDPOINT 1: POST /create-document
# ---------------------------------------------------------
@app.post("/create-document")
async def create_document(request: Request):
    if not BILLDU_API_KEY or not BILLDU_API_SECRET:
        raise HTTPException(
            status_code=500, 
            detail="Server configuration error: API keys are missing in environment variables."
        )

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    doc_type = body.get("type", "estimates")
    payload = body.get("payload")

    if payload is None or not isinstance(payload, dict):
        raise HTTPException(
            status_code=400, 
            detail="Missing or invalid 'payload' object in request body."
        )

    # Generate signature with the payload
    signature, timestamp = generate_signature(BILLDU_API_KEY, BILLDU_API_SECRET, payload)
    
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

    try:
        return JSONResponse(status_code=response.status_code, content=response.json())
    except ValueError:
        return JSONResponse(
            status_code=response.status_code, 
            content={"error": "Non-JSON response from Billdu", "raw_text": response.text}
        )


# ---------------------------------------------------------
# ENDPOINT 2: GET /clients (NEW)
# ---------------------------------------------------------
@app.get("/clients")
def get_clients():
    if not BILLDU_API_KEY or not BILLDU_API_SECRET:
        raise HTTPException(
            status_code=500, 
            detail="Server configuration error: API keys are missing in environment variables."
        )

    # For a GET request, the data payload is an empty dictionary
    empty_payload = {}
    
    # Generate signature using the empty payload
    signature, timestamp = generate_signature(BILLDU_API_KEY, BILLDU_API_SECRET, empty_payload)
    
    url = "https://api.billdu.com/clients"
    
    params = {
        "apiKey": BILLDU_API_KEY,
        "signature": signature,
        "timestamp": timestamp
    }

    # Billdu's API might require application/json even on GET requests
    headers = {"Content-Type": "application/json"}
    
    response = requests.get(url, params=params, headers=headers)

    try:
        return JSONResponse(status_code=response.status_code, content=response.json())
    except ValueError:
        return JSONResponse(
            status_code=response.status_code, 
            content={"error": "Non-JSON response from Billdu", "raw_text": response.text}
        )


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------
@app.get("/")
def read_root():
    return {"status": "online", "message": "Billdu Proxy API is running securely."}