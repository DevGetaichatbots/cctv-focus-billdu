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


# ---------------------------------------------------------
# ENDPOINT 1: POST /create-document (Create Invoices/Estimates)
# ---------------------------------------------------------
@app.post("/create-document")
async def create_document(request: Request):
    if not BILLDU_API_KEY or not BILLDU_API_SECRET:
        raise HTTPException(status_code=500, detail="Missing API keys in environment.")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    doc_type = body.get("type", "estimates")
    payload = body.get("payload")

    if not payload or not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Missing 'payload' dictionary.")

    signature, timestamp = generate_signature(BILLDU_API_KEY, BILLDU_API_SECRET, payload)
    
    url = "https://api.billdu.com/documents"
    params = {"type": doc_type, "apiKey": BILLDU_API_KEY, "signature": signature, "timestamp": timestamp}

    json_body = json.dumps(php_convert(payload), separators=(',', ':'))
    headers = {"Content-Type": "application/json"}
    
    response = requests.post(url, data=json_body, params=params, headers=headers)

    try:
        return JSONResponse(status_code=response.status_code, content=response.json())
    except ValueError:
        return JSONResponse(status_code=response.status_code, content={"error": "Non-JSON response", "raw_text": response.text})


# ---------------------------------------------------------
# ENDPOINT 2: GET /clients (Fetch all clients)
# ---------------------------------------------------------
@app.get("/clients")
def get_clients():
    if not BILLDU_API_KEY or not BILLDU_API_SECRET:
        raise HTTPException(status_code=500, detail="Missing API keys in environment.")

    signature, timestamp = generate_signature(BILLDU_API_KEY, BILLDU_API_SECRET, {})
    
    url = "https://api.billdu.com/clients"
    params = {"apiKey": BILLDU_API_KEY, "signature": signature, "timestamp": timestamp}
    
    response = requests.get(url, params=params) # NO headers here to avoid Nette Syntax Error!

    try:
        return JSONResponse(status_code=response.status_code, content=response.json())
    except ValueError:
        return JSONResponse(status_code=response.status_code, content={"error": "Non-JSON response", "raw_text": response.text})


# ---------------------------------------------------------
# ENDPOINT 3: POST /create-client (DYNAMIC & FIXED)
# ---------------------------------------------------------
@app.post("/create-client")
async def create_client(request: Request):
    if not BILLDU_API_KEY or not BILLDU_API_SECRET:
        raise HTTPException(status_code=500, detail="Missing API keys in environment.")

    try:
        # We take the ENTIRE body sent from n8n
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    # 1. Force the phone number to be a string just in case n8n sends an integer
    if "phone" in payload:
        payload["phone"] = str(payload["phone"])

    # 2. Billdu requires at least a name or company. If n8n didn't send one, add a fallback.
    if "fullname" not in payload and "company" not in payload:
        payload["fullname"] = "John Doe"

    # 3. Generate the signature using EXACTLY what n8n sent
    signature, timestamp = generate_signature(BILLDU_API_KEY, BILLDU_API_SECRET, payload)
    
    url = "https://api.billdu.com/clients"
    
    params = {
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
        return JSONResponse(status_code=response.status_code, content={"error": "Non-JSON response", "raw_text": response.text})


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------
@app.get("/")
def read_root():
    return {"status": "online", "message": "Billdu Proxy API is running securely."}