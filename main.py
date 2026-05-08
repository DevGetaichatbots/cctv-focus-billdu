from fastapi import FastAPI, Request, HTTPException
import time
import json
import hmac
import hashlib
import base64

app = FastAPI(title="Billdu Signature API")

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


@app.post("/sign")
async def sign_payload(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    # Extract credentials and the actual Billdu data payload
    api_key = body.get("api_key")
    api_secret = body.get("api_secret")
    payload = body.get("payload")

    # Validation
    if not api_key or not api_secret or payload is None:
        raise HTTPException(
            status_code=400, 
            detail="Missing 'api_key', 'api_secret', or 'payload' in request body."
        )

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=400, 
            detail="'payload' must be a JSON object (dictionary)."
        )

    # Generate the signature
    signature, timestamp = generate_signature(api_key, api_secret, payload)
    
    return {
        "signature": signature,
        "timestamp": timestamp
    }

@app.get("/")
def read_root():
    return {"status": "online", "message": "Billdu Signature API is running. Send a POST request to /sign."}