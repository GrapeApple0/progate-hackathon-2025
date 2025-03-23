from typing import Optional
import fastapi
from starlette.middleware.cors import CORSMiddleware
import requests
import json
import boto3
from botocore.exceptions import ClientError
import uvicorn
import datetime
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import base64
import jwt
from jwt.algorithms import RSAAlgorithm
import hmac
import hashlib
import psycopg2
from pprint import pprint
# Load environment file
load_dotenv()

app = fastapi.FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,   # 追記により追加
    allow_methods=["*"],      # 追記により追加
    allow_headers=["*"]       # 追記により追加
)
#boto3 clients
s3_client = boto3.client('s3', region_name='us-west-2')
cognito_client = boto3.client('cognito-idp', region_name='us-west-2')
bedrock_runtime_client = boto3.client('bedrock-runtime', region_name='us-west-2')
pg_conn = psycopg2.connect(
    host=os.environ.get("POSTGRES_HOST"),
    port=5432,
    dbname=os.environ.get("POSTGRES_DB"),
    user=os.environ.get("POSTGRES_USER"),
    password=os.environ.get("POSTGRES_PASSWORD"),
)

# models
class File(BaseModel):
    filename: str

class Authorization(BaseModel):
    token: str
    client_id: Optional[str] = None

class FileToDetect(BaseModel):
    filename: str
    filetype: str #'image/jpeg', 'image/png', 'image/gif' or 'image/webp'

class FridgeValue(BaseModel):
    items: dict[str,int]

def get_url_from_s3(filename) -> str:
    url: str = s3_client.generate_presigned_url(
        ClientMethod='get_object',
        Params={'Bucket': os.environ.get("S3_BUCKET"), 'Key': filename},
        ExpiresIn=120)
    url = url.replace('s3.amazonaws.com', 's3.us-west-2.amazonaws.com')
    return url

def file_to_base64(url) -> str:
    res = requests.get(url)
    return (base64.b64encode(res.content)).decode('ascii')

def is_file_exist(filename) -> bool:
    try:
        s3_client.Object(os.environ.get("S3_BUCKET"), filename).load()
        return True
    except ClientError as e:
        return False

def _secret_hash(username) -> str:
    app_client_id, key = os.environ.get("COGNITO_CLIENT_ID"), os.environ.get("COGNITO_CLIENT_SECRET")

    # Create message and key bytes
    message, key = (username + app_client_id).encode('utf-8'), key.encode('utf-8')

    # Calculate secret hash
    secret_hash = base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()
    
    return secret_hash

def verify_token(token: str, client_id: str | None = None) -> bool:
    issuer = f'https://cognito-idp.us-west-2.amazonaws.com/{os.environ.get("COGNITO_USER_POOL_ID")}'
    jwks_url = f'{issuer}/.well-known/jwks.json'

    jwk_set = requests.get(jwks_url).json()

    header = jwt.get_unverified_header(token)
    jwk = next(filter(lambda x: x['kid'] == header['kid'], jwk_set['keys']))
    public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))

    try:
        claims = jwt.decode(
            token,
            public_key,
            issuer=issuer,
            audience=(client_id if client_id != None else os.environ.get("COGNITO_CLIENT_ID")),
            algorithms=jwk['alg'],
        )
        pprint(claims)
        if claims['aud'] != (client_id if client_id != None else os.environ.get("COGNITO_CLIENT_ID")):
            return False
        if claims['iss'] != issuer:
            return False
        if claims['token_use'] != "id":
            return False
        return True
    except Exception as e:
        # だいたい期限切れのエラー
        print("Failed to validate the token. Reason:",e)
        return False

def get_username_from_token(token: str, client_id: str|None = None) -> str:
    issuer = f'https://cognito-idp.us-west-2.amazonaws.com/{os.environ.get("COGNITO_USER_POOL_ID")}'
    jwks_url = f'{issuer}/.well-known/jwks.json'

    jwk_set = requests.get(jwks_url).json()

    header = jwt.get_unverified_header(token)
    jwk = next(filter(lambda x: x['kid'] == header['kid'], jwk_set['keys']))
    public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))

    try:
        claims = jwt.decode(
            token,
            public_key,
            issuer=issuer,
            audience=(client_id if client_id != None else os.environ.get("COGNITO_CLIENT_ID")),
            algorithms=jwk['alg'],
        )
        if claims['aud'] != (client_id if client_id != None else os.environ.get("COGNITO_CLIENT_ID")):
            return None
        if claims['iss'] != issuer:
            return None
        if claims['token_use'] != "id":
            return None
        return claims["cognito:username"]
    except Exception as e:
        # だいたい期限切れのエラー
        print("Failed to validate the token. Reason:",e)
        return None

@app.post("/upload")
def upload(file: File, auth: Authorization):
    if not verify_token(auth.token, auth.client_id):
        raise fastapi.HTTPException(status_code=401, detail="Unauthorized")
    url: str = s3_client.generate_presigned_url(
        ClientMethod='put_object',
        Params={'Bucket': os.environ.get("S3_BUCKET"), 'Key': file.filename},
        ExpiresIn=120)
    url = url.replace('s3.amazonaws.com', 's3.us-west-2.amazonaws.com')
    return {"url": url}

@app.post("/download")
def download(file: File, auth: Authorization):
    if not verify_token(auth.token, auth.client_id):
        raise fastapi.HTTPException(status_code=401, detail="Unauthorized")
    url = get_url_from_s3(file.filename)
    return {"url": url}

@app.post("/detect")
def detect(file: FileToDetect, auth: Authorization):
    if not verify_token(auth.token, auth.client_id):
        raise fastapi.HTTPException(status_code=401, detail="Unauthorized")
    model_id = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    # Define the prompt for the model.
    prompt = "You're a detector of fridges.\nLet me know what are in fridges pairs name of items and count of items with json array without categorized.\nLabels should be Japanese.Moreover, please ignore the items that are not in the fridge and foods.\nExample: {\"items\": {\"りんご\": \"2\", \"みかん\": \"3\"}}"

    # Format the request payload using the model's native structure.
    native_request = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 512,
        "temperature": 0.5,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": prompt
                    },
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": file.filetype,
                            "data": file_to_base64(get_url_from_s3(file.filename))
                        }
                    },
                ],
            }
        ],
    }

    # Convert the native request to JSON.
    request = json.dumps(native_request)

    try:
        # Invoke the model with the request.
        response = bedrock_runtime_client.invoke_model(modelId=model_id, body=request)
        # Decode the response body.
        model_response = json.loads(response["body"].read())

        # Extract and print the response text.
        response_json = json.loads(model_response["content"][0]["text"])
        return response_json
    except (ClientError, Exception) as e:
        print(f"ERROR: Can't invoke '{model_id}'. Reason: {e}")
    

@app.get("/ping")
def ping():
    return {"pong": datetime.datetime.now()}

@app.post("/verify")
def verify(auth: Authorization):
    try:
        return verify_token(auth.token, auth.client_id)
    except ClientError as e:
        return {"error": e}

@app.post("/insert")
def insert(value: FridgeValue,auth: Authorization):
    if not verify_token(auth.token, auth.client_id):
        raise fastapi.HTTPException(status_code=401, detail="Unauthorized")
    try:
        with pg_conn.cursor() as cur:
            sql = "INSERT INTO ingredient_list (username) VALUES (%s) RETURNING id;"
            username = get_username_from_token(auth.token, auth.client_id)
            cur.execute(sql, (username,))
            pg_conn.commit()
            id = cur.fetchone()[0]
            for item, count in value.items.items():
                sql = "INSERT INTO items (ingredient_id, name, count) VALUES (%s, %s, %s)"
                cur.execute(sql, (id, item, count))                
            pg_conn.commit()
            return {"id": id}
    except Exception as err:
        print(err)
        return {"error": err}

@app.post("/list")
def list(auth: Authorization):
    if not verify_token(auth.token, auth.client_id):
        raise fastapi.HTTPException(status_code=401, detail="Unauthorized")
    username = get_username_from_token(auth.token, auth.client_id)
    try:
        with pg_conn.cursor() as cur:
            sql = "SELECT + FROM ingredient_list where il.username = %s;"
            cur.execute(sql, (username,))
            # id = cur.fetchone()[0]
            # sql = "SELECT name, count FROM items WHERE ingredient_id = %s;"
            # cur.execute(sql, (id,))
            items = cur.fetchall()
            return {"items": items}
    except Exception as err:
        print(err)

def list_items(auth: Authorization):
    if not verify_token(auth.token, auth.client_id):
        raise fastapi.HTTPException(status_code=401, detail="Unauthorized")
    username = get_username_from_token(auth.token, auth.client_id)
    try:
        with pg_conn.cursor() as cur:
            sql = "SELECT il.*, i.name, i.count FROM ingredient_list il JOIN items i ON il.id = i.ingredient_id where il.username = %s;"
            cur.execute(sql, (username,))
            # id = cur.fetchone()[0]
            # sql = "SELECT name, count FROM items WHERE ingredient_id = %s;"
            # cur.execute(sql, (id,))
            items = cur.fetchall()
            return {"items": items}
    except Exception as err:
        print(err)

@app.post("/register")
def register(email: str, password: str):
    try:
        response = cognito_client.admin_create_user(
            UserPoolId=os.environ.get("COGNITO_USER_POOL_ID"),
            Username=email,
            TemporaryPassword=password,
            UserAttributes=[
                {
                    'Name': 'email',
                    'Value': email
                },
            ],
            MessageAction='SUPPRESS'
        )
        return {"response": response}
        
    except ClientError as e:
        return {"error": e}

@app.post("/login")
def login(username: str, password: str):
    try:
        response = cognito_client.admin_initiate_auth(
            UserPoolId=os.environ.get("COGNITO_USER_POOL_ID"),
            ClientId=os.environ.get("COGNITO_CLIENT_ID"),
            AuthFlow='ADMIN_USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password,
                'SECRET_HASH': _secret_hash(username),
            }
        )
        if response.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
            response = cognito_client.admin_respond_to_auth_challenge(
                UserPoolId=os.environ.get("COGNITO_USER_POOL_ID"),
                ClientId=os.environ.get("COGNITO_CLIENT_ID"),
                ChallengeName='NEW_PASSWORD_REQUIRED',
                ChallengeResponses={
                    'USERNAME': username,
                    'NEW_PASSWORD': password,
                    'SECRET_HASH': _secret_hash(username),
                },
                Session=response["Session"]
            )
            return {"response": response}
        return {"token": response}
    except ClientError as e:
        return {"error": e}

def main():
    uvicorn.run(app=app)

if __name__ == "__main__":
    main()
