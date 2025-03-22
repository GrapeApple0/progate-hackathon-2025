import fastapi
import requests
import json
import boto3
from botocore.exceptions import ClientError
import uvicorn
import datetime
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import psycopg2
import base64
load_dotenv()

app = fastapi.FastAPI()

#boto3 clients
s3_client = boto3.client('s3', region_name='us-west-2')
cognito_client = boto3.client('cognito-idp', region_name='us-west-2')
bedrock_runtime_client = boto3.client('bedrock-runtime', region_name='us-west-2')

#postgres connection
connection = psycopg2.connect(
    dbname=os.environ.get("POSTGRES_DB"),
    user=os.environ.get("POSTGRES_USER"),
    password=os.environ.get("POSTGRES_PASSWORD"),
    host=os.environ.get("POSTGRES_HOST"),
    port=5432
)

# models
class File(BaseModel):
    filename: str

class FileToDetect(BaseModel):
    filename: str
    filetype: str

@app.post("/upload")
def upload(file: File):
    url: str = s3_client.generate_presigned_url(
            ClientMethod='put_object',
            Params={'Bucket': os.environ.get("S3_BUCKET"), 'Key': file.filename},
            ExpiresIn=120)
    url = url.replace('s3.amazonaws.com', 's3.us-west-2.amazonaws.com')
    return {"url": url}

@app.post("/download")
def download(file: File):
    url = get_url_from_s3(file.filename)
    return {"url": url}

def get_url_from_s3(filename) -> str:
    url: str = s3_client.generate_presigned_url(
            ClientMethod='get_object',
            Params={'Bucket': os.environ.get("S3_BUCKET"), 'Key': filename},
            ExpiresIn=120)
    return url

def file_to_base64(url) -> str:
    res = requests.get(url)
    return (base64.b64encode(res.content)).decode('ascii')

@app.post("/detect")
def detect(file: FileToDetect):
    model_id = "anthropic.claude-3-5-sonnet-20241022-v2:0"
    # Define the prompt for the model.
    prompt = "You're a detector of fridges.\nLet me know what are in fridges with json array without categorized.\nLabels should be Japanese."

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

    except (ClientError, Exception) as e:
        print(f"ERROR: Can't invoke '{model_id}'. Reason: {e}")
        exit(1)

    # Decode the response body.
    model_response = json.loads(response["body"].read())

    # Extract and print the response text.
    response_json = json.loads(model_response["content"][0]["text"])
    return response_json

@app.get("/ping")
def ping():
    return {"pong": datetime.datetime.now()}

@app.post("/lists")
def lists():
    return

def main():
    uvicorn.run(app=app)

if __name__ == "__main__":
    main()
