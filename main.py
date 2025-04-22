from fastapi import FastAPI, Depends, HTTPException, status, Header
from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import JoseError, DecodeError, ExpiredTokenError  # Import specific exceptions
from starlette.config import Config
import httpx
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from fastapi.security.http import HTTPAuthorizationCredentials

config = Config('.env')

app = FastAPI()

origins = [
    "http://localhost:5173",  # Allow your frontend origin
    # Add other origins as needed (e.g., your production frontend)
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],  # Allows all HTTP methods
    allow_headers=["*"],  # Allows all headers
)

# Replace with your actual authorization server details
AUTHORIZATION_SERVER_URL = config('OKTA_ISSUER')  
JWKS_ENDPOINT = f"{AUTHORIZATION_SERVER_URL}/v1/keys"
SCOPES = ['read:messages']

USE_INTROSPECTION = config('USE_INTROSPECTION', cast=bool, default=False)  # Flag to toggle introspection
INTROSPECTION_ENDPOINT = f"{AUTHORIZATION_SERVER_URL}/v1/introspect"
CLIENT_ID = config('OKTA_CLIENT_ID')  # Your OAuth client ID

# Initialize the HTTPBearer scheme
bearer_scheme = HTTPBearer()

class User(BaseModel):
    sub: str
    username: str

async def get_jwks():
    """Retrieves the JWKS from the authorization server."""
    async with httpx.AsyncClient() as client:
        response = await client.get(JWKS_ENDPOINT)
        response.raise_for_status()
        return response.json()

async def introspect_token(token: str, token_type_hint: str = "access_token") -> dict:
    """Introspects the token using the authorization server's introspection endpoint."""
    async with httpx.AsyncClient() as client:
        response = await client.post(
            INTROSPECTION_ENDPOINT,
            data={
                "token": token,
                "token_type_hint": token_type_hint,
                "client_id": CLIENT_ID,  
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",  
            },
        )
        response.raise_for_status()
        return response.json()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> User:
    """Verifies the incoming access token using FastAPI's HTTPBearer."""
    token = credentials.credentials  # Extract the token from the Authorization header
    #print(f"Extracted token: {token}")

    try:
        if USE_INTROSPECTION:
            # Use introspection to validate the token
            introspection_result = await introspect_token(token)
            if not introspection_result.get("active"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is inactive or invalid"
                )
            # Extract user data and scopes from introspection result
            user_data = {
                "sub": introspection_result["sub"],
                "username": introspection_result.get("username", "unknown"),
            }
            token_scopes = introspection_result.get("scope", "").split()

            # Validate the 'aud' claim
            if introspection_result.get("aud") != "api://default":  # Replace with your expected audience
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid audience"
                )
        else:
            # Perform local verification
            jwks_data = await get_jwks()
            rsa_key = None
            for key in jwks_data["keys"]:
                rsa_key = JsonWebKey.import_key(key)
                break
            # Print the RSA key in a readable format
            #print(f"RSA Key: {rsa_key.as_dict()}")

            # Decode the token
            payload = jwt.decode(
                token, rsa_key, claims_options={"exp": {"essential": True}}
            )

            # Print the decoded payload
            #print(f"Decoded payload: {payload}")
            
            # Validate the 'aud' claim
            if payload.get("aud") != config('OKTA_AUDIENCE'):  # Replace with your expected audience
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid audience"
                )

            if "exp" in payload:
                expiration = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
                print(f"Token expiration time: {expiration}")
                if expiration < datetime.now(timezone.utc):
                    print("Token has expired")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
                    )

            token_scopes = payload.get("scp", [])
            if not isinstance(token_scopes, list):
                token_scopes = token_scopes.split()

            user_data = {
                "sub": payload["sub"],
                "username": payload.get("username", payload.get("preferred_username", "unknown")),
            }

        # Validate required scopes
        for scope in SCOPES:
            if scope not in token_scopes:
                print(f"Missing required scope: {scope}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient scope"
                )

        print(f"User data: {user_data}")
        return User(**user_data)

    except ExpiredTokenError as e:
        print(f"ExpiredTokenError: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
        )
    except DecodeError as e:
        print(f"DecodeError: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token decoding failed: {str(e)}"
        )
    except JoseError as e:
        print(f"JoseError: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {str(e)}"
        )
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token verification failed: {str(e)}"
        )

@app.get("/api/messages") 
async def get_messages(user: User = Depends(verify_token)):
    """Endpoint to retrieve messages. Requires authentication."""
    messages = [
        {
            "date": datetime.now(),
            "text": "You are free from the dungeon!"
        }
    ]
    return {"messages": messages}

@app.get("/api/public")
async def public_endpoint():
    return {"message": "Public endpoint, no auth required"}