
#class 11 of piaic step 16 authorization and authentication

from fastapi import FastAPI ,HTTPException # type: ignore
from jose import jwt,JWTError # type: ignore
from datetime import datetime,timedelta
from fastapi.security import OAuth2PasswordRequestForm # type: ignore
from typing import Annotated
from fastapi import Depends # type: ignore
from fastapi.security import OAuth2PasswordBearer # type: ignore

ALGORITHM:str = "HS256"
SECRET_KEY:str = "A Secured Secret Key"


app = FastAPI()
oayth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
# oayth2_scheme(token="token")

oayth3_scheme = OAuth2PasswordBearer(tokenUrl="login")
fake_users_db: dict[str, dict[str, str]] = {
    "ameenalam": {
        "username": "ameenalam",
        "full_name": "Ameen Alam",
        "email": "ameenalam@example.com",
        "password": "ameenalamsecret",
    },
    "mjunaid": {
        "username": "mjunaid",
        "full_name": "Muhammad Junaid",
        "email": "mjunaid@example.com",
        "password": "mjunaidsecret",
    },
}
  
  
@app.post("/login")
def login_request(data_from_user:Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)]):
 
    
    
     user_in_fake_db = fake_users_db.get(data_from_user.username)
     if user_in_fake_db is None:
         raise HTTPException(status_code=400, detail="Incorrect username")
    
     if user_in_fake_db["password"] != data_from_user.password:
         raise HTTPException(status_code=400, detail="Incorrect password..")
    
     access_token_expiry_minutes = timedelta(minutes=1)
     
     generated_token = create_access_token(
         subject=data_from_user.username, expires_delta=access_token_expiry_minutes)
     
     
     return{"username": data_from_user.username, "access_token":generated_token}
    
@app.get("/all-users")
def get_all_users(token: Annotated[str,Depends(oayth2_scheme)]):
    return fake_users_db
@app.get("/specialall")
def specialall_users(token: Annotated[str,Depends(oayth3_scheme)]):
    return {"welcome":"here", "token":token}

@app.get("/")
def read_root():
    return{"hello":"baby"}

def create_access_token(subject: str , expires_delta: timedelta) ->str:
    expire = datetime.utcnow() +  expires_delta
    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.get("/get-token")
def get_token(name:str):
    access_token_expiry_minutes = timedelta(minutes=1)
    print("access_token_expiry_minutes",access_token_expiry_minutes)
    
    generated_token = create_access_token(subject=name,expires_delta=access_token_expiry_minutes)
    
    return {"access_token":generated_token}


def decode_access_token(access_token: str):
    decoded_data = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
    return decoded_data

@app.get("/decode_token")
def decode_token(access_token: str):
   try:
       decoded_data = decode_access_token(access_token)
       return decoded_data
   except JWTError as e:
       return {"error": str(e)}