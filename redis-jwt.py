from fastapi import FastAPI, Depends, HTTPException, status,Form
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from . import models, schemas, database, crud, auth
from pydantic import BaseModel
from jose import JWTError,jwt
from rediscluster import RedisCluster
from datetime import datetime, timedelta

models.Base.metadata.create_all(bind=database.engine)
# Define startup nodes for Redis Cluster
startup_nodes = [{"host": "192.168.0.10", "port": "6370"},
                 {"host": "192.168.0.10", "port": "6371"},
                 {"host":"192.168.0.10", "port": "6372"},
                 {"host":"192.168.0.10", "port": "6373"},
                 {"host":"192.168.0.10", "port": "6374"},
                 {"host": "192.168.0.10", "port": "6375"}]

app = FastAPI()

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS=7



# Connect to Redis Cluster
redis_client = RedisCluster(startup_nodes=startup_nodes, decode_responses=True)


# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# Example user store for demo (You can use a database for production)
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "password": "password",  # Store hashed password in real applications
    }
}

@app.post("/signup", response_model=schemas.UserOut)
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db, user)




@app.post("/login", response_model=Token)
def login(username: str = Form(...), password: str = Form(...)):
    # Verify user credentials (use hashed password check in production)
    user = fake_users_db.get(username)
    if not user or user['password'] != password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Generate JWT tokens
    access_token = auth.create_access_token(data={"sub": username})
    refresh_token =auth.create_refresh_token(data={"sub": username})

    # Store refresh token in Redis with expiration (e.g., 7 days)
    redis_client.setex(f"refresh_token:{username}", timedelta(days=7), refresh_token)

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}



@app.post("/refresh-token", response_model=Token)
def refresh_token(refresh_data: RefreshTokenRequest):
    refresh_token = refresh_data.refresh_token
    try:
        # Decode the refresh token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        # Retrieve the stored refresh token from Redis
        stored_token = redis_client.get(f"refresh_token:{username}")
        if stored_token != refresh_token:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

        # Generate a new access token
        new_access_token = auth.create_access_token(data={"sub": username})

        return {
            "access_token": new_access_token,
            "refresh_token": refresh_token,  # Optionally issue a new refresh token
            "token_type": "bearer",
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")



@app.post("/logout")
def logout(username: str):
    # Delete refresh token from Redis
    redis_client.delete(f"refresh_token:{username}")
    return {"detail": "Logged out successfully"}


class RefreshTokenRequest(BaseModel):
    refresh_token: str

@app.post("/refresh-token", response_model=schemas.Token)
def refresh_token(
    refresh_data: RefreshTokenRequest, db: Session = Depends(get_db)
):
    refresh_token=refresh_data.refresh_token
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        db_user = crud.get_user_by_username(db, username)
        if not db_user:
            raise HTTPException(status_code=401, detail="User not found")
        
        new_access_token = auth.create_access_token(data={"sub": username})
        new_refresh_token = auth.create_refresh_token(data={"sub": username})
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

