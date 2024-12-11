from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from . import models, schemas, database, crud, auth
from pydantic import BaseModel
from jose import JWTError,jwt

models.Base.metadata.create_all(bind=database.engine)

app = FastAPI()

SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS=7





# Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/signup", response_model=schemas.UserOut)
def signup(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db, user)

@app.post("/login",response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm=Depends(),db:Session=Depends(get_db),):
    db_user = crud.get_user_by_username(db, form_data.username)
    if not db_user or not auth.verify_password(form_data.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = auth.create_access_token(data={"sub": db_user.username})
    refresh_token = auth.create_refresh_token(data={"sub":db_user.username})
    crud.save_refresh_token(db, db_user.id, refresh_token)

    return {"access_token": access_token,"refresh_token":refresh_token, "token_type": "bearer"}

@app.get("/users/me",response_model=schemas.UserOut)
def read_users_me(current_user:schemas.TokenData=Depends(auth.get_current_user),db:Session=Depends(get_db),):
    db_user = crud.get_user_by_username(db, current_user.username)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


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



#check if refresh token has not been expired
@app.post("/refresh-token", response_model=schemas.Token)
def refresh_token(
    refresh_data: RefreshTokenRequest, db: Session = Depends(get_db)
):
    refresh_token = refresh_data.refresh_token
    
    try:
        # Decode the refresh token
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
        # Check if the token exists in the database
        db_refresh_token = crud.get_refresh_token(db, refresh_token)

        if not db_refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not found"
            )
        # Check if the token has expired
        if db_refresh_token.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired"
            )

        new_access_token = auth.create_access_token(data={"sub": username})


        return {
            "access_token": new_access_token,
            "refresh_token": refresh_token,  # Return the existing refresh token
            "token_type": "bearer",
        }
