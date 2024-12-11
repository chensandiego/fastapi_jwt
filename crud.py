from sqlalchemy.orm import Session
from . import models,schemas,auth
def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = auth.hash_password(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def get_refresh_token(db: Session, token: str):
    return db.query(models.RefreshToken).filter(models.RefreshToken.token == token).first()


# New Function to Save a Refresh Token
def save_refresh_token(db: Session, user_id: int, token: str, expires_in: int = 7):
    expires_at = datetime.utcnow() + timedelta(days=expires_in)
    db_refresh_token = models.RefreshToken(
        token=token, user_id=user_id, expires_at=expires_at
    )
    db.add(db_refresh_token)
    db.commit()
    db.refresh(db_refresh_token)
    return db_refresh_token