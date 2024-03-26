from fastapi import FastAPI, HTTPException, Depends
from sqlalchemy import create_engine, Column, Integer, String, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from typing import List, Optional
from pydantic import BaseModel
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta

app = FastAPI()

# Database Configuration
SQLALCHEMY_DATABASE_URL = "postgresql://user:password@localhost/dbname"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT Configuration
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Dependency to get DB Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# User Model
class User(BaseModel):
    username: str
    email: str

# User Table
class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True)
    email = Column(String, unique=True)
    hashed_password = Column(String)

# Water Quality Observation Record Model
class WaterQualityRecord(BaseModel):
    location: dict
    date_time: str
    description: str
    parameters: dict

# Water Quality Observation Record Table
class WaterQualityRecordDB(Base):
    __tablename__ = "water_quality_records"

    id = Column(Integer, primary_key=True, index=True)
    location = Column(JSON)
    date_time = Column(String)
    description = Column(String)
    parameters = Column(JSON)

# Create tables
Base.metadata.create_all(bind=engine)

# CRUD operations for Water Quality Observation Records
@app.post("/records/")
def create_record(record: WaterQualityRecord, db: Session = Depends(get_db)):
    db_record = WaterQualityRecordDB(**record.dict())
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    return db_record

@app.get("/records/")
def read_records(db: Session = Depends(get_db)):
    return db.query(WaterQualityRecordDB).all()

@app.put("/records/{record_id}")
def update_record(record_id: int, record: WaterQualityRecord, db: Session = Depends(get_db)):
    db_record = db.query(WaterQualityRecordDB).filter(WaterQualityRecordDB.id == record_id).first()
    if db_record:
        update_data = record.dict(exclude_unset=True)
        for key, value in update_data.items():
            setattr(db_record, key, value)
        db.commit()
        db.refresh(db_record)
        return db_record
    else:
        raise HTTPException(status_code=404, detail="Record not found")

@app.delete("/records/{record_id}")
def delete_record(record_id: int, db: Session = Depends(get_db)):
    db_record = db.query(WaterQualityRecordDB).filter(WaterQualityRecordDB.id == record_id).first()
    if db_record:
        db.delete(db_record)
        db.commit()
        return {"message": "Record deleted successfully"}
    else:
        raise HTTPException(status_code=404, detail="Record not found")

@app.get("/records/{record_id}")
def read_record(record_id: int, db: Session = Depends(get_db)):
    db_record = db.query(WaterQualityRecordDB).filter(WaterQualityRecordDB.id == record_id).first()
    if db_record:
        return db_record
    else:
        raise HTTPException(status_code=404, detail="Record not found")

# Search Endpoint by Location
@app.get("/records/search/location/")
def search_records_by_location(latitude: float, longitude: float, radius: Optional[float] = 10.0, db: Session = Depends(get_db)):
    results = []
    records = db.query(WaterQualityRecordDB).all()
    for record in records:
        # Implement search logic based on location
        # For demonstration, let's assume we're searching records within a certain radius
        if calculate_distance(latitude, longitude, record.location['latitude'], record.location['longitude']) <= radius:
            results.append(record)
    return results

# Function to calculate distance between two points
def calculate_distance(lat1, lon1, lat2, lon2):
    # Dummy implementation for demonstration
    return abs(lat1 - lat2) + abs(lon1 - lon2)

# JWT Token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Verify Password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Get User
def get_user(db, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

# Authenticate User
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Create JWT Token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Token Endpoint
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    db = SessionLocal()
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Protected Endpoint
@app.get("/users/me/")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    db = SessionLocal()
    user = get_user(db, username=username)
    if user is None:
        raise credentials_exception
    return user
