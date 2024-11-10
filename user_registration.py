from fastapi import FastAPI, Depends, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr, constr
from typing import Optional
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from core.database import SessionLocal, engine, Base
from users.models import UserModel
from core.security import get_password_hash, verify_password
from core.email import send_verification_email
from jose import JWTError, jwt


# Initialize FastAPI app
app = FastAPI()

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Define OAuth2 scheme for token-based authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Settings for JWT
SECRET_KEY = "educare_login#234 "
ALGORITHM = "HS256"

# Function to create access token with expiration
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=1)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# User registration model
class UserRegistration(BaseModel):
    full_name: str
    email: EmailStr
    institution: str
    course_level: int
    state_of_school: str
    password: str
    confirm_password: str

# Email verification model
class EmailVerification(BaseModel):
    email: EmailStr
    verification_token: str

# User login model
class UserLogin(BaseModel):
    username_or_email: str
    password: str

# Endpoint for user registration
@app.post("/sign-up", status_code=status.HTTP_201_CREATED)
async def sign_up(user: UserRegistration, db: Session = Depends(get_db)):
    # Check for existing user by email
    if db.query(UserModel).filter(UserModel.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email is already registered.")
    
    # Check password match
    if user.password != user.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    
    # Hash the password and create user entry
    hashed_password = get_password_hash(user.password)
    new_user = UserModel(
        full_name=user.full_name,
        email=user.email,
        institution_name=user.institution,
        course_of_study=user.course_level,
        state_of_school=user.state_of_school,
        password=hashed_password,
        is_active=False,
        is_verified=False,
        registered_at=datetime.now(),
        updated_at=datetime.now()
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Send verification email with a token that expires in 1 minute
    verification_token = create_access_token(data={"sub": user.email}, expires_delta=timedelta(minutes=1))
    send_verification_email(user.email, verification_token)

    return {"message": "Verification email sent. Please check your inbox."}

# Endpoint for email verification
@app.post("/verify-email")
async def verify_email(data: EmailVerification, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if user.is_verified:
        raise HTTPException(status_code=400, detail="User already verified.")

    try:
        # Decode and validate token
        payload = jwt.decode(data.verification_token, SECRET_KEY, algorithms=[ALGORITHM])
        token_email = payload.get("sub")
        if token_email != user.email:
            raise HTTPException(status_code=400, detail="Invalid verification token.")
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token.")

    # Mark the user as verified
    user.is_verified = True
    user.is_active = True
    db.commit()
    
    return {"message": "User successfully verified. Redirecting to login page."}

# Endpoint for user login
@app.post("/login")
async def login(data: UserLogin, db: Session = Depends(get_db)):
    # Find user by email or username
    user = db.query(UserModel).filter((UserModel.email == data.username_or_email)).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Generate access token
    access_token = create_access_token(data={"sub": user.email})

    return {"message": "Login successful. Redirecting to dashboard.", "access_token": access_token}

# Dependency for getting the current user
def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(UserModel).filter(UserModel.email == email).first()
    if user is None:
        raise credentials_exception
    return user

# Protected user dashboard endpoint
@app.get("/{username}/dashboard")
async def user_dashboard(username: str, current_user: UserModel = Depends(get_current_user)):
    if current_user.full_name != username:
        raise HTTPException(status_code=403, detail="Access forbidden.")
    return {"message": f"Welcome to your dashboard, {current_user.full_name}!", "user_data": current_user}
