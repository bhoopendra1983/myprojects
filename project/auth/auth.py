from fastapi import APIRouter, HTTPException
from auth.schema import RegisterSchema, LoginSchema
from database import user_collection
from passlib.context import CryptContext

from jose import jwt
from datetime import datetime, timedelta

router = APIRouter(prefix="/auth", tags=["Auth"])

SECRET_KEY = "MY_SECRET_KEY"       # change in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt_sha256"], deprecated="auto")


# ✅ Create Access Token
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ✅ Hash Password
def hash_password(password: str):
    return pwd_context.hash(password)



# ✅ Verify Password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# ✅ Register API
@router.post("/register")
async def register_user(user: RegisterSchema):
    existing_user = await user_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    



    hashed_pw = hash_password(user.password)

    new_user = {
        "name": user.name,
        "email": user.email,
        "password": hashed_pw
    }

    result= await user_collection.insert_one(new_user)

    return {"message": "User registered successfully"}


# ✅ Login API
@router.post("/login")
async def login_user(user: LoginSchema):
    db_user = await user_collection.find_one({"email": user.email})

    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    if not verify_password(user.password, db_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    token = create_access_token({"email": user.email})

    return {
        "message": "Login Successful",
        "access_token": token,
        "token_type": "bearer"
    }
