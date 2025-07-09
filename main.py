from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
import sqlite3

app = FastAPI()

# CORS 설정 명확히 추가
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "qualibot_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    age: int
    company: str
    position: str
    phone_number: str

def init_db():
    conn = sqlite3.connect('qualibot.db')
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            hashed_password TEXT,
            full_name TEXT,
            age INTEGER,
            company TEXT,
            position TEXT,
            phone_number TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_password_hash(password):
    return pwd_context.hash(password)

def authenticate_user(email, password):
    conn = sqlite3.connect('qualibot.db')
    cur = conn.cursor()
    cur.execute("SELECT hashed_password FROM users WHERE email=?", (email,))
    user = cur.fetchone()
    conn.close()
    if not user:
        return False
    return pwd_context.verify(password, user[0])

def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    encoded_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/register")
def register(user: User):
    hashed_password = get_password_hash(user.password)
    conn = sqlite3.connect('qualibot.db')
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (email, hashed_password, full_name, age, company, position, phone_number)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user.email, hashed_password, user.full_name, user.age, user.company, user.position, user.phone_number))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="이미 가입된 사용자입니다.")
    conn.close()
    return {"msg": "회원가입 성공!"}

@app.post("/login")
def login(user: User):
    if not authenticate_user(user.email, user.password):
        raise HTTPException(status_code=401, detail="로그인 실패.")
    access_token = create_access_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}
