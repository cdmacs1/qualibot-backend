from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
import sqlite3

app = FastAPI()

# CORS 허용 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT 설정
SECRET_KEY = "qualibot_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# 비밀번호 암호화 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 사용자 데이터 모델
class User(BaseModel):
    username: str
    password: str

# SQLite DB 초기 설정 (사용자 저장소)
def init_db():
    conn = sqlite3.connect('qualibot.db')
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# 비밀번호 암호화 함수
def get_password_hash(password):
    return pwd_context.hash(password)

# 사용자 확인 함수
def authenticate_user(username, password):
    conn = sqlite3.connect('qualibot.db')
    cur = conn.cursor()
    cur.execute("SELECT hashed_password FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    conn.close()

    if not user:
        return False
    return pwd_context.verify(password, user[0])

# JWT 토큰 생성 함수
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 회원가입 API
@app.post("/register")
def register(user: User):
    hashed_password = get_password_hash(user.password)
    conn = sqlite3.connect('qualibot.db')
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (user.username, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="이미 가입된 사용자입니다.")
    conn.close()
    return {"msg": "회원가입 성공!"}

# 로그인 API
@app.post("/login")
def login(user: User):
    if not authenticate_user(user.username, user.password):
        raise HTTPException(status_code=401, detail="로그인 실패. 정보를 확인해 주세요.")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/")
def read_root():
    return {"message": "Hello from Qualibot!"}

@app.get("/ipc_standards/{section}/explain")
async def explain_ipc_section(section: str, class_level: str):
    return {
        "section": section,
        "title": f"IPC 섹션 {section}",
        "ai_explanation": f"선택된 섹션: {section}, 등급: {class_level}에 대한 설명입니다."
    }
