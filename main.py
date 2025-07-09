import os
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, field_validator
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta
from typing import Optional
import sqlite3

# OpenAI 연동
from openai import OpenAI  # pip install openai

app = FastAPI()

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

# --- User, Auth, Register, Login 등 기존 코드 (생략 가능, 아래 예시 유지) ---

class User(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    age: Optional[int] = None
    company: Optional[str] = None
    position: Optional[str] = None
    phone_number: Optional[str] = None

    @field_validator('age', 'company', 'position', 'phone_number')
    @classmethod
    def not_empty(cls, v):
        if v is None or (isinstance(v, str) and not v.strip()):
            raise ValueError("빈 값은 허용되지 않습니다.")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

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

def verify_token(token: str = Header(..., alias="Authorization")):
    if token.startswith("Bearer "):
        token = token.replace("Bearer ", "")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if user_email is None:
            raise HTTPException(status_code=401, detail="토큰 정보가 없습니다.")
        return user_email
    except JWTError:
        raise HTTPException(status_code=401, detail="유효하지 않은 토큰입니다.")

@app.post("/register")
def register(user: User):
    hashed_password = get_password_hash(user.password)
    conn = sqlite3.connect('qualibot.db')
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (email, hashed_password, full_name, age, company, position, phone_number)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user.email, hashed_password, user.full_name,
            user.age, user.company, user.position, user.phone_number
        ))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="이미 가입된 사용자입니다.")
    conn.close()
    return {"msg": "회원가입 성공!"}

@app.post("/login")
def login(user: LoginRequest):
    if not authenticate_user(user.email, user.password):
        raise HTTPException(status_code=401, detail="로그인 실패.")
    access_token = create_access_token({"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/me")
def get_me(user_email: str = Depends(verify_token)):
    return {"user": user_email}

# === 🟢 질의/표준추천 + AI 연동 완전 전체 코드 ===

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")  # 환경변수 또는 Render/로컬에서 지정

class AskRequest(BaseModel):
    question: str

@app.post("/ask")
def ask_standard(request: AskRequest):
    q = request.question.strip().lower()

    # 1. IPC/ESA/NASA 키워드별 안내
    if "ipc" in q or "qfp" in q or "솔더" in q or "pcb" in q:
        return {
            "answer": (
                "추천 표준: IPC-A-610, IPC-6012 등\n"
                "설명: 전자기기 솔더링/PCB/QFP 등은 IPC-A-610, 6012 등의 국제표준을 따릅니다.\n"
                "(예: QFP 소자 솔더링 기준은 IPC-A-610 8판 8.3.2절을 참고하세요.)"
            )
        }
    elif "esa" in q or "ecss" in q or "space" in q or "우주" in q:
        return {
            "answer": (
                "추천 표준: ESA ECSS-Q-ST-70 시리즈\n"
                "설명: 우주분야(ESA, ECSS)는 ECSS-Q-ST-70-xx(솔더링/어셈블리/와이어 등) 표준을 참고하세요."
            )
        }
    elif "nasa" in q or "8739" in q:
        return {
            "answer": (
                "추천 표준: NASA-STD-8739 시리즈\n"
                "설명: NASA 우주 전자/솔더링/케이블/수리 등은 NASA-STD-8739.1~5를 참고하세요."
            )
        }
    elif "whma" in q or "620" in q or "와이어" in q or "wire" in q:
        return {
            "answer": (
                "추천 표준: IPC/WHMA-A-620\n"
                "설명: 와이어 하네스 및 전선 조립 기준은 IPC/WHMA-A-620을 참고하세요."
            )
        }
    elif "리페어" in q or "rework" in q or "repair" in q:
        return {
            "answer": (
                "추천 표준: IPC-7711/21, NASA-STD-8739.3\n"
                "설명: 리페어/재작업은 IPC-7711/21 또는 NASA-STD-8739.3을 참고하세요."
            )
        }

    # 2. OpenAI GPT 연동 (환경변수 설정 필요)
    if OPENAI_API_KEY:
        try:
            client = OpenAI(api_key=OPENAI_API_KEY)
            system_msg = (
                "너는 국제표준 길라잡이 AI '퀄리'야. "
                "사용자의 질문이 표준 문서에 직접 복사/붙여넣기 하지 말고, "
                "적합한 국제표준(IPC, ESA, NASA 등)의 번호/판/항목만 안내하고, "
                "가능하면 핵심 내용을 네 말로 요약해줘. "
                "원문이 필요하면 '공식 표준서를 참고하세요'라고 안내해."
            )
            user_msg = request.question.strip()
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                max_tokens=512,
                temperature=0.4,
            )
            answer = response.choices[0].message.content.strip()
            return {"answer": answer}
        except Exception as e:
            return {
                "answer": f"AI 답변 중 오류 발생: {str(e)}\n규정 안내나 키워드 중심 질의는 즉시 답변 가능합니다."
            }

    # 3. 환경변수 없을 때 fallback
    return {
        "answer": (
            "질문을 더 구체적으로 입력해 주세요!\n"
            "예) QFP 소자 솔더링 기준, 와이어 수락 조건, 우주등급 리페어 등"
        )
    }
