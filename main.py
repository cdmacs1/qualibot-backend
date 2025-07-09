from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# CORS 설정 추가
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 모든 주소 허용 (개발용으로 사용)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    return {"message": "Hello from Qualibot!"}

@app.get("/search")
def search(query: str):
    return {"results": [f"찾은 결과: {query} 관련 내용"]}

@app.get("/ipc_standards/{section}/explain")
async def explain_ipc_section(section: str, class_level: str):
    # 예시 데이터
    return {
        "section": section,
        "title": f"IPC 섹션 {section}",
        "ai_explanation": f"선택된 섹션: {section}, 등급: {class_level}에 대한 설명입니다."
    }

