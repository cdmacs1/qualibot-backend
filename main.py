from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Hello from Qualibot!"}

@app.get("/search")
def search(query: str):
    return {"results": [f"찾은 결과: {query} 관련 내용"]}
