from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

app.get("/")
async def home():
    return "Đây là API phát hiện ransomware sử dụng một mô hình ensemble deep learning, truy cập /docs để hiểu thêm"

