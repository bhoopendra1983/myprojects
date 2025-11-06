from fastapi import FastAPI
from routes import student

app = FastAPI(title="Student Management System")

app.include_router(student.router)

@app.get("/")
def home():
    return {"message": "Welcome to Student Management API"}
