from pydantic import BaseModel, Field
from typing import Optional

class Student(BaseModel):
    name: str = Field(..., example="John Doe")
    age: int = Field(..., example=21)
    course: str = Field(..., example="B.Tech")
    year: int = Field(..., example=3)

class UpdateStudent(BaseModel):
    name: Optional[str]
    age: Optional[int]
    course: Optional[str]
    year: Optional[int]