from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Protected Demo API")


class LoginRequest(BaseModel):
    email: str
    password: str


class SearchRequest(BaseModel):
    query: str


class PaymentRequest(BaseModel):
    amount: float
    currency: str
    recipient_id: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "protected_api"}


@app.post("/login")
def login(payload: LoginRequest):
    return {
        "message": "Login request received",
        "email": payload.email,
    }


@app.get("/users/{user_id}")
def get_user(user_id: int):
    return {
        "user_id": user_id,
        "name": "Demo User",
    }


@app.post("/search")
def search(payload: SearchRequest):
    return {
        "results": [],
        "query": payload.query,
    }


@app.post("/payments")
def create_payment(payload: PaymentRequest):
    return {
        "message": "Payment processed",
        "amount": payload.amount,
        "currency": payload.currency,
        "recipient_id": payload.recipient_id,
    }