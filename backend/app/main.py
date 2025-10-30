from fastapi import FastAPI
from app.api import scans

app = FastAPI(title="Network Scanner API")

app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])

@app.get("/")
async def root():
    return {"message": "Network Scanner API is running!"}
