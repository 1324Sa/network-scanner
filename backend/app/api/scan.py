from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, constr
import uuid

router = APIRouter()

ALLOWED_TYPES = {"tcp", "udp", "service"}

class ScanRequest(BaseModel):
    target: constr(min_length=3)
    scan_type: str

@router.post("", status_code=202)
async def create_scan(req: ScanRequest):
    if req.scan_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail="Invalid scan type")

    task_id = str(uuid.uuid4())
    return {"task_id": task_id, "status": "queued"}
