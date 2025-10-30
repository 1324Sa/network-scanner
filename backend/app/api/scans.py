# backend/app/api/scans.py
import os
import re
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, constr
import uuid
from redis import Redis
from rq import Queue
from rq.job import Job
import json

router = APIRouter()

ALLOWED_TYPES = {"tcp", "udp", "service"}
ALLOWED_OPTIONS = {"-sV", "-A", "-Pn", "-T4"}  # نترك -p خارجها ونتعامل معه بصيغة خاصة

# regex to allow -p80 or -p80-90 (single port or range)
PORT_RE = re.compile(r"^-p(\d{1,5})(-(\d{1,5}))?$")

# Read REDIS host from env so it works both in Docker and local dev.
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

redis_conn = Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)
q = Queue(connection=redis_conn)

class ScanRequest(BaseModel):
    target: constr(min_length=3)
    scan_type: str
    options: list[str] = []

def validate_option(opt: str) -> bool:
    """
    Returns True if option is allowed:
    - either in ALLOWED_OPTIONS (e.g. -sV, -A, -Pn, -T4)
    - or a port spec like -p80 or -p80-90
    """
    if opt in ALLOWED_OPTIONS:
        return True
    if PORT_RE.match(opt):
        # extra validation: ports 1-65535
        m = PORT_RE.match(opt)
        start = int(m.group(1))
        end = int(m.group(3)) if m.group(3) else start
        if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
            return True
    return False

@router.post("", status_code=202)
async def create_scan(req: ScanRequest):
    # validations
    if req.scan_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail="scan_type not allowed")
    for opt in req.options:
        if not validate_option(opt):
            raise HTTPException(status_code=400, detail=f"option {opt} not allowed")
    # basic target safety: disallow empty / very short input
    if len(req.target) < 3:
        raise HTTPException(status_code=400, detail="invalid target")
    # create task id and enqueue
    task_id = str(uuid.uuid4())
    job = q.enqueue("worker.run_nmap", {"target": req.target, "options": req.options}, job_id=task_id, result_ttl=3600)
    return {"task_id": task_id, "status": "queued"}

@router.get("/{task_id}")
async def get_scan_status(task_id: str):
    try:
        job = Job.fetch(task_id, connection=redis_conn)
    except Exception:
        raise HTTPException(status_code=404, detail="task_id not found")

    result = None
    if job.is_finished:
        result = job.result
        try:
            json.dumps(result)
        except Exception:
            result = str(result)

    return {
        "task_id": task_id,
        "status": job.get_status(),
        "result": result,
        "enqueued_at": str(job.enqueued_at) if job.enqueued_at else None,
        "started_at": str(job.started_at) if getattr(job, "started_at", None) else None,
        "ended_at": str(job.ended_at) if getattr(job, "ended_at", None) else None,
    }
