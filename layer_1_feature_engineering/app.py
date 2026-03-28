from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Union
import os

from ingestion_orchestrator import (
    process_json_text,
    process_jsonl_text,
    process_records,
)

app = FastAPI(
    title="SOC Ingestion API",
    description="Ingest logs and connect them to Layer 1 feature extraction"
)


@app.get("/")
def health():
    return {
        "status": "ok",
        "service": "soc-ingestion-api"
    }


@app.post("/ingest/text")
def ingest_text(payload: Any = Body(...)):
    try:
        if isinstance(payload, str):
            result = process_json_text(payload)

        elif isinstance(payload, dict):
            result = process_records([payload])

        elif isinstance(payload, list):
            if not all(isinstance(item, dict) for item in payload):
                raise HTTPException(status_code=400, detail="Body list must contain JSON objects only")
            result = process_records(payload)

        else:
            raise HTTPException(status_code=400, detail="Unsupported request body format")

        return JSONResponse(content={
            "status": "success",
            "source": "raw_text_payload",
            "total_records": result["total_records"],
            "sample_normalized": result["normalized_records"][:3],
            "sample_enriched": result["enriched_records"][:2]
        })

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/ingest/file")
async def ingest_file(files: List[UploadFile] = File(...)):
    results = []

    for file in files:
        filename = file.filename or "uploaded_file"
        ext = os.path.splitext(filename)[1].lower()

        if ext not in {".json", ".jsonl"}:
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file format for {filename}. Please change the format to JSON or JSONL."
            )

        content_bytes = await file.read()

        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail=f"{filename} is not valid UTF-8 text")

        try:
            if ext == ".json":
                result = process_json_text(content)
            else:
                result = process_jsonl_text(content)

            results.append({
                "filename": filename,
                "total_records": result["total_records"],
                "sample_normalized": result["normalized_records"][:3],
                "sample_enriched": result["enriched_records"][:2]
            })

        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"{filename}: {str(e)}")

    return JSONResponse(content={
        "status": "success",
        "files_processed": len(results),
        "results": results
    })