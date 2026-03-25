"""
ioc_api.py
----------
FastAPI router exposing CRUD endpoints for the IOC database.

Mount this router in your main FastAPI app (or in layer_6/soc_api.py):

    from layer_2_detection.ioc_database.ioc_api import ioc_router
    app.include_router(ioc_router, prefix="/api/v1")

Endpoints:
  GET    /ioc                           List all active IOC entries
  GET    /ioc/{ioc_id}                  Get a single IOC entry
  POST   /ioc                           Add a new IOC entry
  PUT    /ioc/{ioc_id}                  Update an existing entry
  DELETE /ioc/{ioc_id}                  Soft-delete an entry
  POST   /ioc/bulk                      Bulk import from a list

  GET    /ioc/candidates                List pending auto-enriched candidates
  POST   /ioc/candidates/{id}/promote   Promote candidate to ioc_entries
  POST   /ioc/candidates/{id}/reject    Reject as false positive

  GET    /ioc/cis                       List CIS benchmark rules
  GET    /ioc/iot-thresholds            List IoT device thresholds
  POST   /ioc/iot-thresholds            Add / update an IoT threshold

  GET    /ioc/stats                     Summary counts for dashboard
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional, List
from ioc_db import (
    get_all_iocs, lookup_ioc, insert_ioc, delete_ioc,
    lookup_cis_rules, lookup_iot_thresholds,
    get_pending_candidates, get_connection, DEFAULT_DB_PATH
)
from auto_enricher import promote_candidate, reject_candidate

ioc_router = APIRouter(prefix="/ioc", tags=["IOC Database"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class IOCCreate(BaseModel):
    ioc_type:        str = Field(..., description="ip | domain | file_hash | url | email")
    value:           str
    threat_type:     Optional[str] = None
    severity:        str = "medium"
    confidence:      str = "high"
    source:          str = "manual"
    mitre_tactic:    Optional[str] = None
    mitre_technique: Optional[str] = None
    description:     Optional[str] = None
    added_by:        str = "analyst"


class IOCUpdate(BaseModel):
    threat_type:     Optional[str] = None
    severity:        Optional[str] = None
    confidence:      Optional[str] = None
    mitre_tactic:    Optional[str] = None
    mitre_technique: Optional[str] = None
    description:     Optional[str] = None
    is_active:       Optional[int] = None


class IOCBulkItem(BaseModel):
    ioc_type:    str
    value:       str
    threat_type: Optional[str] = None
    severity:    str = "medium"
    source:      str = "manual"


class PromoteRequest(BaseModel):
    analyst_id:  str
    severity:    str = "medium"
    confidence:  str = "medium"
    description: Optional[str] = None


class RejectRequest(BaseModel):
    analyst_id: str


class IoTThresholdCreate(BaseModel):
    device_type:     str
    metric:          str
    threshold_min:   Optional[float] = None
    threshold_max:   Optional[float] = None
    severity:        str = "medium"
    description:     Optional[str] = None
    mitre_technique: Optional[str] = None


# ---------------------------------------------------------------------------
# IOC entries CRUD
# ---------------------------------------------------------------------------

@ioc_router.get("", summary="List all active IOC entries")
def list_iocs(active_only: bool = True):
    return {"iocs": get_all_iocs(active_only=active_only)}


@ioc_router.get("/stats", summary="IOC database summary stats for dashboard")
def ioc_stats():
    with get_connection(DEFAULT_DB_PATH) as conn:
        total_iocs    = conn.execute("SELECT COUNT(*) FROM ioc_entries WHERE is_active=1").fetchone()[0]
        total_cis     = conn.execute("SELECT COUNT(*) FROM cis_rules WHERE is_active=1").fetchone()[0]
        total_iot     = conn.execute("SELECT COUNT(*) FROM iot_thresholds WHERE is_active=1").fetchone()[0]
        pending_cands = conn.execute("SELECT COUNT(*) FROM auto_enriched_candidates WHERE status='pending'").fetchone()[0]
        by_type       = conn.execute(
            "SELECT ioc_type, COUNT(*) as cnt FROM ioc_entries WHERE is_active=1 GROUP BY ioc_type"
        ).fetchall()
        by_severity   = conn.execute(
            "SELECT severity, COUNT(*) as cnt FROM ioc_entries WHERE is_active=1 GROUP BY severity"
        ).fetchall()
    return {
        "total_active_iocs":      total_iocs,
        "total_cis_rules":        total_cis,
        "total_iot_thresholds":   total_iot,
        "pending_candidates":     pending_cands,
        "by_type":     {r["ioc_type"]: r["cnt"] for r in by_type},
        "by_severity": {r["severity"]: r["cnt"] for r in by_severity},
    }


@ioc_router.get("/{ioc_id}", summary="Get a single IOC entry by id")
def get_ioc(ioc_id: int):
    with get_connection(DEFAULT_DB_PATH) as conn:
        row = conn.execute("SELECT * FROM ioc_entries WHERE id=?", (ioc_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"IOC id {ioc_id} not found")
    return dict(row)


@ioc_router.post("", summary="Add a new IOC entry")
def add_ioc(body: IOCCreate):
    valid_types = ("ip", "domain", "file_hash", "url", "email")
    if body.ioc_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"ioc_type must be one of {valid_types}")
    ioc_id = insert_ioc(
        ioc_type=body.ioc_type, value=body.value,
        threat_type=body.threat_type, severity=body.severity,
        confidence=body.confidence, source=body.source,
        mitre_tactic=body.mitre_tactic, mitre_technique=body.mitre_technique,
        description=body.description, added_by=body.added_by,
    )
    return {"status": "ok", "ioc_id": ioc_id}


@ioc_router.put("/{ioc_id}", summary="Update an existing IOC entry")
def update_ioc(ioc_id: int, body: IOCUpdate):
    updates = {k: v for k, v in body.dict().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update.")
    set_clause = ", ".join(f"{k}=?" for k in updates)
    values = list(updates.values()) + [ioc_id]
    with get_connection(DEFAULT_DB_PATH) as conn:
        conn.execute(
            f"UPDATE ioc_entries SET {set_clause}, updated_at=datetime('now') WHERE id=?",
            values
        )
    return {"status": "updated", "ioc_id": ioc_id}


@ioc_router.delete("/{ioc_id}", summary="Soft-delete an IOC entry")
def remove_ioc(ioc_id: int):
    delete_ioc(ioc_id)
    return {"status": "deleted", "ioc_id": ioc_id}


@ioc_router.post("/bulk", summary="Bulk import IOC entries from a list")
def bulk_import(items: List[IOCBulkItem]):
    results = {"inserted": 0, "errors": []}
    for item in items:
        try:
            insert_ioc(
                ioc_type=item.ioc_type, value=item.value,
                threat_type=item.threat_type, severity=item.severity,
                source=item.source, added_by="bulk_import"
            )
            results["inserted"] += 1
        except Exception as e:
            results["errors"].append({"value": item.value, "error": str(e)})
    return results


# ---------------------------------------------------------------------------
# Auto-enriched candidates
# ---------------------------------------------------------------------------

@ioc_router.get("/candidates", summary="List pending auto-enriched IOC candidates")
def list_candidates():
    return {"candidates": get_pending_candidates()}


@ioc_router.post("/candidates/{candidate_id}/promote", summary="Promote candidate to IOC entries")
def promote(candidate_id: int, body: PromoteRequest):
    ioc_id = promote_candidate(
        candidate_id=candidate_id,
        analyst_id=body.analyst_id,
        severity=body.severity,
        confidence=body.confidence,
        description=body.description,
    )
    if ioc_id is None:
        raise HTTPException(status_code=404,
                            detail=f"Candidate {candidate_id} not found or already reviewed.")
    return {"status": "promoted", "ioc_id": ioc_id}


@ioc_router.post("/candidates/{candidate_id}/reject", summary="Reject a candidate as false positive")
def reject(candidate_id: int, body: RejectRequest):
    reject_candidate(candidate_id, body.analyst_id)
    return {"status": "rejected", "candidate_id": candidate_id}


# ---------------------------------------------------------------------------
# CIS rules (read-only via API; write via cis_loader.py CLI)
# ---------------------------------------------------------------------------

@ioc_router.get("/cis", summary="List CIS benchmark rules")
def list_cis(
    section: Optional[str] = Query(None, description="Filter by CIS section"),
    profile_level: str = Query("Level 1", description="Level 1 or Level 2"),
):
    rules = lookup_cis_rules(section=section, profile_level=profile_level)
    return {"rules": rules, "count": len(rules)}


# ---------------------------------------------------------------------------
# IoT thresholds
# ---------------------------------------------------------------------------

@ioc_router.get("/iot-thresholds", summary="List IoT device thresholds")
def list_iot_thresholds(device_type: Optional[str] = Query(None)):
    if device_type:
        rows = lookup_iot_thresholds(device_type)
    else:
        with get_connection(DEFAULT_DB_PATH) as conn:
            rows = [dict(r) for r in conn.execute(
                "SELECT * FROM iot_thresholds WHERE is_active=1"
            ).fetchall()]
    return {"thresholds": rows, "count": len(rows)}


@ioc_router.post("/iot-thresholds", summary="Add or update an IoT device threshold")
def add_iot_threshold(body: IoTThresholdCreate):
    with get_connection(DEFAULT_DB_PATH) as conn:
        conn.execute("""
            INSERT INTO iot_thresholds
                (device_type, metric, threshold_min, threshold_max,
                 severity, description, mitre_technique)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(device_type, metric) DO UPDATE SET
                threshold_min   = excluded.threshold_min,
                threshold_max   = excluded.threshold_max,
                severity        = excluded.severity,
                description     = excluded.description,
                mitre_technique = excluded.mitre_technique
        """, (body.device_type, body.metric, body.threshold_min,
              body.threshold_max, body.severity, body.description,
              body.mitre_technique))
    return {"status": "ok"}