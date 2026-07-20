from fastapi import APIRouter, HTTPException

from app.core.lab import AttemptResult, LabMetadata
from app.labs import get_lab, list_labs

router = APIRouter(prefix="/labs", tags=["labs"])


@router.get("", response_model=list[LabMetadata])
def get_labs() -> list[LabMetadata]:
    return [lab.metadata for lab in list_labs()]


@router.get("/{lab_id}", response_model=LabMetadata)
def get_lab_metadata(lab_id: str) -> LabMetadata:
    lab = get_lab(lab_id)
    if lab is None:
        raise HTTPException(status_code=404, detail=f"랩을 찾을 수 없습니다: {lab_id}")
    return lab.metadata


@router.post("/{lab_id}/attempt", response_model=AttemptResult)
def attempt_lab(lab_id: str, payload: dict) -> AttemptResult:
    lab = get_lab(lab_id)
    if lab is None:
        raise HTTPException(status_code=404, detail=f"랩을 찾을 수 없습니다: {lab_id}")
    return lab.attempt(payload)
