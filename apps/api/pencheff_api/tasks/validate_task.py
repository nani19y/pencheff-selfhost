from .celery_app import celery_app
from ..services.finding_validation import validate_scan_findings_sync


@celery_app.task(name="pencheff.scan.validate_findings")
def validate_findings(scan_id: str, mode: str = "standard", finding_ids: list[str] | None = None) -> dict:
    return validate_scan_findings_sync(scan_id, mode, finding_ids)
