from .celery_app import celery_app
from ..services.recheck import recheck_sync


@celery_app.task(name="pencheff.finding.recheck")
def recheck_finding(finding_id: str) -> str:
    return recheck_sync(finding_id)
