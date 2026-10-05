from .celery_app import celery_app
from ..services.reports import generate_report_sync


@celery_app.task(name="pencheff.report.generate")
def generate_report(report_id: str) -> None:
    generate_report_sync(report_id)
