"""Source-code upload endpoint.

Accepts a .zip / .tar.gz archive (the browser zips a picked folder client-side,
or the operator uploads an archive directly) and stores it in R2 under
``uploads/<workspace>/<uuid>/<file>``. Returns the object key, which the caller
puts on a source_code target's ``kind_config.upload_key`` (source="upload").
The scan then fetches + extracts it (see artifact orchestrator).
"""
import hashlib
import uuid

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from starlette.concurrency import run_in_threadpool

from ..auth.deps import get_active_workspace, require_scope
from ..config import get_settings
from ..db.models import Workspace
from ..services import upload_storage

router = APIRouter(prefix="/uploads", tags=["uploads"])

# Archive magic bytes — zip (PK..) and gzip (1f 8b, i.e. .tar.gz / .tgz).
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC = b"\x1f\x8b"


def _detect_archive(data: bytes) -> str | None:
    if data.startswith(_ZIP_MAGICS):
        return "zip"
    if data.startswith(_GZIP_MAGIC):
        return "gzip"
    return None


@router.post("", dependencies=[Depends(require_scope("targets:write"))])
async def upload_source_archive(
    file: UploadFile = File(...),
    workspace: Workspace = Depends(get_active_workspace),
) -> dict:
    if not upload_storage.storage_configured():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Upload storage (R2) is not configured on this deployment.",
        )
    settings = get_settings()
    cap = settings.source_upload_max_bytes
    # Read one byte past the cap so we can reject oversized uploads without
    # buffering the whole thing (Starlette spools the multipart body to disk).
    data = await file.read(cap + 1)
    if len(data) > cap:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Upload exceeds the {cap // (1024 * 1024)} MiB limit.",
        )
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Empty upload.")
    kind = _detect_archive(data)
    if kind is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Upload must be a .zip or .tar.gz archive.",
        )

    raw = (file.filename or "source").rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    safe = "".join(c for c in raw if c.isalnum() or c in "._-") or "source"
    if not safe.endswith((".zip", ".tar.gz", ".tgz")):
        safe += ".zip" if kind == "zip" else ".tar.gz"

    key = f"uploads/{workspace.id}/{uuid.uuid4().hex}/{safe}"
    ct = "application/zip" if kind == "zip" else "application/gzip"
    sha256 = hashlib.sha256(data).hexdigest()
    await run_in_threadpool(upload_storage.put_bytes, key, data, ct)
    return {
        "key": key,
        "filename": safe,
        "size": len(data),
        "archive": kind,
        "sha256": sha256,
    }
