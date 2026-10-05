"""R2 (S3-compatible) object storage for uploaded source-code archives and the
agent-fixed .zip outputs.

Reuses the Security Lake R2 credentials (``settings.r2_*``) and the
``r2_uploads_bucket`` bucket. Objects are namespaced by prefix:

    uploads/<workspace_id>/<uuid>/<filename>   — operator-supplied source archive
    fixes/<run_id>/fixed.zip                    — agent-fixed tree, zipped

boto3 calls are blocking; async callers MUST wrap these in
``starlette.concurrency.run_in_threadpool``.
"""
from __future__ import annotations

from ..config import get_settings


def storage_configured() -> bool:
    s = get_settings()
    return bool(
        s.r2_endpoint_url and s.r2_access_key_id and s.r2_secret_access_key
    )


def _client():
    import boto3  # available in the api/worker image

    s = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=s.r2_endpoint_url,
        aws_access_key_id=s.r2_access_key_id,
        aws_secret_access_key=s.r2_secret_access_key,
        region_name="auto",  # R2 ignores region but boto3 requires one
    )


def _bucket() -> str:
    return get_settings().r2_uploads_bucket


def put_bytes(
    key: str, data: bytes, content_type: str = "application/octet-stream"
) -> None:
    _client().put_object(
        Bucket=_bucket(), Key=key, Body=data, ContentType=content_type
    )


def get_bytes(key: str) -> bytes:
    obj = _client().get_object(Bucket=_bucket(), Key=key)
    return obj["Body"].read()


def presigned_get(
    key: str, *, expires: int = 3600, download_name: str | None = None
) -> str:
    """Short-lived presigned GET URL. When ``download_name`` is set the object
    is served as an attachment with that filename."""
    params: dict = {"Bucket": _bucket(), "Key": key}
    if download_name:
        # Guard the header against quote/CRLF injection via the filename.
        safe = download_name.replace('"', "").replace("\n", "").replace("\r", "")
        params["ResponseContentDisposition"] = f'attachment; filename="{safe}"'
    return _client().generate_presigned_url(
        "get_object", Params=params, ExpiresIn=expires
    )


def delete(key: str) -> None:
    try:
        _client().delete_object(Bucket=_bucket(), Key=key)
    except Exception:  # noqa: BLE001 — best-effort cleanup, never raise
        pass


def object_exists(key: str) -> bool:
    try:
        _client().head_object(Bucket=_bucket(), Key=key)
        return True
    except Exception:  # noqa: BLE001
        return False


# ── Archive helpers (safe extract / zip) ────────────────────────────────────
# Mirrors the guards in plugins/pencheff artifact_download_extract (the plugin
# can't import this API module), used by the agentic fixer's upload path.

_MAX_UNCOMPRESSED = 500 * 1024 * 1024  # 500 MiB
_MAX_FILES = 50_000


def extract_archive(data: bytes, dest) -> int:
    """Safely extract a .zip / .tar.gz byte blob into ``dest`` (a Path).

    Guards: uncompressed-size + entry-count caps (zip-bomb) and per-entry
    path-traversal checks (zip) / tarfile ``data`` filter (tar). Returns the
    number of entries seen. Raises ValueError on a non-archive / oversized blob.
    """
    import io
    import shutil
    import tarfile
    import zipfile
    from pathlib import Path

    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    total = 0
    files = 0
    buf = io.BytesIO(data)

    if zipfile.is_zipfile(buf):
        buf.seek(0)
        with zipfile.ZipFile(buf) as z:
            for info in z.infolist():
                files += 1
                if files > _MAX_FILES:
                    raise ValueError("archive has too many entries")
                total += info.file_size
                if total > _MAX_UNCOMPRESSED:
                    raise ValueError("archive too large uncompressed")
                target = (dest / info.filename).resolve()
                if target != root and root not in target.parents:
                    continue  # path-traversal — skip
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with z.open(info) as src, open(target, "wb") as out:
                    shutil.copyfileobj(src, out)
        return files

    buf.seek(0)
    try:
        with tarfile.open(fileobj=buf, mode="r:*") as t:
            for m in t.getmembers():
                files += 1
                if files > _MAX_FILES:
                    raise ValueError("archive has too many entries")
                total += max(m.size, 0)
                if total > _MAX_UNCOMPRESSED:
                    raise ValueError("archive too large uncompressed")
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r:*") as t2:
            try:
                t2.extractall(dest, filter="data")
            except TypeError:  # pragma: no cover — pre-3.12
                for m in t2.getmembers():
                    if not (m.isfile() or m.isdir()):
                        continue
                    target = (dest / m.name).resolve()
                    if target != root and root not in target.parents:
                        continue
                    t2.extract(m, dest)
        return files
    except tarfile.TarError as exc:
        raise ValueError(f"not a valid zip or tar.gz archive: {exc}") from exc


def zip_dir(root) -> bytes:
    """Zip every file under ``root`` (repo-relative paths) and return the bytes."""
    import io
    import zipfile
    from pathlib import Path

    root = Path(root)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                z.write(p, arcname=str(p.relative_to(root)))
    return out.getvalue()
