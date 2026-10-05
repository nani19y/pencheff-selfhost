"""File upload vulnerability testing."""

from __future__ import annotations

from typing import Any

from pencheff.config import Severity
from pencheff.core.findings import Evidence, Finding
from pencheff.core.http_client import PencheffHTTPClient
from pencheff.core.session import PentestSession
from pencheff.modules.base import BaseTestModule

UPLOAD_PATHS = [
    "/upload", "/api/upload", "/api/v1/upload", "/file/upload",
    "/images/upload", "/media/upload", "/attachments",
    "/api/files", "/api/v1/files",
]


class FileUploadModule(BaseTestModule):
    name = "file_upload"
    category = "file_handling"
    owasp_categories = ["A04"]
    description = "File upload bypass testing"

    def get_techniques(self) -> list[str]:
        return ["extension_bypass", "mime_bypass", "content_type_bypass"]

    async def run(
        self,
        session: PentestSession,
        http: PencheffHTTPClient,
        targets: list[str] | None = None,
        config: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings = []
        base_url = session.target.base_url

        # Find upload endpoints
        upload_urls = []
        for ep in session.discovered.endpoints:
            if any(kw in ep["url"].lower() for kw in ["upload", "file", "attach", "import"]):
                upload_urls.append(ep["url"])

        for path in UPLOAD_PATHS:
            try:
                # OPTIONS as the cheap initial probe — only 200/204 count as
                # a positive signal. 405 was previously accepted, but on a
                # SPA the apex catchall 405s OPTIONS for every unknown path,
                # which then ran 9 dangerous-extension POSTs against each
                # phantom URL. Real REST endpoints that 405 on OPTIONS are
                # still picked up via session.discovered.endpoints above.
                resp = await http.options(f"{base_url}{path}", module="file_upload")
                if resp.status_code not in (200, 204):
                    continue
                # Confirm with a GET — if the body is the SPA's index.html
                # served as a 404 fallback, the path doesn't really exist
                # and POSTing dangerous payloads against it is wasted work.
                confirm = await http.get(f"{base_url}{path}", module="file_upload")
                if confirm.status_code != 200:
                    continue
                body = (getattr(confirm, "text", "") or "")[:2048].lower()
                if any(tok in body for tok in (
                    "<!doctype html",
                    "<html",
                    "404",
                    "not found",
                    "page does not exist",
                )):
                    continue
                upload_urls.append(f"{base_url}{path}")
            except Exception:
                continue

        # Dangerous extensions to test
        test_files = [
            ("test.php", "<?php echo 'pencheff'; ?>", "application/x-php"),
            ("test.jsp", "<% out.println(\"pencheff\"); %>", "application/x-jsp"),
            ("test.aspx", "<%@ Page Language=\"C#\" %>pencheff", "application/x-aspx"),
            ("test.html", "<script>alert('pencheff')</script>", "text/html"),
            ("test.svg", '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "image/svg+xml"),
            # Double extension bypass
            ("test.php.jpg", "<?php echo 'pencheff'; ?>", "image/jpeg"),
            ("test.php%00.jpg", "<?php echo 'pencheff'; ?>", "image/jpeg"),
            # Case variation
            ("test.PHP", "<?php echo 'pencheff'; ?>", "application/x-php"),
            ("test.pHp", "<?php echo 'pencheff'; ?>", "application/x-php"),
        ]

        for url in upload_urls[:5]:
            for filename, content, content_type in test_files:
                try:
                    import io
                    boundary = "----PencheffBoundary"
                    body = (
                        f"--{boundary}\r\n"
                        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
                        f"Content-Type: {content_type}\r\n\r\n"
                        f"{content}\r\n"
                        f"--{boundary}--\r\n"
                    )

                    resp = await http.post(
                        url,
                        body=body,
                        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                        module="file_upload",
                    )

                    if resp.status_code in (200, 201):
                        findings.append(Finding(
                            title=f"Dangerous File Upload Accepted: {filename}",
                            severity=Severity.HIGH if ".php" in filename.lower() or ".jsp" in filename.lower()
                                     else Severity.MEDIUM,
                            category="file_handling",
                            owasp_category="A04",
                            description=f"Upload endpoint accepted '{filename}' with content type '{content_type}'. "
                                        "Executable files on the server can lead to Remote Code Execution.",
                            remediation="Validate file extensions via allowlist (not blocklist). "
                                        "Check magic bytes. Store uploads outside webroot. Rename uploaded files.",
                            endpoint=url,
                            parameter=filename,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                            cvss_score=8.8,
                            cwe_id="CWE-434",
                            evidence=[Evidence(
                                request_method="POST",
                                request_url=url,
                                description=f"Uploaded {filename} ({content_type}): accepted with status {resp.status_code}",
                            )],
                        ))
                        break  # One finding per endpoint
                except Exception:
                    continue

        return findings
