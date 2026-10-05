"""Static analysis (SAST) coverage for repos attached to a URL pentest."""

from pencheff.modules.sast.runner import SastRunner, run_sast_for_repo

__all__ = ["SastRunner", "run_sast_for_repo"]
