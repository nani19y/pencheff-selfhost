"""CTF auto-solver (Phase 3.1).

The classifier in :mod:`solver` triages a challenge file or text, then routes
to the appropriate sub-solver. Decisions are pattern-based; nothing here
calls an LLM. Replaces the ``CTFWorkflowManager`` agent with deterministic
rules.
"""
