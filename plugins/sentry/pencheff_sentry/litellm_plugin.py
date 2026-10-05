# SPDX-License-Identifier: AGPL-3.0-or-later
"""LiteLLM hook plugin — pre/post-call inline guardrail.

Drop-in for users who already run LiteLLM. Two callbacks:

* ``pre_call`` runs before the upstream model is hit; a BLOCK verdict
  raises ``litellm.BadRequestError`` with a clear reason so the
  application sees a normal LiteLLM error path.
* ``post_call`` runs on the model's response; a BLOCK verdict mutates
  the choice content to a hard-coded refusal string and stamps a
  ``pencheff_sentry`` metadata block on the LiteLLM response.

Lazy-imports LiteLLM so this module is importable without it; the
hook only registers when LiteLLM is actually present at runtime.

Usage:

    import litellm
    from pencheff_sentry.litellm_plugin import register

    register(litellm)

    # Pencheff Sentry now intercepts every litellm.completion() call.
"""
from __future__ import annotations

from typing import Any, Callable

from .core import (
    GuardrailConfig,
    GuardrailDecision,
    Verdict,
    evaluate_prompt,
    evaluate_response,
)


_DEFAULT_REFUSAL = (
    "I can't help with that — Pencheff Sentry blocked the response "
    "because it contained sensitive content that violates the "
    "deployed guardrail policy."
)


def make_pre_call_hook(
    *, config: GuardrailConfig | None = None,
    on_block: Callable[[GuardrailDecision], None] | None = None,
):
    """Return a LiteLLM-shaped pre_call hook closure."""
    cfg = config or GuardrailConfig()

    def hook(*, kwargs: dict[str, Any], **_) -> None:  # noqa: ANN001 — LiteLLM kw-only
        messages = kwargs.get("messages") or []
        prompt = "\n".join(
            (m.get("content") or "") if isinstance(m.get("content"), str) else ""
            for m in messages
            if m.get("role") in {"system", "user", "tool"}
        )
        decision = evaluate_prompt(prompt, config=cfg)
        if decision.verdict == Verdict.BLOCK:
            if on_block is not None:
                on_block(decision)
            # LiteLLM expects a raised exception to short-circuit.
            try:
                import litellm  # type: ignore[import-not-found]
                err_cls = litellm.BadRequestError
            except ImportError:
                err_cls = ValueError
            raise err_cls(
                f"Pencheff Sentry blocked: {decision.reason}",
            )
    return hook


def make_post_call_hook(
    *, config: GuardrailConfig | None = None,
    on_block: Callable[[GuardrailDecision], None] | None = None,
    refusal_text: str = _DEFAULT_REFUSAL,
):
    """Return a LiteLLM-shaped post_call hook closure.

    Mutates the response in place so the application sees a sanitised
    choice — preferable to a hard error in many cases (the model
    "decided" to refuse).
    """
    cfg = config or GuardrailConfig()

    def hook(*, response: Any, kwargs: dict[str, Any] | None = None, **_) -> Any:
        kwargs = kwargs or {}
        messages = kwargs.get("messages") or []
        prompt = "\n".join(
            (m.get("content") or "") if isinstance(m.get("content"), str) else ""
            for m in messages
            if m.get("role") in {"system", "user", "tool"}
        )
        # LiteLLM responses follow the OpenAI shape: ``response.choices[].message.content``.
        try:
            text = response.choices[0].message.content  # type: ignore[union-attr]
        except (AttributeError, IndexError, TypeError):
            return response

        # Output-token count if LiteLLM exposed usage.
        output_tokens = None
        try:
            output_tokens = response.usage.completion_tokens  # type: ignore[union-attr]
        except AttributeError:
            pass

        decision = evaluate_response(
            prompt, text or "", config=cfg, output_tokens=output_tokens,
        )
        if decision.verdict == Verdict.BLOCK:
            if on_block is not None:
                on_block(decision)
            try:
                response.choices[0].message.content = refusal_text  # type: ignore[union-attr]
            except (AttributeError, IndexError, TypeError):
                return response
            # Side-channel: stamp metadata so callers can detect
            # Sentry intervention without parsing the refusal string.
            try:
                response.pencheff_sentry = {  # type: ignore[union-attr]
                    "blocked": True,
                    "category": decision.category,
                    "detector": decision.detector,
                    "reason": decision.reason,
                }
            except (AttributeError, TypeError):
                pass
        return response
    return hook


def register(litellm_module: Any, *, config: GuardrailConfig | None = None) -> None:
    """One-shot registration. ``litellm.callbacks`` accepts a list of
    callables for both ``input_callback`` and ``success_callback``.
    """
    pre = make_pre_call_hook(config=config)
    post = make_post_call_hook(config=config)
    # Keep additive — don't clobber other callbacks the user wired up.
    litellm_module.input_callback = (
        list(getattr(litellm_module, "input_callback", []) or []) + [pre]
    )
    litellm_module.success_callback = (
        list(getattr(litellm_module, "success_callback", []) or []) + [post]
    )
