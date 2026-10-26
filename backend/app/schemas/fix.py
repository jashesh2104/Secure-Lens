"""Schemas for the self-verifying fix pipeline.

Most tools stop at "here is a suggested fix." SecureLens goes one step further:
it generates the patch, applies it to a throwaway sandbox copy of the file, and
*re-runs a check to prove the vulnerability is gone and the code still parses*
before ever showing it to you. ``verified=True`` therefore means something
concrete — an independent recheck passed — not just that an LLM was confident.

``ProposedFix`` is the LLM's structured output (mockable in tests, exactly like
the triage agent). ``VerifiedFixResult`` is what we persist and return.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

FixStatus = Literal["verified", "unverified", "failed"]


class ProposedFix(BaseModel):
    """The LLM's proposed remediation for a single finding's file."""

    patched_file_content: str = Field(
        description="The full corrected contents of the affected file."
    )
    fix_explanation: str = Field(
        description="Short explanation of what was changed and why it is safe."
    )


class VerificationStep(BaseModel):
    """One independent check run against the patched code."""

    name: str
    passed: bool
    detail: str = ""


class VerifiedFixResult(BaseModel):
    """A proposed fix plus the outcome of independently verifying it."""

    status: FixStatus
    verified: bool
    fix_explanation: str = ""
    unified_diff: str = ""
    patched_file_content: str = ""
    steps: list[VerificationStep] = Field(default_factory=list)
