"""Heuristic regex guardrails for secrets and untrusted LLM input."""

import re


_SECRET_ASSIGNMENT = re.compile(
    r"(?P<prefix>\b(?:api[_-]?key|secret|password|token)\b\s*[:=]\s*)"
    r"(?:(?P<quote>['\"])(?P<quoted>[^'\"]{8,})(?P=quote)"
    r"|(?P<bare>[^\s'\"`,;}\]]{8,}))",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_PROMPT_INJECTION = re.compile(
    r"\b(?:"
    r"ignore\s+(?:(?:all|any)\s+)?(?:(?:previous|prior|preceding)\s+)?instructions?"
    r"|disregard\s+(?:(?:all|any)\s+)?(?:previous|prior|preceding\s+)?(?:instructions?|rules?)"
    r"|you\s+are\s+now"
    r"|reveal\s+(?:the\s+)?(?:system|hidden)\s+(?:prompt|instructions?)"
    r"|show\s+(?:me\s+)?(?:the\s+)?system\s+prompt"
    r")\b",
    re.IGNORECASE,
)
_INJECTION_PLACEHOLDER = "[conteúdo redigido: padrão de prompt injection detectado]"


def _substituir_segredo(match: re.Match[str]) -> str:
    quote = match.group("quote") or ""
    return f"{match.group('prefix')}{quote}[REDACTED]{quote}"


def mascarar_segredos(texto: str) -> str:
    """Mask known credential patterns; regex coverage is heuristic, not exhaustive."""
    texto = texto or ""
    texto = _SECRET_ASSIGNMENT.sub(_substituir_segredo, texto)
    return _AWS_ACCESS_KEY.sub("[REDACTED]", texto)


def sanitizar_para_ia(texto: str) -> str:
    """Replace the full text when a known prompt-injection phrase is detected."""
    texto = texto or ""
    if _PROMPT_INJECTION.search(texto):
        return _INJECTION_PLACEHOLDER
    return texto