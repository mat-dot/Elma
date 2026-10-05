# Elma ASPM - Challenge FIAP x PRIDE 2026
# Copyright (C) 2026 Equipe Abutres
# SPDX-License-Identifier: BSD-3-Clause
# Licenciado sob BSD 3-Clause. Veja o arquivo LICENSE.md.

"""Heuristic regex guardrails for secrets and untrusted LLM input.

Padrões de segredo:
- Palavras-chave seguidas de ``:`` ou ``=``, com ou sem prefixo variável (ex.:
  ``db_password``, ``client_secret``, ``access_token``, ``x_api_key``).
- O prefixo é limitado a 64 caracteres e ancorado por um lookbehind negativo
  para evitar retrocesso exponencial (ReDoS) em entradas gigantes.
- Exceção explícita: somente a palavra-chave seguida de ``hash``
  (``password_hash``, ``pwd_hash`` e ``passwd_hash``) não é mascarada,
  porque representa um hash de senha e não um valor sensível em texto puro.
- Cobertura de objetos JSON: ``{"password": "..."}`` / ``"api_key": "..."``.
- Caso conhecido: ``csrf_token = generate_token()`` é mascarado e não é uma
  exceção; a documentação anterior estava desatualizada.
"""

import re


_SECRET_ASSIGNMENT = re.compile(
    r"(?P<prefix>"
    r"(?<![A-Za-z0-9_-])"
    r"[A-Za-z0-9_-]{0,64}?"
    r"(?:api[_-]?key|secret(?:[_-]?(?:access[_-]?)?key)?|password|passwd|token)"
    r"(?![_-]?hash)"
    r"\s*[:=]\s*"
    r")"
    r"(?!\[REDACTED\])"
    r"(?P<value>"
    r"(?:"
    r"(?P<quote>['\"])(?P<quoted>[^'\"]{8,})(?P=quote)"
    r"|"
    r"(?P<bare>[^\s'\"`,;\}\]]{8,})"
    r")"
    r")",
    re.IGNORECASE,
)
_JSON_QUOTED_SECRET = re.compile(
    r"(?P<prefix>"
    r"(?<![A-Za-z0-9_-])"
    r"[\"'][^\"']{0,64}?"
    r"(?:api[_-]?key|secret(?:[_-]?(?:access[_-]?)?key)?|password|passwd|token)"
    r"(?!(?:[_-])?hash)"
    r"[\"']\s*:\s*"
    r")"
    r"(?!\[REDACTED\])"
    r"(?:(?P<quote>['\"])(?P<quoted>[^'\"]{8,})(?P=quote)"
    r"|(?P<bare>[^\s'\"`,;}\]]{8,}))",
    re.IGNORECASE,
)
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_AWS_SECRET_KEY = re.compile(
    r"(?P<prefix>"
    r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{0,32}?"
    r"(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)"
    r"\s*[:=]\s*"
    r")"
    r"(?:(?P<quote>['\"])(?P<quoted>[A-Za-z0-9/+=]{40})(?P=quote)"
    r"|(?P<bare>[A-Za-z0-9/+=]{40}))",
    re.IGNORECASE,
)
_GITHUB_TOKEN = re.compile(
    r"\b(?:ghp_|gho_|ghs_|github_pat_)[A-Za-z0-9_]{20,}\b", re.IGNORECASE
)
_GOOGLE_API_KEY = re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", re.IGNORECASE)
# PEM content beyond the 8192-character body limit is not fully masked.
_PRIVATE_KEY_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
    r"[A-Za-z0-9+/=\s]{0,8192}"
    r"(?:-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----)?",
    re.IGNORECASE,
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"
    r"\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])"
)
_URL_PASSWORD = re.compile(
    r"(?P<prefix>(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{0,31}://[^:/@\s]+:)"
    r"(?P<password>[^/@\s]+)(?P<suffix>@)",
    re.IGNORECASE,
)
_CPF_FORMATADO = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b")
_CNPJ_FORMATADO = re.compile(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b")
_CPF_SEM_FORMATACAO = re.compile(r"(\bcpf\b\s*[:=]?\s*)\d{11}\b", re.IGNORECASE)
_PROMPT_INJECTION = re.compile(
    r"\b(?:"
    r"ignore\s+(?:(?:all|any)\s+)?(?:(?:previous|prior|preceding)\s+)?instructions?"
    r"|disregard\s+(?:(?:all|any)\s+)?(?:(?:previous|prior|preceding)\s+)?(?:instructions?|rules?)"
    r"|you\s+are\s+now"
    r"|reveal\s+(?:the\s+)?(?:system|hidden)\s+(?:prompt|instructions?)"
    r"|show\s+(?:me\s+)?(?:the\s+)?system\s+prompt"
    r"|(?:ignore|ignorar|desconsidere|desconsiderar|esquece|esqueça|esqueca|esquecer)"
    r"\s+(?:(?:todas?)\s+)?(?:as\s+)?instru[cç](?:[õo]es)\s+anteriores"
    r"|voc[eê]\s+agora\s+[ée]"
    r"|(?:revele|revela|revelar|mostre|mostra|mostrar)\s+"
    r"(?:(?:me|para\s+mim)\s+)?(?:o\s+)?prompt\s+(?:do|de)\s+sistema"
    r")\b",
    re.IGNORECASE,
)
_INJECTION_PLACEHOLDER = "[conteúdo redigido: padrão de prompt injection detectado]"


def _substituir_segredo(match: re.Match[str]) -> str:
    quote = match.group("quote") or ""
    return f"{match.group('prefix')}{quote}[REDACTED]{quote}"


_substituir_json_secret = _substituir_segredo
_substituir_aws_secret = _substituir_segredo


def mascarar_segredos(texto: str) -> str:
    """Mask known credential patterns; regex coverage is heuristic, not exhaustive."""
    texto = texto or ""
    texto = _URL_PASSWORD.sub(r"\g<prefix>[REDACTED]\g<suffix>", texto)
    texto = _PRIVATE_KEY_PEM.sub("[REDACTED]", texto)
    texto = _GITHUB_TOKEN.sub("[REDACTED]", texto)
    texto = _GOOGLE_API_KEY.sub("[REDACTED]", texto)
    texto = _SLACK_TOKEN.sub("[REDACTED]", texto)
    texto = _JWT.sub("[REDACTED]", texto)
    texto = _CPF_FORMATADO.sub("[REDACTED]", texto)
    texto = _CNPJ_FORMATADO.sub("[REDACTED]", texto)
    texto = _CPF_SEM_FORMATACAO.sub(r"\g<1>[REDACTED]", texto)
    texto = _AWS_SECRET_KEY.sub(_substituir_aws_secret, texto)
    texto = _JSON_QUOTED_SECRET.sub(_substituir_json_secret, texto)
    texto = _SECRET_ASSIGNMENT.sub(_substituir_segredo, texto)
    texto = _AWS_ACCESS_KEY.sub("[REDACTED]", texto)
    return texto


def sanitizar_para_ia(texto: str) -> str:
    """Replace the full text when a known prompt-injection phrase is detected."""
    texto = texto or ""
    if _PROMPT_INJECTION.search(texto):
        return _INJECTION_PLACEHOLDER
    return texto