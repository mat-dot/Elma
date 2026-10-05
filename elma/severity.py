# Elma ASPM - Challenge FIAP x PRIDE 2026
# Copyright (C) 2026 Equipe Abutres
# SPDX-License-Identifier: BSD-3-Clause
# Licenciado sob BSD 3-Clause. Veja o arquivo LICENSE.md.

"""Canonical severity normalization shared by SARIF ingestion and DB migration."""

import math
from typing import Any


SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CANONICAL_SEVERITIES = frozenset((*SEVERITY_RANK, "UNKNOWN"))


def normalizar_severidade(valor: Any) -> str:
    """Convert scanner severity aliases and scores to Elma's canonical values."""
    if valor is None:
        return "UNKNOWN"

    severidade = str(valor).strip().upper()
    aliases = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "NOTE": "LOW",
        "NONE": "INFO",
    }
    severidade = aliases.get(severidade, severidade)
    if severidade in CANONICAL_SEVERITIES:
        return severidade

    try:
        score = float(severidade)
    except ValueError:
        return "UNKNOWN"
    if not math.isfinite(score) or not 0 <= score <= 10:
        return "UNKNOWN"
    if score >= 9:
        return "CRITICAL"
    if score >= 7:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


def avaliar_bloqueio(achados: list[dict], fail_on: str) -> tuple[list[dict], int]:
    """Decide quais achados bloqueiam, dado um limite de severidade.

    Severidade ausente/inválida (UNKNOWN) SEMPRE bloqueia, independente de
    fail_on — fail-closed. Única fonte de verdade dessa regra: usada tanto
    pelo comando `elma ci` quanto pela API HTTP, pra não divergir.

    Retorna (achados_bloqueadores, quantidade_com_severidade_indefinida).
    """
    if fail_on not in SEVERITY_RANK:
        raise ValueError(f"fail_on precisa ser um de: {sorted(SEVERITY_RANK)}")
    limite = SEVERITY_RANK[fail_on]
    bloqueadores = []
    indefinidas = 0
    for achado in achados:
        severidade = achado.get("severity")
        if severidade is None:
            severidade = achado.get("severidade")
        rank = SEVERITY_RANK.get(severidade) if isinstance(severidade, str) else None
        if rank is None:
            indefinidas += 1
            bloqueadores.append(achado)
        elif rank >= limite:
            bloqueadores.append(achado)
    return bloqueadores, indefinidas