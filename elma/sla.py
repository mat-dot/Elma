"""SLA de remediação derivado por severidade, sem persistência.

Inspirado no DefectDojo: cada severidade tem um prazo em dias contado a
partir da primeira vez que o finding apareceu. O cálculo é puro e derivado
de ``primeira_vez`` + ``severidade`` + ``status``, então não exige coluna nem
migração no banco — apenas recomputa na leitura.

Prazos padrão (INFO e UNKNOWN ficam sem SLA, como no DefectDojo):
    CRITICAL=15, HIGH=30, MEDIUM=90, LOW=120 dias.

Somente findings abertos (``novo``/``confirmado``) acumulam SLA;
``falso_positivo`` e ``corrigido`` não.

Overrides por ambiente: ``ELMA_SLA_<SEVERIDADE>`` (ex.: ``ELMA_SLA_HIGH=21``)
ajustam o prazo sem tocar no código. Um inteiro não negativo é obrigatório;
valores inválidos levantam ``ValueError``.
"""

import os
from datetime import datetime, timedelta, timezone

from .severity import CANONICAL_SEVERITIES

SLA_DIAS_PADRAO: dict[str, int | None] = {
    "CRITICAL": 15,
    "HIGH": 30,
    "MEDIUM": 90,
    "LOW": 120,
    "INFO": None,
    "UNKNOWN": None,
}
STATUS_COM_SLA = ("novo", "confirmado")


def _normalizar_severidade(valor: object) -> str:
    severidade = str(valor or "UNKNOWN").strip().upper()
    return severidade if severidade in CANONICAL_SEVERITIES else "UNKNOWN"


def _parsear_iso(valor: object) -> datetime | None:
    if not isinstance(valor, str) or not valor:
        return None
    try:
        momento = datetime.fromisoformat(valor)
    except ValueError:
        return None
    return momento if momento.tzinfo else momento.replace(tzinfo=timezone.utc)


def resolver_sla_dias() -> dict[str, int | None]:
    """Return SLA days per severity, honoring ``ELMA_SLA_<SEVERIDADE>`` overrides."""
    dias = dict(SLA_DIAS_PADRAO)
    for severidade in dias:
        bruto = os.getenv(f"ELMA_SLA_{severidade}")
        if bruto is None or not bruto.strip():
            continue
        try:
            valor = int(bruto.strip())
        except ValueError:
            raise ValueError(
                f"ELMA_SLA_{severidade} precisa ser um inteiro de dias"
            ) from None
        if valor < 0:
            raise ValueError(f"ELMA_SLA_{severidade} precisa ser >= 0")
        dias[severidade] = valor
    return dias


def calcular_sla(
    achado: dict,
    agora: datetime | str | None = None,
    sla_dias: dict[str, int | None] | None = None,
) -> dict:
    """Compute the remediation SLA for one finding without external state.

    Returns a dict with ``aplicavel``, ``sla_dias``, ``data_limite`` (ISO date),
    ``dias_restantes`` (negative when overdue) and ``atrasado``. Non-applicable
    cases (closed findings, severities without SLA, missing/invalid ``primeira_vez``)
    return ``aplicavel=False`` with the remaining fields empty.
    """
    dias = sla_dias if sla_dias is not None else resolver_sla_dias()
    severidade = _normalizar_severidade(
        achado.get("severidade") or achado.get("severity")
    )
    status = achado.get("status", "novo")
    prazo = dias.get(severidade)

    base = {
        "severidade": severidade,
        "aplicavel": False,
        "sla_dias": prazo,
        "data_limite": None,
        "dias_restantes": None,
        "atrasado": False,
    }
    if prazo is None or status not in STATUS_COM_SLA:
        return base

    inicio = _parsear_iso(achado.get("primeira_vez"))
    if inicio is None:
        return base

    referencia = agora
    if isinstance(referencia, str):
        referencia = _parsear_iso(referencia)
    referencia = referencia or datetime.now(timezone.utc)
    if referencia.tzinfo is None:
        referencia = referencia.replace(tzinfo=timezone.utc)

    limite = inicio + timedelta(days=prazo)
    dias_restantes = (limite.date() - referencia.date()).days
    return {
        **base,
        "aplicavel": True,
        "data_limite": limite.date().isoformat(),
        "dias_restantes": dias_restantes,
        "atrasado": dias_restantes < 0,
    }


def resumir_sla(
    achados: list[dict],
    agora: datetime | str | None = None,
    sla_dias: dict[str, int | None] | None = None,
) -> dict:
    """Aggregate SLA applicability and overdue counts across findings."""
    dias = sla_dias if sla_dias is not None else resolver_sla_dias()
    aplicaveis = 0
    atrasados = 0
    por_severidade: dict[str, int] = {}
    for achado in achados:
        sla = calcular_sla(achado, agora=agora, sla_dias=dias)
        if not sla["aplicavel"]:
            continue
        aplicaveis += 1
        if sla["atrasado"]:
            atrasados += 1
            chave = sla["severidade"]
            por_severidade[chave] = por_severidade.get(chave, 0) + 1
    return {
        "aplicaveis": aplicaveis,
        "atrasados": atrasados,
        "atrasados_por_severidade": por_severidade,
    }
