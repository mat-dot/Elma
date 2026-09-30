"""Métricas derivadas de postura (aging, MTTR, tendência), sem persistência.

Inspirado no DefectDojo: métricas de vulnerabilidade calculadas de forma
derivada dos dados já armazenados — timestamps dos findings (``primeira_vez``,
``fechado_automaticamente_em``) e o histórico da tabela ``importacoes``. Não
exige coluna nova nem migração; apenas recomputa na leitura, como o SLA.

- **Aging**: idade dos findings abertos (``novo``/``confirmado``) em dias desde
  ``primeira_vez``, com média/mediana/máximo e distribuição por faixa.
- **MTTR**: tempo médio de resolução dos findings ``corrigido``. Apenas os que
  gravaram um timestamp de resolução (``fechado_automaticamente_em``, definido
  no fechamento automático) entram na amostra; findings corrigidos manualmente
  não gravam esse timestamp, então ``amostra``/``corrigidos`` expõem a cobertura.
- **Tendência**: ``novos``/``fechados``/``lidos`` agregados por dia a partir do
  histórico de importações.
"""

import statistics
from datetime import datetime, timezone

from .sla import resumir_sla

STATUS_ABERTOS = ("novo", "confirmado")
# (chave, mínimo, máximo) em dias inteiros; máximo None significa "sem teto".
FAIXAS_AGING = (
    ("0_30", 0, 30),
    ("31_60", 31, 60),
    ("61_90", 61, 90),
    ("90_plus", 91, None),
)
ROTULOS_FAIXAS = {
    "0_30": "0–30 dias",
    "31_60": "31–60 dias",
    "61_90": "61–90 dias",
    "90_plus": "90+ dias",
}


def _parsear_iso(valor: object) -> datetime | None:
    if not isinstance(valor, str) or not valor:
        return None
    try:
        momento = datetime.fromisoformat(valor)
    except ValueError:
        return None
    return momento if momento.tzinfo else momento.replace(tzinfo=timezone.utc)


def _resolver_referencia(agora: datetime | str | None) -> datetime:
    referencia = agora
    if isinstance(referencia, str):
        referencia = _parsear_iso(referencia)
    referencia = referencia or datetime.now(timezone.utc)
    if referencia.tzinfo is None:
        referencia = referencia.replace(tzinfo=timezone.utc)
    return referencia


def _dias_entre(inicio: datetime, fim: datetime) -> int:
    """Whole days from ``inicio`` to ``fim``, clamped at zero."""
    dias = (fim - inicio).days
    return dias if dias >= 0 else 0


def _media(valores: list[int]) -> float | None:
    return round(statistics.fmean(valores), 1) if valores else None


def _mediana(valores: list[int]) -> float | None:
    return round(statistics.median(valores), 1) if valores else None


def calcular_aging(
    achados: list[dict], agora: datetime | str | None = None
) -> dict:
    """Bucket open findings by age (days since ``primeira_vez``)."""
    referencia = _resolver_referencia(agora)
    idades: list[int] = []
    for achado in achados:
        if achado.get("status", "novo") not in STATUS_ABERTOS:
            continue
        inicio = _parsear_iso(achado.get("primeira_vez"))
        if inicio is None:
            continue
        idades.append(_dias_entre(inicio, referencia))

    faixas = {chave: 0 for chave, _, _ in FAIXAS_AGING}
    for idade in idades:
        for chave, minimo, maximo in FAIXAS_AGING:
            if idade >= minimo and (maximo is None or idade <= maximo):
                faixas[chave] += 1
                break

    return {
        "abertos": len(idades),
        "idade_media_dias": _media(idades),
        "idade_mediana_dias": _mediana(idades),
        "idade_maxima_dias": max(idades) if idades else None,
        "faixas": faixas,
    }


def calcular_mttr(achados: list[dict]) -> dict:
    """Mean/median days from first-seen to resolution for corrected findings.

    Only findings carrying a resolution timestamp (``fechado_automaticamente_em``)
    are measurable; ``amostra`` vs ``corrigidos`` reports that coverage so the
    number is never read as covering manually-corrected findings.
    """
    corrigidos = 0
    duracoes: list[int] = []
    for achado in achados:
        if achado.get("status") != "corrigido":
            continue
        corrigidos += 1
        inicio = _parsear_iso(achado.get("primeira_vez"))
        resolucao = _parsear_iso(achado.get("fechado_automaticamente_em"))
        if inicio is None or resolucao is None:
            continue
        duracoes.append(_dias_entre(inicio, resolucao))

    return {
        "corrigidos": corrigidos,
        "amostra": len(duracoes),
        "mttr_dias": _media(duracoes),
        "mttr_mediano_dias": _mediana(duracoes),
    }


def calcular_tendencia(importacoes: list[dict]) -> list[dict]:
    """Aggregate import-history rows into a per-day series, oldest first."""
    por_dia: dict[str, dict] = {}
    for registro in importacoes:
        data = _parsear_iso(registro.get("data"))
        if data is None:
            continue
        chave = data.date().isoformat()
        dia = por_dia.setdefault(
            chave, {"data": chave, "novos": 0, "fechados": 0, "lidos": 0}
        )
        dia["novos"] += int(registro.get("novos") or 0)
        dia["fechados"] += int(registro.get("fechados") or 0)
        dia["lidos"] += int(registro.get("lidos") or 0)
    return [por_dia[chave] for chave in sorted(por_dia)]


def resumir_metricas(
    achados: list[dict],
    importacoes: list[dict],
    agora: datetime | str | None = None,
    sla_dias: dict[str, int | None] | None = None,
) -> dict:
    """Combine aging, MTTR, trend and SLA into one derived metrics summary."""
    return {
        "aging": calcular_aging(achados, agora=agora),
        "mttr": calcular_mttr(achados),
        "tendencia": calcular_tendencia(importacoes),
        "sla": resumir_sla(achados, agora=agora, sla_dias=sla_dias),
    }
