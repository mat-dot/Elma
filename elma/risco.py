"""Pure heuristic risk scoring for Elma findings and assets."""

PESOS_SEVERIDADE = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 1,
    "UNKNOWN": 7,
}
FATORES_EXPOSICAO = {"internet": 1.5, "interna": 1.0}
CRITICIDADE_MINIMA = 0.6
CRITICIDADE_MAXIMA = 1.4
CONFIANCA_IA_ALTA = 8
FATOR_IA_FALSO_POSITIVO = 0.5


def calcular_componentes_score(achado: dict, ativo: dict | None = None) -> dict:
    """Return the score components, without reading or mutating external state."""
    ativo = ativo or {}
    status = achado.get("status", "novo")
    severidade = str(achado.get("severidade") or achado.get("severity") or "UNKNOWN").upper()
    peso_severidade = PESOS_SEVERIDADE.get(severidade, PESOS_SEVERIDADE["UNKNOWN"])
    exposicao = ativo.get("exposicao", "interna")
    fator_exposicao = FATORES_EXPOSICAO.get(exposicao, FATORES_EXPOSICAO["interna"])
    criticidade = ativo.get("criticidade", 3)
    if isinstance(criticidade, bool) or not isinstance(criticidade, (int, float)):
        criticidade = 3
    criticidade = min(5, max(1, criticidade))
    fator_criticidade = CRITICIDADE_MINIMA + (criticidade - 1) * (
        (CRITICIDADE_MAXIMA - CRITICIDADE_MINIMA) / 4
    )
    confianca = achado.get("confianca_ia", achado.get("confianca"))
    sugestao_ia = achado.get("sugestao_ia", achado.get("sugestao"))
    fator_ia = (
        FATOR_IA_FALSO_POSITIVO
        if sugestao_ia == "provavel_falso_positivo"
        and isinstance(confianca, int)
        and not isinstance(confianca, bool)
        and confianca >= CONFIANCA_IA_ALTA
        else 1.0
    )
    score = 0.0 if status in {"falso_positivo", "corrigido"} else (
        peso_severidade * fator_exposicao * fator_criticidade * fator_ia
    )
    return {
        "peso_severidade": peso_severidade,
        "fator_exposicao": fator_exposicao,
        "fator_criticidade": round(fator_criticidade, 2),
        "fator_ia": fator_ia,
        "score": round(score, 2),
    }


def calcular_score(achado: dict, ativo: dict | None = None) -> float:
    """Compute a heuristic priority score, not a definitive security verdict."""
    return calcular_componentes_score(achado, ativo)["score"]
