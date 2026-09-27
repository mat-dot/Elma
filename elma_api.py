"""elma_api.py — endpoint HTTP mínimo pra receber SARIF via push.

Pensado pro caso de uso: um step do GitHub Actions roda um scanner
(Semgrep, Trivy, etc.), gera SARIF, e manda pra cá via POST — a Elma
devolve pass/fail com base num limite de severidade, pra falhar o
pipeline quando necessário.

    POST /findings
    Header: Authorization: Bearer <ELMA_API_KEY>
    Body (JSON):
        {
          "sarif": { ...documento SARIF 2.1.0... },
          "fail_on": "HIGH",          # opcional, default HIGH
          "repositorio": "org/repo"   # opcional; compõe a identidade do achado
        }

Resposta: pass/fail + contagens + lista dos achados bloqueadores.

IMPORTANTE — decisão de design deliberada: este endpoint SÓ aceita SARIF
e SEMPRE passa pelo `parse_sarif` de elma_import.py antes de chegar em
`filtrar_achados_novos`. Isso garante que a normalização de severidade
(que hoje vive em elma_import.py) seja sempre aplicada. Não adicione um
caminho que insira achados "crus" direto no banco sem passar por aqui —
foi exatamente esse tipo de segundo caminho que causou o bug de
severidade original.

Limitações conhecidas da v1 (documentadas de propósito, não escondidas):
- Autenticação é 1 API key estática compartilhada, não 1 token por
  repositório. Suficiente pra portfólio/uso pessoal, não pra multi-tenant.
- O campo "repositorio" faz parte da identidade do achado quando informado
    e é persistido no banco. Sem ele, o fingerprint mantém o formato anterior.
"""

import json
import os
import secrets

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from elma_db import FingerprintConflictError, conectar, filtrar_achados_novos
from elma_import import TAMANHO_MAXIMO_SARIF, parse_sarif
from elma_severity import SEVERITY_RANK, avaliar_bloqueio

CAMINHO_BANCO = os.getenv("ELMA_DB_PATH", "elma_findings.db")
FAIL_ON_PADRAO = "HIGH"

app = FastAPI(title="Elma ASPM — Ingestão", version="0.1.0")


class RequisicaoFindings(BaseModel):
    sarif: dict = Field(..., description="Documento SARIF 2.1.0 completo")
    fail_on: str = Field(FAIL_ON_PADRAO, description="CRITICAL|HIGH|MEDIUM|LOW|INFO")
    repositorio: str | None = Field(
        None,
        description="ex.: org/repo — escopa a identidade dos achados",
    )


def _verificar_autenticacao(authorization: str | None) -> None:
    chave_esperada = os.getenv("ELMA_API_KEY")
    if not chave_esperada:
        # Fail-closed: sem chave configurada no servidor, ninguém entra.
        raise HTTPException(status_code=500, detail="ELMA_API_KEY não configurada no servidor")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="token ausente")
    token_recebido = authorization.removeprefix("Bearer ").strip()
    if not secrets.compare_digest(token_recebido, chave_esperada):
        raise HTTPException(status_code=401, detail="token inválido")


@app.post("/findings")
async def receber_findings(
    request: Request,
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)

    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            tamanho_declarado = int(content_length)
        except ValueError as erro:
            raise HTTPException(status_code=400, detail="Content-Length inválido") from erro
        if tamanho_declarado < 0:
            raise HTTPException(status_code=400, detail="Content-Length inválido")
        if tamanho_declarado > TAMANHO_MAXIMO_SARIF:
            raise HTTPException(
                status_code=413,
                detail="payload SARIF excede o limite permitido",
            )

    partes = []
    tamanho_lido = 0
    async for parte in request.stream():
        tamanho_lido += len(parte)
        if tamanho_lido > TAMANHO_MAXIMO_SARIF:
            raise HTTPException(
                status_code=413,
                detail="payload SARIF excede o limite permitido",
            )
        partes.append(parte)

    try:
        dados = json.loads(b"".join(partes))
    except (json.JSONDecodeError, UnicodeDecodeError) as erro:
        raise HTTPException(status_code=422, detail="corpo deve ser JSON válido") from erro
    if not isinstance(dados, dict):
        raise HTTPException(status_code=422, detail="corpo deve ser um objeto JSON")
    try:
        corpo = RequisicaoFindings(**dados)
    except ValidationError as erro:
        raise HTTPException(status_code=422, detail=erro.errors()) from erro

    if corpo.fail_on not in SEVERITY_RANK:
        raise HTTPException(
            status_code=422,
            detail=f"fail_on precisa ser um de: {sorted(SEVERITY_RANK)}",
        )

    try:
        resultados = parse_sarif(corpo.sarif)
    except ValueError as erro:
        raise HTTPException(status_code=422, detail=str(erro)) from erro
    for resultado in resultados:
        resultado["repositorio"] = corpo.repositorio

    conn = conectar(CAMINHO_BANCO)
    try:
        try:
            ativos = filtrar_achados_novos(resultados, conn)
        except FingerprintConflictError as erro:
            # Não decide sozinho qual fingerprint é o certo — reporta e para,
            # igual o comportamento da CLI.
            raise HTTPException(status_code=409, detail=str(erro)) from erro
    finally:
        conn.close()

    bloqueadores, severidades_indefinidas = avaliar_bloqueio(ativos, corpo.fail_on)

    resposta = {
        "aprovado": not bloqueadores,
        "fail_on": corpo.fail_on,
        "repositorio": corpo.repositorio,
        "total_lidos": len(resultados),
        "ativos": len(ativos),
        "bloqueadores": len(bloqueadores),
        "severidades_indefinidas": severidades_indefinidas,
        "detalhes_bloqueadores": [
            {
                "arquivo": achado.get("path"),
                "linha": achado.get("start", {}).get("line"),
                "regra": achado.get("check_id"),
                "severidade": achado.get("severity"),
                "mensagem": achado.get("extra", {}).get("message"),
            }
            for achado in bloqueadores
        ],
    }
    return JSONResponse(status_code=200, content=resposta)


@app.get("/health")
async def health():
    """Sem autenticação — só pra checar se o serviço está de pé (liveness probe)."""
    return {"status": "ok"}
