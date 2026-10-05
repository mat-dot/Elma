# Elma ASPM - Challenge FIAP x PRIDE 2026
# Copyright (C) 2026 Equipe Abutres
# SPDX-License-Identifier: BSD-3-Clause
# Licenciado sob BSD 3-Clause. Veja o arquivo LICENSE.md.

"""elma.api — endpoint HTTP mínimo pra receber SARIF via push.

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
e SEMPRE passa pelo `parse_sarif` de elma.importer antes de chegar em
`filtrar_achados_novos`. Isso garante que a normalização de severidade
(que hoje vive em elma.importer) seja sempre aplicada. Não adicione um
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
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .db import (
    TIPOS_SCAN,
    FingerprintConflictError,
    atualizar_ativo,
    atualizar_remediacao_ia,
    atualizar_sugestao_ia,
    conectar,
    filtrar_achados_novos,
    inicializar_banco,
    listar_fila,
    marcar_status,
    obter_achado,
    registrar_ativo_se_ausente,
    registrar_importacao,
    resumir_ativos,
    resumir_metricas,
    resumir_postura,
)
from .importer import (
    TAMANHO_MAXIMO_SARIF,
    fechar_ausentes_para_ferramentas,
    ferramentas_no_sarif,
    parse_sarif,
    parse_sarif_com_escopo,
)
from .priorizacao import (
    gerar_remediacoes_estruturadas,
    gerar_sugestoes_estruturadas,
    resolver_configuracao_ia,
)
from .risco import calcular_componentes_score
from .severity import SEVERITY_RANK, avaliar_bloqueio
from .sla import resolver_sla_dias
from .tickets import (
    carregar_config,
    criar_issue_confirmado,
    fechar_issue,
    sincronizar_issues_apos_ingestao,
)
from dotenv import load_dotenv

load_dotenv()
if os.getenv("ELMA_GOOGLE_API_KEY"):
    os.environ.setdefault("GOOGLE_API_KEY", os.environ["ELMA_GOOGLE_API_KEY"])
CAMINHO_BANCO = os.getenv("ELMA_DB_PATH", "elma_findings.db")
FAIL_ON_PADRAO = "HIGH"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gerencia ciclo de vida da aplicação.

    Roda **uma única vez** na inicialização do servidor:
    1. valida a configuração de SLA (``ELMA_SLA_*``) e falha cedo se inválida;
    2. abre conexão SQLite e roda todas as migrações via ``inicializar_banco``;
    3. fecha a conexão de bootstrap.
    """
    try:
        resolver_sla_dias()
    except ValueError as erro:
        raise RuntimeError(f"Configuração de SLA inválida: {erro}") from erro
    conn = inicializar_banco(CAMINHO_BANCO)
    conn.close()
    yield


app = FastAPI(
    title="Elma ASPM — Ingestão",
    version="0.1.0",
    lifespan=lifespan,
)


class RequisicaoFindings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sarif: dict = Field(..., description="Documento SARIF 2.1.0 completo")
    fail_on: str = Field(FAIL_ON_PADRAO, description="CRITICAL|HIGH|MEDIUM|LOW|INFO")
    repositorio: str | None = Field(
        None,
        description="ex.: org/repo — escopa a identidade dos achados",
    )
    tipo_scan: str | None = Field(
        None,
        description=f"tipo do scan: {', '.join(TIPOS_SCAN)}",
    )
    fechar_ausentes: bool = Field(
        False,
        description="fecha findings ausentes somente após runs concluídos sem erro",
    )


class RequisicaoStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["novo", "confirmado", "falso_positivo", "corrigido"]


class RequisicaoAtualizarAtivo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nome: str | None = None
    tipo: Literal["webapp", "api", "lib"] | None = None
    exposicao: Literal["internet", "interna"] | None = None
    criticidade: int | None = Field(None, ge=1, le=5)
    url_alvo: str | None = None


class RequisicaoAnaliseIA(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["gemini", "ollama"] | None = None
    model: str | None = None


class RequisicaoAnaliseEmLote(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fingerprints: list[str] = Field(..., min_length=1, max_length=50)
    provider: Literal["gemini", "ollama"] | None = None
    model: str | None = None


def _verificar_autenticacao(authorization: str | None) -> None:
    chave_esperada = os.getenv("ELMA_API_KEY")
    if not chave_esperada:
        raise HTTPException(status_code=500, detail="ELMA_API_KEY não configurada no servidor")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="token ausente")
    token_recebido = authorization.removeprefix("Bearer ").strip()
    try:
        token_bytes = token_recebido.encode("utf-8")
        chave_bytes = chave_esperada.encode("utf-8")
    except (UnicodeEncodeError, AttributeError):
        raise HTTPException(status_code=401, detail="token inválido")
    if not secrets.compare_digest(token_bytes, chave_bytes):
        raise HTTPException(status_code=401, detail="token inválido")


def _processar_ingestao(
    corpo: RequisicaoFindings,
) -> dict:
    """Executa todo o trabalho CPU-bound e síncrono de ingestão.

    Separado do endpoint async para ser executar em ``run_in_threadpool`` e não
    travar o event loop do ASGI mesmo com payloads de 25 MB.
    """
    inicio_execucao = datetime.now(timezone.utc).isoformat()
    ignorados = {"runs": 0, "resultados": 0}
    ferramentas_identificadas = ferramentas_no_sarif(corpo.sarif)
    sucessos_explicitos = set()
    ferramentas_sem_sucesso_explicito = set()
    try:
        if corpo.fechar_ausentes:
            resultados, ferramentas_ok = parse_sarif_com_escopo(
                corpo.sarif,
                corpo.tipo_scan,
                ignorados,
                sucessos_explicitos,
                ferramentas_sem_sucesso_explicito,
                ferramentas_identificadas,
            )
        else:
            resultados = parse_sarif(corpo.sarif, corpo.tipo_scan, ignorados)
            ferramentas_ok = set()
    except ValueError as erro:
        raise HTTPException(status_code=422, detail=str(erro)) from erro
    for resultado in resultados:
        resultado["repositorio"] = corpo.repositorio

    conn = conectar(CAMINHO_BANCO)
    reabertos_fps: list[str] = []
    fechados_fps: list[str] = []
    resumo_issues = {"reabertas": 0, "fechadas": 0}
    try:
        registrar_ativo_se_ausente(corpo.repositorio, conn)
        contagens = {"novos": 0, "reabertos": 0}
        try:
            ativos = filtrar_achados_novos(
                resultados, conn, agora=inicio_execucao, contagens=contagens,
                reabertos_fps=reabertos_fps,
            )
        except FingerprintConflictError as erro:
            raise HTTPException(status_code=409, detail=str(erro)) from erro
        fechados = 0
        avisos = []
        if corpo.fechar_ausentes and ignorados["runs"] == 0 and ignorados["resultados"] == 0:
            fechados, avisos = fechar_ausentes_para_ferramentas(
                conn,
                corpo.repositorio,
                ferramentas_ok,
                corpo.tipo_scan,
                inicio_execucao,
                sucessos_explicitos=sucessos_explicitos,
                ferramentas_sem_sucesso_explicito=ferramentas_sem_sucesso_explicito,
                fechados_fps=fechados_fps,
            )
        elif corpo.fechar_ausentes:
            avisos.append("Fechamento automático ignorado: o SARIF contém runs/resultados descartados.")
        ferramentas = sorted(
            {
                *ferramentas_ok,
                *ferramentas_identificadas,
                *(
                    resultado.get("tool_name") or resultado.get("ferramenta")
                    for resultado in resultados
                    if resultado.get("tool_name") or resultado.get("ferramenta")
                ),
            }
        )
        registrar_importacao(
            conn,
            corpo.repositorio,
            ", ".join(ferramentas) or None,
            corpo.tipo_scan,
            len(resultados),
            contagens["novos"],
            contagens["reabertos"],
            fechados,
            inicio_execucao,
            ignorados["runs"] + ignorados["resultados"],
        )
        resumo_issues = sincronizar_issues_apos_ingestao(
            conn, reabertos_fps, fechados_fps
        )
    finally:
        conn.close()

    bloqueadores, severidades_indefinidas = avaliar_bloqueio(ativos, corpo.fail_on)
    ignorados_total = ignorados["runs"] + ignorados["resultados"]
    motivo = []
    if bloqueadores:
        motivo.append("severidade")
    if ignorados_total > 0:
        motivo.append("sarif_malformado")

    resposta = {
        "aprovado": not bloqueadores and ignorados_total == 0,
        "fail_on": corpo.fail_on,
        "repositorio": corpo.repositorio,
        "total_lidos": len(resultados),
        "resultados_ignorados": ignorados["resultados"],
        "runs_ignorados": ignorados["runs"],
        "ativos": len(ativos),
        "novos": contagens["novos"],
        "reabertos": contagens["reabertos"],
        "fechar_ausentes": corpo.fechar_ausentes,
        "fechamento_bloqueado": corpo.fechar_ausentes and bool(avisos),
        "motivo_fechamento": "; ".join(avisos) if avisos else None,
        "fechados_automaticamente": fechados,
        "issues_reabertas": resumo_issues["reabertas"],
        "issues_fechadas": resumo_issues["fechadas"],
        "avisos": avisos,
        "bloqueadores": len(bloqueadores),
        "severidades_indefinidas": severidades_indefinidas,
        "motivo_reprovacao": motivo,
        "detalhes_bloqueadores": [
            {
                "arquivo": achado.get("path"),
                "linha": achado.get("start", {}).get("line"),
                "regra": achado.get("check_id"),
                "severidade": achado.get("severity"),
                "mensagem": achado.get("extra", {}).get("message"),
                "possivel_segredo": bool(achado.get("possivel_segredo")),
            }
            for achado in bloqueadores
        ],
    }
    return resposta


@app.post("/findings")
async def receber_findings(
    request: Request,
    authorization: str | None = Header(None),
):
    """Endpoint async — só o I/O do corpo é assíncrono; parse + banco rodam em threadpool."""
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

    if corpo.fechar_ausentes:
        if not corpo.repositorio or not corpo.repositorio.strip():
            raise HTTPException(
                status_code=422,
                detail="repositorio é obrigatório quando fechar_ausentes=true",
            )
        if not corpo.tipo_scan:
            raise HTTPException(
                status_code=422,
                detail="tipo_scan é obrigatório quando fechar_ausentes=true",
            )

    if corpo.fail_on not in SEVERITY_RANK:
        raise HTTPException(
            status_code=422,
            detail=f"fail_on precisa ser um de: {sorted(SEVERITY_RANK)}",
        )

    # A parte CPU-bound (parse SARIF + DB + SQLite) roda em threadpool separado para
    # não travar o event loop do asyncio, mesmo com payload de 25 MB.
    resposta = await run_in_threadpool(_processar_ingestao, corpo)
    return JSONResponse(status_code=200, content=resposta)


@app.get("/postura")
def obter_postura(authorization: str | None = Header(None)):
    _verificar_autenticacao(authorization)
    conn = conectar(CAMINHO_BANCO)
    try:
        return JSONResponse(content=resumir_postura(conn))
    finally:
        conn.close()


@app.get("/metricas")
def obter_metricas(authorization: str | None = Header(None)):
    _verificar_autenticacao(authorization)
    conn = conectar(CAMINHO_BANCO)
    try:
        return JSONResponse(content=resumir_metricas(conn))
    finally:
        conn.close()


@app.get("/ativos")
def obter_ativos(authorization: str | None = Header(None)):
    _verificar_autenticacao(authorization)
    conn = conectar(CAMINHO_BANCO)
    try:
        ativos = resumir_ativos(conn)
        return JSONResponse(content={"items": ativos, "total": len(ativos)})
    finally:
        conn.close()


@app.patch("/ativos/{repositorio:path}")
def atualizar_dados_ativo(
    repositorio: str,
    corpo: RequisicaoAtualizarAtivo,
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)
    campos = corpo.model_dump(exclude_unset=True)
    try:
        conn = conectar(CAMINHO_BANCO)
        try:
            atualizar_ativo(repositorio, campos, conn)
            ativo = next(
                (
                    resumo
                    for resumo in resumir_ativos(conn)
                    if resumo["repositorio"] == repositorio
                ),
                None,
            )
        finally:
            conn.close()
    except ValueError as erro:
        raise HTTPException(status_code=422, detail=str(erro)) from erro
    return JSONResponse(content=ativo)


@app.get("/findings")
def obter_fila_findings(
    status: str | None = None,
    severidade: str | None = None,
    tipo_scan: str | None = None,
    repositorio: str | None = None,
    exposicao: str | None = None,
    criticidade_min: int | None = Query(None, ge=1, le=5),
    possivel_segredo: bool | None = None,
    atrasado: bool | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)
    sla_dias = resolver_sla_dias()
    filtros = {
        chave: valor
        for chave, valor in {
            "status": status,
            "severidade": severidade,
            "tipo_scan": tipo_scan,
            "repositorio": repositorio,
            "exposicao": exposicao,
            "criticidade_min": criticidade_min,
            "possivel_segredo": possivel_segredo,
            "atrasado": atrasado,
        }.items()
        if valor is not None
    }
    conn = conectar(CAMINHO_BANCO)
    try:
        try:
            resultado = listar_fila(conn, filtros, limit, offset, sla_dias=sla_dias)
        except ValueError as erro:
            raise HTTPException(status_code=422, detail=str(erro)) from erro
        return JSONResponse(content=resultado)
    finally:
        conn.close()


@app.get("/findings/{fingerprint}")
def obter_detalhe_finding(
    fingerprint: str,
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)
    conn = conectar(CAMINHO_BANCO)
    try:
        finding = obter_achado(fingerprint, conn)
        if finding is None:
            raise HTTPException(status_code=404, detail="finding não encontrado")
        ativo = None
        if finding.get("repositorio"):
            row = conn.execute(
                """SELECT repositorio, nome, tipo, exposicao, criticidade, url_alvo,
                          criado_em FROM ativos WHERE repositorio = ?""",
                (finding["repositorio"],),
            ).fetchone()
            if row:
                ativo = dict(
                    zip(
                        (
                            "repositorio", "nome", "tipo", "exposicao", "criticidade",
                            "url_alvo", "criado_em",
                        ),
                        row,
                    )
                )
        componentes = calcular_componentes_score(finding, ativo)
        return JSONResponse(
            content={
                **finding,
                "ativo": ativo,
                "score": componentes["score"],
                "score_componentes": componentes,
            }
        )
    finally:
        conn.close()


@app.get("/ai/config")
def obter_configuracao_ia_dashboard(authorization: str | None = Header(None)):
    _verificar_autenticacao(authorization)
    provider, model, base_url = resolver_configuracao_ia()
    modelos = {
        nome: resolver_configuracao_ia(provider=nome)[1]
        for nome in ("gemini", "ollama")
    }
    return JSONResponse(
        content={
            "provider": provider,
            "model": model,
            "base_url": base_url,
            "providers": ["gemini", "ollama"],
            "modelos": modelos,
        }
    )


@app.post("/findings/{fingerprint}/analyze")
def analisar_finding_por_ia(
    fingerprint: str,
    corpo: RequisicaoAnaliseIA | None = None,
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)
    corpo = corpo or RequisicaoAnaliseIA()
    conn = conectar(CAMINHO_BANCO)
    try:
        achado = obter_achado(fingerprint, conn)
        if achado is None:
            raise HTTPException(status_code=404, detail="finding não encontrado")
        try:
            sugestoes = gerar_sugestoes_estruturadas(
                [achado], provider=corpo.provider, model=corpo.model, strict=True
            )
        except (ValueError, RuntimeError) as erro:
            raise HTTPException(status_code=503, detail=str(erro)) from erro
        resultado = next((item for item in sugestoes if item["fingerprint"] == fingerprint), None)
        if resultado is None:
            return JSONResponse(content={"fingerprint": fingerprint, "updated": 0, "provider": corpo.provider, "model": corpo.model})
        atualizado = atualizar_sugestao_ia(
            fingerprint,
            resultado["sugestao"],
            resultado["confianca"],
            resultado["justificativa"],
            conn,
        )
        return JSONResponse(
            content={
                "fingerprint": fingerprint,
                "updated": 1 if atualizado else 0,
                "provider": corpo.provider or resolver_configuracao_ia()[0],
                "model": corpo.model or resolver_configuracao_ia()[1],
                "result": resultado,
            }
        )
    finally:
        conn.close()


@app.post("/findings/analyze")
def analisar_findings_em_lote_por_ia(
    corpo: RequisicaoAnaliseEmLote,
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)
    conn = conectar(CAMINHO_BANCO)
    try:
        achados = []
        for fingerprint in corpo.fingerprints:
            achado = obter_achado(fingerprint, conn)
            if achado is not None:
                achados.append(achado)
        try:
            sugestoes = gerar_sugestoes_estruturadas(
                achados, provider=corpo.provider, model=corpo.model, strict=True
            )
        except (ValueError, RuntimeError) as erro:
            raise HTTPException(status_code=503, detail=str(erro)) from erro
        resultados = []
        for item in sugestoes:
            fingerprint = item["fingerprint"]
            if atualizar_sugestao_ia(
                fingerprint,
                item["sugestao"],
                item["confianca"],
                item["justificativa"],
                conn,
            ):
                resultados.append({"fingerprint": fingerprint, **item})
        return JSONResponse(
            content={
                "updated": len(resultados),
                "items": resultados,
                "provider": corpo.provider or resolver_configuracao_ia()[0],
                "model": corpo.model or resolver_configuracao_ia()[1],
            }
        )
    finally:
        conn.close()


@app.post("/findings/{fingerprint}/remediate")
def remediar_finding_por_ia(
    fingerprint: str,
    corpo: RequisicaoAnaliseIA | None = None,
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)
    corpo = corpo or RequisicaoAnaliseIA()
    conn = conectar(CAMINHO_BANCO)
    try:
        achado = obter_achado(fingerprint, conn)
        if achado is None:
            raise HTTPException(status_code=404, detail="finding não encontrado")
        try:
            remediacoes = gerar_remediacoes_estruturadas(
                [achado], provider=corpo.provider, model=corpo.model, strict=True
            )
        except (ValueError, RuntimeError) as erro:
            raise HTTPException(status_code=503, detail=str(erro)) from erro
        resultado = next(
            (item for item in remediacoes if item["fingerprint"] == fingerprint), None
        )
        if resultado is None or resultado["remediacao"] is None:
            raise HTTPException(
                status_code=503,
                detail="não foi possível gerar a remediação para este finding",
            )
        atualizado = atualizar_remediacao_ia(fingerprint, resultado["remediacao"], conn)
        return JSONResponse(
            content={
                "fingerprint": fingerprint,
                "updated": 1 if atualizado else 0,
                "provider": corpo.provider or resolver_configuracao_ia()[0],
                "model": corpo.model or resolver_configuracao_ia()[1],
                "result": resultado,
            }
        )
    finally:
        conn.close()


@app.post("/findings/remediate")
def remediar_findings_em_lote_por_ia(
    corpo: RequisicaoAnaliseEmLote,
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)
    conn = conectar(CAMINHO_BANCO)
    try:
        achados = []
        for fingerprint in corpo.fingerprints:
            achado = obter_achado(fingerprint, conn)
            if achado is not None:
                achados.append(achado)
        try:
            remediacoes = gerar_remediacoes_estruturadas(
                achados, provider=corpo.provider, model=corpo.model, strict=True
            )
        except (ValueError, RuntimeError) as erro:
            raise HTTPException(status_code=503, detail=str(erro)) from erro
        resultados = []
        for item in remediacoes:
            if item["remediacao"] is None:
                continue
            fingerprint = item["fingerprint"]
            if atualizar_remediacao_ia(fingerprint, item["remediacao"], conn):
                resultados.append({"fingerprint": fingerprint, **item})
        if achados and not resultados:
            raise HTTPException(
                status_code=503,
                detail="não foi possível gerar remediação para nenhum finding do lote",
            )
        return JSONResponse(
            content={
                "updated": len(resultados),
                "items": resultados,
                "provider": corpo.provider or resolver_configuracao_ia()[0],
                "model": corpo.model or resolver_configuracao_ia()[1],
            }
        )
    finally:
        conn.close()


@app.post("/findings/{fingerprint}/status")
def atualizar_status_finding(
    fingerprint: str,
    corpo: RequisicaoStatus,
    authorization: str | None = Header(None),
):
    _verificar_autenticacao(authorization)
    conn = conectar(CAMINHO_BANCO)
    try:
        if not marcar_status(fingerprint, corpo.status, conn):
            raise HTTPException(status_code=404, detail="finding não encontrado")
        ticket = None
        if corpo.status == "confirmado":
            ticket = criar_issue_confirmado(fingerprint, conn)
        elif corpo.status == "corrigido":
            ticket = fechar_issue(fingerprint, conn, carregar_config())
        return JSONResponse(
            content={
                "fingerprint": fingerprint,
                "status": corpo.status,
                "ticket": ticket,
            }
        )
    finally:
        conn.close()


@app.get("/painel")
def servir_painel():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/health")
def health():
    """Sem autenticação — só pra checar se o serviço está de pé (liveness probe)."""
    return {"status": "ok"}
