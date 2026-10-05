# Elma ASPM - Challenge FIAP x PRIDE 2026
# Copyright (C) 2026 Equipe Abutres
# SPDX-License-Identifier: BSD-3-Clause
# Licenciado sob BSD 3-Clause. Veja o arquivo LICENSE.md.

"""Parsing local de relatórios SARIF para o formato de findings da Elma."""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from .db import (
    TIPOS_SCAN,
    conectar,
    fechar_ausentes,
    filtrar_achados_novos,
    registrar_ativo_se_ausente,
    registrar_importacao,
)
from .guardrails import mascarar_segredos
from .severity import normalizar_severidade

TAMANHO_MAXIMO_SARIF = 25 * 1024 * 1024
TAGS_SEVERIDADE = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN",
    "ERROR", "WARNING", "NOTE", "NONE",
}
LOGGER = logging.getLogger(__name__)


def ferramentas_no_sarif(documento: dict[str, Any]) -> set[str]:
    """Return named tools from structurally valid SARIF runs."""
    ferramentas = set()
    runs = documento.get("runs")
    if not isinstance(runs, list):
        return ferramentas
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        nome = driver.get("name") if isinstance(driver, dict) else None
        if isinstance(nome, str) and nome:
            ferramentas.add(nome)
    return ferramentas


def _severity(properties: dict[str, Any]) -> str | None:
    for key in ("security-severity", "severity"):
        value = properties.get(key)
        if value not in (None, ""):
            return str(value)
    tags = properties.get("tags", [])
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.upper() in TAGS_SEVERIDADE:
                return tag
    return None


def parse_sarif(
    documento: dict[str, Any],
    tipo_scan: str | None = None,
    ignorados: dict[str, int] | None = None,
) -> list[dict[str, Any]]:
    """Converte resultados SARIF 2.1.0 para o formato aceito pelo SQLite da Elma."""
    if ignorados is None:
        ignorados = {"runs": 0, "resultados": 0}
    else:
        ignorados["runs"] = ignorados.get("runs", 0)
        ignorados["resultados"] = ignorados.get("resultados", 0)
    if tipo_scan is not None and tipo_scan not in TIPOS_SCAN:
        raise ValueError(f"tipo precisa ser um de: {TIPOS_SCAN}")
    if not isinstance(documento, dict):
        raise ValueError("o documento SARIF deve ser um objeto JSON")
    if documento.get("version") != "2.1.0":
        raise ValueError("versão SARIF não suportada; esperado 2.1.0")
    runs = documento.get("runs")
    if not isinstance(runs, list):
        raise ValueError("documento SARIF sem a lista 'runs'")

    findings: list[dict[str, Any]] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            ignorados["runs"] = ignorados.get("runs", 0) + 1
            LOGGER.warning("Ignorando run SARIF %d: estrutura inválida", run_index)
            continue
        try:
            tool_data = run.get("tool", {})
            if not isinstance(tool_data, dict):
                raise ValueError("'tool' deve ser um objeto")
            tool_info = tool_data.get("driver", {})
            if not isinstance(tool_info, dict):
                raise ValueError("'driver' deve ser um objeto")
            tool_name = tool_info.get("name") or "SARIF"
            raw_rules = tool_info.get("rules", []) or []
            if not isinstance(raw_rules, list):
                raise ValueError("'rules' do driver deve ser uma lista")
            rules = {
                rule.get("id"): rule
                for rule in raw_rules
                if isinstance(rule, dict) and rule.get("id")
            }
            results = run.get("results", [])
            if not isinstance(results, list):
                raise ValueError("'results' deve ser uma lista")
        except (AttributeError, TypeError, ValueError) as error:
            ignorados["runs"] = ignorados.get("runs", 0) + 1
            LOGGER.warning("Ignorando run SARIF %d: %s", run_index, error)
            continue

        for result_index, result in enumerate(results):
            try:
                if not isinstance(result, dict):
                    raise ValueError("resultado deve ser um objeto")
                rule_id = result.get("ruleId") or "rule_desconhecida"
                rule = rules.get(rule_id, {})
                message = result.get("message", {})
                if isinstance(message, dict):
                    message_text = message.get("text") or message.get("markdown") or ""
                else:
                    message_text = str(message)

                locations = result.get("locations", [])
                if not isinstance(locations, list):
                    raise ValueError("'locations' deve ser uma lista")
                physical: dict[str, Any] = {}
                if locations and not isinstance(locations[0], dict):
                    raise ValueError("localização deve ser um objeto")
                if locations:
                    physical = locations[0].get("physicalLocation", {}) or {}
                if not isinstance(physical, dict):
                    raise ValueError("'physicalLocation' deve ser um objeto")
                artifact = physical.get("artifactLocation", {}) or {}
                region = physical.get("region", {}) or {}
                snippet = region.get("snippet", {}) or {}
                properties = result.get("properties", {}) or {}
                rule_properties = rule.get("properties", {}) or {}
                rule_configuration = rule.get("defaultConfiguration", {}) or {}
                if not isinstance(artifact, dict) or not isinstance(region, dict):
                    raise ValueError("localização física inválida")
                if not isinstance(snippet, dict):
                    raise ValueError("snippet deve ser um objeto")
                if not isinstance(properties, dict) or not isinstance(rule_properties, dict):
                    raise ValueError("properties deve ser um objeto")
                if not isinstance(rule_configuration, dict):
                    rule_configuration = {}
                severity = (
                    _severity(properties)
                    or _severity(rule_properties)
                    or result.get("level")
                    or rule_configuration.get("level")
                )
                uri = artifact.get("uri", "")
                if not isinstance(uri, str):
                    raise ValueError("URI de artefato deve ser texto")
                snippet_text = snippet.get("text", "")
                possivel_segredo = any(
                    mascarar_segredos(texto or "") != (texto or "")
                    for texto in (message_text, snippet_text, uri)
                    if isinstance(texto, str)
                )

                findings.append(
                    {
                        "check_id": rule_id,
                        "path": uri,
                        "start": {"line": region.get("startLine", 0)},
                        "extra": {
                            "message": message_text,
                            "lines": snippet_text,
                        },
                        "possivel_segredo": possivel_segredo,
                        "tool_name": tool_name,
                        "severity": normalizar_severidade(severity),
                        "source_format": "SARIF 2.1.0",
                        "tipo_scan": tipo_scan,
                    }
                )
            except (AttributeError, IndexError, TypeError, ValueError) as error:
                ignorados["resultados"] = ignorados.get("resultados", 0) + 1
                LOGGER.warning(
                    "Ignorando resultado SARIF %d do run %d: %s",
                    result_index,
                    run_index,
                    error,
                )
    return findings


def parse_sarif_com_escopo(
    documento: dict[str, Any],
    tipo_scan: str | None = None,
    ignorados: dict[str, int] | None = None,
    sucessos_explicitos: set[str] | None = None,
    ferramentas_sem_sucesso_explicito: set[str] | None = None,
    ferramentas_identificadas: set[str] | None = None,
) -> tuple[list[dict[str, Any]], set[str]]:
    """Parse findings and report tools whose every SARIF run completed cleanly."""
    if ignorados is None:
        ignorados = {"runs": 0, "resultados": 0}
    else:
        ignorados["runs"] = ignorados.get("runs", 0)
        ignorados["resultados"] = ignorados.get("resultados", 0)
    findings = parse_sarif(documento, tipo_scan, ignorados)
    if ferramentas_identificadas is not None:
        ferramentas_identificadas.update(ferramentas_no_sarif(documento))
    runs_por_ferramenta: dict[str, list[tuple[bool, bool, bool]]] = {}

    for run in documento.get("runs", []):
        if not isinstance(run, dict):
            continue
        tool_data = run.get("tool")
        tool_info = tool_data.get("driver") if isinstance(tool_data, dict) else None
        ferramenta = tool_info.get("name") if isinstance(tool_info, dict) else None
        if not isinstance(ferramenta, str) or not ferramenta:
            continue

        run_ok = True
        sucesso_explicito = False
        invocations = run.get("invocations", [])
        if not isinstance(invocations, list):
            run_ok = False
            invocations = []
        for invocation in invocations:
            if not isinstance(invocation, dict):
                run_ok = False
                continue
            if invocation.get("executionSuccessful") is True:
                sucesso_explicito = True
            if invocation.get("executionSuccessful") is False:
                run_ok = False
            for notification_key in (
                "toolExecutionNotifications",
                "configurationNotifications",
            ):
                notifications = invocation.get(notification_key, [])
                if not isinstance(notifications, list):
                    run_ok = False
                    continue
                if any(
                    isinstance(notification, dict)
                    and str(notification.get("level", "")).lower() == "error"
                    for notification in notifications
                ):
                    run_ok = False
        resultados_run = run.get("results", [])
        tem_resultados = isinstance(resultados_run, list) and bool(resultados_run)
        runs_por_ferramenta.setdefault(ferramenta, []).append(
            (run_ok, sucesso_explicito, tem_resultados)
        )

    ferramentas_ok = set()
    confirmadas = set()
    sem_confirmacao = set()
    for ferramenta, estados in runs_por_ferramenta.items():
        execucoes_ok = all(estado[0] for estado in estados)
        tem_resultados = any(estado[2] for estado in estados)
        sucesso_explicito = any(estado[1] for estado in estados)
        if execucoes_ok and sucesso_explicito:
            confirmadas.add(ferramenta)
        if execucoes_ok and (tem_resultados or sucesso_explicito):
            ferramentas_ok.add(ferramenta)
        elif execucoes_ok and not tem_resultados:
            sem_confirmacao.add(ferramenta)
    if ignorados["runs"] > 0 or ignorados["resultados"] > 0:
        ferramentas_ok = set()
        confirmadas = set()
        sem_confirmacao = set()
    if sucessos_explicitos is not None:
        sucessos_explicitos.update(confirmadas)
    if ferramentas_sem_sucesso_explicito is not None:
        ferramentas_sem_sucesso_explicito.update(sem_confirmacao)
    return findings, ferramentas_ok


def _ler_documento_sarif(caminho_arquivo: str) -> dict[str, Any]:
    """Read a bounded SARIF file and decode its JSON document."""
    tamanho = os.path.getsize(caminho_arquivo)
    if tamanho > TAMANHO_MAXIMO_SARIF:
        raise ValueError(
            f"arquivo SARIF excede o limite de {TAMANHO_MAXIMO_SARIF // (1024 * 1024)} MB"
        )
    with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:
        try:
            documento = json.load(arquivo)
        except json.JSONDecodeError as e:
            raise ValueError(f"JSON inválido: {e.msg}") from e
    return documento


def carregar_sarif(
    caminho_arquivo: str,
    tipo_scan: str | None = None,
    ignorados: dict[str, int] | None = None,
    ferramentas_identificadas: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Lê um arquivo SARIF local, limitando tamanho antes de decodificar JSON."""
    documento = _ler_documento_sarif(caminho_arquivo)
    if ferramentas_identificadas is not None:
        ferramentas_identificadas.update(ferramentas_no_sarif(documento))
    return parse_sarif(documento, tipo_scan, ignorados)


def carregar_sarif_com_escopo(
    caminho_arquivo: str,
    tipo_scan: str | None = None,
    ignorados: dict[str, int] | None = None,
    sucessos_explicitos: set[str] | None = None,
    ferramentas_sem_sucesso_explicito: set[str] | None = None,
    ferramentas_identificadas: set[str] | None = None,
) -> tuple[list[dict[str, Any]], set[str]]:
    """Load findings together with the tools eligible for absent-finding closure."""
    documento = _ler_documento_sarif(caminho_arquivo)
    return parse_sarif_com_escopo(
        documento,
        tipo_scan,
        ignorados,
        sucessos_explicitos,
        ferramentas_sem_sucesso_explicito,
        ferramentas_identificadas,
    )


def fechar_ausentes_para_ferramentas(
    conn,
    repositorio: str | None,
    ferramentas_ok: set[str],
    tipo_scan: str | None,
    inicio_execucao: str,
    force: bool = False,
    sucessos_explicitos: set[str] | None = None,
    ferramentas_sem_sucesso_explicito: set[str] | None = None,
    fechados_fps: list[str] | None = None,
) -> tuple[int, list[str]]:
    """Close per-tool scopes and collect operator-visible warnings."""
    if not repositorio or not tipo_scan:
        _, aviso = fechar_ausentes(
            conn, repositorio, None, tipo_scan, inicio_execucao, force,
            fechados_fps=fechados_fps,
        )
        return 0, [aviso] if aviso else []
    avisos = []
    for ferramenta in sorted(ferramentas_sem_sucesso_explicito or set()):
        abertos = conn.execute(
            """SELECT COUNT(*) FROM findings
               WHERE repositorio = ? AND ferramenta = ? AND tipo_scan = ?
                 AND status IN ('novo', 'confirmado')""",
            (repositorio, ferramenta, tipo_scan),
        ).fetchone()[0]
        if abertos and not force:
            avisos.append(
                "Fechamento automático bloqueado: o SARIF de resultado vazio para "
                f"{ferramenta} não contém executionSuccessful: true; "
                f"{abertos} finding(s) permanecem abertos."
            )
    ferramentas_para_fechar = set(ferramentas_ok)
    if force:
        ferramentas_para_fechar.update(ferramentas_sem_sucesso_explicito or set())
    if not ferramentas_para_fechar:
        if not avisos:
            avisos.append(
                "Fechamento automático ignorado: nenhuma ferramenta concluiu "
                "o scan sem erros."
            )
        return 0, avisos

    fechados = 0
    for ferramenta in sorted(ferramentas_para_fechar):
        quantidade, aviso = fechar_ausentes(
            conn,
            repositorio,
            ferramenta,
            tipo_scan,
            inicio_execucao,
            force,
            ferramenta in (sucessos_explicitos or set()),
            fechados_fps=fechados_fps,
        )
        fechados += quantidade
        if aviso:
            avisos.append(aviso)
    return fechados, avisos


def marcar_sarif_sucesso_explicito(caminho_arquivo: str) -> None:
    """Add a success invocation to each Trivy run after its action succeeds."""
    documento = _ler_documento_sarif(caminho_arquivo)
    runs = documento.get("runs")
    if not isinstance(runs, list):
        raise ValueError("documento SARIF sem a lista 'runs'")
    for run in runs:
        if not isinstance(run, dict):
            continue
        tool_data = run.get("tool")
        tool_info = tool_data.get("driver") if isinstance(tool_data, dict) else None
        if not isinstance(tool_info, dict) or tool_info.get("name") != "Trivy":
            continue
        invocations = run.get("invocations")
        if invocations is None:
            invocations = []
        if not isinstance(invocations, list):
            raise ValueError("'invocations' deve ser uma lista")
        invocations.append({"executionSuccessful": True})
        run["invocations"] = invocations
    with open(caminho_arquivo, "w", encoding="utf-8") as arquivo:
        json.dump(documento, arquivo, ensure_ascii=False)
        arquivo.write("\n")


def importar_sarif_para_banco(
    caminho_arquivo: str,
    caminho_banco: str = "elma_findings.db",
    repositorio: str | None = None,
    tipo_scan: str | None = None,
    ignorados: dict[str, int] | None = None,
    reabertos_fps: list[str] | None = None,
) -> tuple[int, int]:
    """Importa um relatório e retorna total lido e findings apresentados."""
    if ignorados is None:
        ignorados = {"runs": 0, "resultados": 0}
    else:
        ignorados["runs"] = ignorados.get("runs", 0)
        ignorados["resultados"] = ignorados.get("resultados", 0)
    documento = _ler_documento_sarif(caminho_arquivo)
    resultados = parse_sarif(documento, tipo_scan, ignorados)
    if repositorio:
        for achado in resultados:
            achado["repositorio"] = repositorio
    conn = conectar(caminho_banco)
    try:
        registrar_ativo_se_ausente(repositorio, conn)
        contagens = {"novos": 0, "reabertos": 0}
        apresentados = filtrar_achados_novos(
            resultados, conn, contagens=contagens, reabertos_fps=reabertos_fps
        )
        ferramentas = sorted(ferramentas_no_sarif(documento))
        registrar_importacao(
            conn,
            repositorio,
            ", ".join(ferramentas) or None,
            tipo_scan,
            len(resultados),
            contagens["novos"],
            contagens["reabertos"],
            0,
            descartados=ignorados["runs"] + ignorados["resultados"],
        )
        return len(resultados), len(apresentados)
    finally:
        conn.close()


def importar_sarif_para_banco_com_fechamento(
    caminho_arquivo: str,
    caminho_banco: str,
    repositorio: str | None,
    tipo_scan: str | None,
    force_close: bool = False,
    ignorados: dict[str, int] | None = None,
    reabertos_fps: list[str] | None = None,
    fechados_fps: list[str] | None = None,
) -> tuple[int, int, int, list[str]]:
    """Import SARIF and optionally close missing findings in successful scopes."""
    inicio_execucao = datetime.now(timezone.utc).isoformat()
    if ignorados is None:
        ignorados = {"runs": 0, "resultados": 0}
    else:
        ignorados["runs"] = ignorados.get("runs", 0)
        ignorados["resultados"] = ignorados.get("resultados", 0)
    sucessos_explicitos = set()
    ferramentas_sem_sucesso_explicito = set()
    documento = _ler_documento_sarif(caminho_arquivo)
    ferramentas_identificadas = ferramentas_no_sarif(documento)
    resultados, ferramentas_ok = parse_sarif_com_escopo(
        documento,
        tipo_scan,
        ignorados,
        sucessos_explicitos,
        ferramentas_sem_sucesso_explicito,
        ferramentas_identificadas,
    )
    if ignorados["runs"] > 0 or ignorados["resultados"] > 0:
        ferramentas_ok = set()
    for achado in resultados:
        achado["repositorio"] = repositorio

    conn = conectar(caminho_banco)
    try:
        registrar_ativo_se_ausente(repositorio, conn)
        contagens = {"novos": 0, "reabertos": 0}
        apresentados = filtrar_achados_novos(
            resultados, conn, agora=inicio_execucao, contagens=contagens,
            reabertos_fps=reabertos_fps,
        )
        fechados, avisos = fechar_ausentes_para_ferramentas(
            conn,
            repositorio,
            ferramentas_ok,
            tipo_scan,
            inicio_execucao,
            force_close,
            sucessos_explicitos,
            ferramentas_sem_sucesso_explicito,
            fechados_fps=fechados_fps,
        )
        ferramentas = sorted(
            {
                *ferramentas_ok,
                *ferramentas_sem_sucesso_explicito,
                *ferramentas_identificadas,
                *(
                    achado.get("tool_name") or achado.get("ferramenta")
                    for achado in resultados
                    if achado.get("tool_name") or achado.get("ferramenta")
                ),
            }
        )
        registrar_importacao(
            conn,
            repositorio,
            ", ".join(ferramentas) or None,
            tipo_scan,
            len(resultados),
            contagens["novos"],
            contagens["reabertos"],
            fechados,
            descartados=ignorados["runs"] + ignorados["resultados"],
        )
        return len(resultados), len(apresentados), fechados, avisos
    finally:
        conn.close()