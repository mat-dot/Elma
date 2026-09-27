"""Parsing local de relatórios SARIF para o formato de findings da Elma."""

import json
import logging
import os
from typing import Any

from elma_db import conectar, filtrar_achados_novos
from elma_severity import normalizar_severidade

TAMANHO_MAXIMO_SARIF = 25 * 1024 * 1024
TAGS_SEVERIDADE = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN",
    "ERROR", "WARNING", "NOTE", "NONE",
}
LOGGER = logging.getLogger(__name__)


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


def parse_sarif(documento: dict[str, Any]) -> list[dict[str, Any]]:
    """Converte resultados SARIF 2.1.0 para o formato aceito pelo SQLite da Elma."""
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

                findings.append(
                    {
                        "check_id": rule_id,
                        "path": uri,
                        "start": {"line": region.get("startLine", 0)},
                        "extra": {
                            "message": message_text,
                            "lines": snippet.get("text", ""),
                        },
                        "tool_name": tool_name,
                        "severity": normalizar_severidade(severity),
                        "source_format": "SARIF 2.1.0",
                    }
                )
            except (AttributeError, IndexError, TypeError, ValueError) as error:
                LOGGER.warning(
                    "Ignorando resultado SARIF %d do run %d: %s",
                    result_index,
                    run_index,
                    error,
                )
    return findings


def carregar_sarif(caminho_arquivo: str) -> list[dict[str, Any]]:
    """Lê um arquivo SARIF local, limitando tamanho antes de decodificar JSON."""
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
    return parse_sarif(documento)


def importar_sarif_para_banco(
    caminho_arquivo: str,
    caminho_banco: str = "elma_findings.db",
) -> tuple[int, int]:
    """Importa um relatório e retorna total lido e findings apresentados."""
    resultados = carregar_sarif(caminho_arquivo)
    if not resultados:
        return 0, 0
    conn = conectar(caminho_banco)
    try:
        apresentados = filtrar_achados_novos(resultados, conn)
        return len(resultados), len(apresentados)
    finally:
        conn.close()