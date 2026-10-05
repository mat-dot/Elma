# Elma ASPM - Challenge FIAP x PRIDE 2026
# Copyright (C) 2026 Equipe Abutres
# SPDX-License-Identifier: BSD-3-Clause
# Licenciado sob BSD 3-Clause. Veja o arquivo LICENSE.md.

"""Isolated GitHub Issues integration for confirmed Elma findings."""

from __future__ import annotations

import html
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from .guardrails import mascarar_segredos


_REPOSITORIO_GITHUB = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>]+")
_CONTROLES = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_API_BASE = "https://api.github.com"
_RESERVA_CRIACAO_TTL = timedelta(minutes=10)
_BLOCO_ELMA_INICIO = "<!-- elma-context:start -->"
_BLOCO_ELMA_FIM = "<!-- elma-context:end -->"


@dataclass(frozen=True)
class ConfigTickets:
    ativo: bool = False
    dry_run: bool = True
    token: str | None = None
    dashboard_url: str = "http://localhost:8000/painel"
    timeout: float = 15.0


class GitHubAPIError(RuntimeError):
    """Sanitized GitHub transport or response error."""

    def __init__(self, status_code: int | None = None):
        self.status_code = status_code
        message = (
            f"GitHub API retornou HTTP {status_code}"
            if status_code is not None
            else "Falha de comunicação com a GitHub API"
        )
        super().__init__(message)


Transport = Callable[
    [str, str, dict[str, str], bytes | None, float],
    tuple[int, Any, dict[str, str]],
]


def _bool_env(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def carregar_config(env: dict[str, str] | None = None) -> ConfigTickets:
    """Read ticket settings without loading or printing any credential values."""
    env = os.environ if env is None else env
    dashboard_url = (
        env.get("ELMA_DASHBOARD_URL")
        or env.get("ELMA_API_URL")
        or "http://localhost:8000"
    ).rstrip("/")
    if not dashboard_url.endswith("/painel"):
        dashboard_url += "/painel"
    return ConfigTickets(
        ativo=_bool_env(env.get("ELMA_TICKETS_ATIVO"), False),
        dry_run=_bool_env(env.get("ELMA_TICKETS_DRY_RUN"), True),
        token=env.get("ELMA_GITHUB_TOKEN") or None,
        dashboard_url=dashboard_url,
    )


def _texto_nao_confiavel(valor: Any, limite: int = 4000) -> str:
    texto = mascarar_segredos(str(valor or ""))
    texto = _CONTROLES.sub("", texto)
    texto = _URL.sub("[link removido]", texto)
    texto = texto.replace("@", "[at]")
    return html.escape(texto[:limite], quote=True)


def _bloco_codigo(valor: Any) -> str:
    texto = _texto_nao_confiavel(valor)
    maior_sequencia = max(
        (len(match.group(0)) for match in re.finditer(r"`+", texto)),
        default=0,
    )
    fence = "`" * max(3, maior_sequencia + 1)
    return f"{fence}\n{texto or '(vazio)'}\n{fence}"


def _repositorio(finding: dict[str, Any]) -> str | None:
    repositorio = finding.get("repositorio")
    if not isinstance(repositorio, str) or not _REPOSITORIO_GITHUB.fullmatch(repositorio):
        return None
    return repositorio


def montar_corpo_issue(
    finding: dict[str, Any],
    ativo: dict[str, Any] | None,
    dashboard_url: str | None = None,
) -> tuple[str, str]:
    """Build a safe issue title/body from already-masked database fields."""
    ativo = ativo or {}
    fingerprint = _texto_nao_confiavel(finding.get("fingerprint"), 128)
    severidade = _texto_nao_confiavel(finding.get("severidade") or "UNKNOWN", 30)
    dashboard = (dashboard_url or ativo.get("dashboard_url") or "").rstrip("/")
    if dashboard and not dashboard.endswith("/painel"):
        dashboard += "/painel"
    link_painel = (
        f"\n\n[Ver no painel da Elma]({dashboard})" if dashboard else ""
    )

    if finding.get("possivel_segredo") or finding.get("tipo_scan") == "secrets":
        titulo = f"Possível segredo detectado ({severidade})"
        regra = _texto_nao_confiavel(finding.get("regra") or "regra desconhecida", 500)
        arquivo = _texto_nao_confiavel(
            finding.get("arquivo") or "arquivo desconhecido", 1000
        )
        linha = finding.get("linha")
        local = f"{arquivo}:{linha}" if isinstance(linha, int) and linha > 0 else arquivo
        scanner = _texto_nao_confiavel(finding.get("ferramenta") or "desconhecido", 200)
        repositorio = _texto_nao_confiavel(
            finding.get("repositorio") or "desconhecido", 200
        )
        nome_ativo = _texto_nao_confiavel(ativo.get("nome") or repositorio, 200)
        remediacao = finding.get("remediacao_ia")
        secao_remediacao = (
            "\n\n**Sugestão de remediação (gerada por IA, revisar antes de aplicar)**\n\n"
            f"{_bloco_codigo(remediacao)}"
            if remediacao
            else ""
        )
        corpo = (
            "A Elma detectou um finding potencialmente sensível. O valor bruto do segredo "
            "foi omitido; os campos abaixo foram sanitizados antes do envio.\n\n"
            f"- Ativo: {nome_ativo}\n"
            f"- Repositório: `{repositorio}`\n"
            f"- Fingerprint: `{fingerprint}`\n"
            f"- Severidade: {severidade}\n"
            f"- Scanner: {scanner}\n"
            f"- Regra: {_bloco_codigo(regra)}\n"
            f"- Local: {_bloco_codigo(local)}\n\n"
            "**Mensagem do scanner (sanitizada)**\n\n"
            f"{_bloco_codigo(finding.get('mensagem') or 'Sem mensagem.')}\n\n"
            "**Evidência (sanitizada)**\n\n"
            f"{_bloco_codigo(finding.get('trecho') or 'Sem evidência.')}"
            f"{secao_remediacao}"
            f"{link_painel}"
        )
        return titulo[:256], corpo[:60000]

    remediacao = finding.get("remediacao_ia")
    secao_remediacao = ""
    if remediacao:
        secao_remediacao = (
            "\n\n**Sugestão de remediação (gerada por IA, revisar antes de aplicar)**\n\n"
            f"{_bloco_codigo(remediacao)}"
        )

    regra = _texto_nao_confiavel(finding.get("regra") or "regra desconhecida", 500)
    arquivo = _texto_nao_confiavel(finding.get("arquivo") or "arquivo desconhecido", 1000)
    linha = finding.get("linha")
    local = f"{arquivo}:{linha}" if isinstance(linha, int) and linha > 0 else arquivo
    nome_ativo = _texto_nao_confiavel(ativo.get("nome") or _repositorio(finding) or "repositório", 200)
    titulo = f"[{severidade}] {regra} em {local}"
    corpo = (
        f"Finding de segurança em **{nome_ativo}**.\n\n"
        f"- Fingerprint: `{fingerprint}`\n"
        f"- Severidade: {severidade}\n"
        f"- Regra: {_bloco_codigo(finding.get('regra') or 'regra desconhecida')}\n"
        f"- Local: {_bloco_codigo(local)}\n\n"
        "**Mensagem do scanner**\n\n"
        f"{_bloco_codigo(finding.get('mensagem') or 'Sem mensagem.')}"
        f"{secao_remediacao}"
        f"{link_painel}"
    )
    return titulo[:256], corpo[:60000]


def _corpo_issue_gerenciado(
    finding: dict[str, Any],
    ativo: dict[str, Any] | None,
    config: ConfigTickets,
) -> tuple[str, str]:
    titulo, corpo = montar_corpo_issue(finding, ativo, config.dashboard_url)
    marcador = f"<!-- elma-fingerprint:{finding['fingerprint']} -->"
    return titulo, f"{_BLOCO_ELMA_INICIO}\n{corpo}\n{_BLOCO_ELMA_FIM}\n\n{marcador}"


def _mesclar_corpo_issue_existente(
    corpo_atual: str,
    corpo_gerado: str,
    fingerprint: str,
) -> str | None:
    padrao = re.compile(
        re.escape(_BLOCO_ELMA_INICIO) + r".*?" + re.escape(_BLOCO_ELMA_FIM),
        re.DOTALL,
    )
    if padrao.search(corpo_atual):
        return padrao.sub(corpo_gerado, corpo_atual, count=1)
    if "Detalhes do scanner foram omitidos por segurança." in corpo_atual:
        return (
            f"{corpo_gerado}\n\n"
            f"<!-- elma-fingerprint:{fingerprint} -->"
        )
    return None


def deve_criar_issue(
    finding: dict[str, Any], config: ConfigTickets
) -> bool:
    """Return whether policy permits creating a new issue for this finding."""
    return _motivo_nao_elegivel(finding, config) is None


def _motivo_nao_elegivel(
    finding: dict[str, Any],
    config: ConfigTickets,
    ignorar_vinculo: bool = False,
) -> str | None:
    if not config.ativo:
        return "tickets_desativados"
    if finding.get("status") != "confirmado":
        return "finding_nao_confirmado"
    if finding.get("severidade") != "CRITICAL":
        return "severidade_nao_critica"
    fingerprint = finding.get("fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        return "fingerprint_invalido"
    if not _repositorio(finding):
        return "repositorio_invalido"
    if not ignorar_vinculo:
        if finding.get("issue_url") or finding.get("issue_numero") is not None:
            return "issue_ja_vinculada"
        if finding.get("issue_estado"):
            return "issue_ja_vinculada"
    if not config.dry_run and not config.token:
        return "token_ausente"
    return None


def _issue_vinculada(finding: dict[str, Any]) -> bool:
    return bool(finding.get("issue_url")) or (
        finding.get("issue_numero") is not None or bool(finding.get("issue_estado"))
    )


def _github_transport(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, Any, dict[str, str]]:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            payload = json.loads(raw) if raw else None
            return response.status, payload, dict(response.headers.items())
    except urllib.error.HTTPError as error:
        raise GitHubAPIError(error.code) from None
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        raise GitHubAPIError() from None


def _request(
    config: ConfigTickets,
    method: str,
    url: str,
    payload: dict[str, Any] | None = None,
    transport: Transport | None = None,
) -> tuple[Any, dict[str, str]]:
    if not config.token:
        raise GitHubAPIError()
    parsed_url = urllib.parse.urlsplit(url)
    if parsed_url.scheme != "https" or parsed_url.netloc != "api.github.com":
        raise GitHubAPIError()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {config.token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Elma-ASPM",
    }
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    status, response, response_headers = (transport or _github_transport)(
        method, url, headers, body, config.timeout
    )
    if not 200 <= status < 300:
        raise GitHubAPIError(status)
    return response, response_headers


def _url_proxima_pagina(headers: dict[str, str]) -> str | None:
    link = headers.get("Link") or headers.get("link") or ""
    match = re.search(r'<([^>]+)>;\s*rel="next"', link)
    return match.group(1) if match else None


def _buscar_issue_existente(
    config: ConfigTickets,
    repositorio: str,
    marcador: str,
    transport: Transport | None,
) -> dict[str, Any] | None:
    url = (
        f"{_API_BASE}/repos/{repositorio}/issues"
        "?state=all&per_page=100&page=1"
    )
    for _ in range(10):
        itens, headers = _request(config, "GET", url, transport=transport)
        if not isinstance(itens, list):
            raise GitHubAPIError()
        for item in itens:
            if (
                isinstance(item, dict)
                and "pull_request" not in item
                and marcador in str(item.get("body") or "")
                and isinstance(item.get("number"), int)
                and isinstance(item.get("html_url"), str)
            ):
                return item
        proxima = _url_proxima_pagina(headers)
        if not proxima:
            return None
        parsed = urllib.parse.urlsplit(proxima)
        if parsed.scheme != "https" or parsed.netloc != "api.github.com":
            raise GitHubAPIError()
        url = proxima
    raise GitHubAPIError()


def _finding_ticket(conn, fingerprint: str) -> dict[str, Any] | None:
    cursor = conn.execute(
        """SELECT fingerprint, status, regra, arquivo, linha, trecho, mensagem,
                  severidade, possivel_segredo, tipo_scan, repositorio, ferramenta, issue_url,
                  issue_numero, issue_estado, issue_erro, issue_tentativas,
                  remediacao_ia
           FROM findings WHERE fingerprint = ?""",
        (fingerprint,),
    )
    row = cursor.fetchone()
    return dict(zip((item[0] for item in cursor.description), row)) if row else None


def _gravar_erro(
    conn,
    fingerprint: str,
    erro: Exception,
    incrementar_tentativa: bool = True,
) -> None:
    mensagem = str(erro)[:300]
    conn.execute(
        """UPDATE findings
           SET issue_erro = ?, issue_reservado_em = NULL,
               issue_tentativas = issue_tentativas + ?
           WHERE fingerprint = ?""",
        (mensagem, int(incrementar_tentativa), fingerprint),
    )
    conn.commit()


def _gravar_issue(
    conn,
    fingerprint: str,
    url: str,
    numero: int,
    estado: str,
    incrementar_tentativa: bool,
) -> None:
    conn.execute(
        """UPDATE findings
           SET issue_url = ?, issue_numero = ?, issue_estado = ?, issue_erro = NULL,
               issue_reservado_em = NULL, issue_tentativas = issue_tentativas + ?
           WHERE fingerprint = ?""",
        (url, numero, estado, int(incrementar_tentativa), fingerprint),
    )
    conn.commit()


def _reservar_criacao(conn, fingerprint: str) -> bool:
    agora = datetime.now(timezone.utc)
    agora_texto = agora.isoformat()
    reserva_expirada = (agora - _RESERVA_CRIACAO_TTL).isoformat()
    cursor = conn.execute(
        """UPDATE findings
           SET issue_erro = 'criando', issue_reservado_em = ?
           WHERE fingerprint = ? AND status = 'confirmado'
             AND issue_url IS NULL AND issue_numero IS NULL AND issue_estado IS NULL
             AND (issue_reservado_em IS NULL OR issue_reservado_em < ?)""",
        (agora_texto, fingerprint, reserva_expirada),
    )
    conn.commit()
    return cursor.rowcount == 1


def _registrar_issue_existente(
    conn,
    fingerprint: str,
    repositorio: str,
    existente: dict[str, Any],
    config: ConfigTickets,
    transport: Transport | None,
) -> dict[str, Any]:
    """Link a remote issue found by marker, reopening it if GitHub has it closed."""
    fechada_remotamente = existente.get("state") == "closed"
    url, numero = existente["html_url"], existente["number"]
    if fechada_remotamente:
        url, numero = _patch_estado_issue(
            config, repositorio, numero, "aberta", transport
        )
    _gravar_issue(
        conn, fingerprint, url, numero, "aberta", incrementar_tentativa=False
    )
    return {
        "criada": False,
        "reconciliada": True,
        "reaberta": fechada_remotamente,
        "issue_url": url,
        "issue_numero": numero,
        "issue_estado": "aberta",
    }


def _reconciliar_issue_vinculada(
    finding: dict[str, Any],
    ativo: dict[str, Any] | None,
    conn,
    config: ConfigTickets,
    transport: Transport | None,
) -> dict[str, Any]:
    """Reopen the already-linked issue when GitHub has it closed.

    Re-confirmation must not create a duplicate issue; the existing one keeps
    its comment history and returns to the backlog.
    """
    fingerprint = finding["fingerprint"]
    repositorio = _repositorio(finding)
    marcador = f"<!-- elma-fingerprint:{fingerprint} -->"
    mutacao_tentada = False
    try:
        existente = _buscar_issue_existente(config, repositorio, marcador, transport)
        if existente is None:
            return {"criada": False, "ignorada": True, "motivo": "issue_ja_vinculada"}
        titulo, corpo_gerenciado = _corpo_issue_gerenciado(finding, ativo, config)
        corpo_secao = corpo_gerenciado.split("\n\n<!-- elma-fingerprint:", 1)[0]
        corpo_atualizado = _mesclar_corpo_issue_existente(
            str(existente.get("body") or ""),
            corpo_secao,
            fingerprint,
        )
        conteudo_atualizado = corpo_atualizado is not None and (
            corpo_atualizado != existente.get("body")
            or titulo != existente.get("title")
        )
        if conteudo_atualizado:
            mutacao_tentada = True
            resposta, _ = _request(
                config,
                "PATCH",
                f"{_API_BASE}/repos/{repositorio}/issues/{existente['number']}",
                {"title": titulo, "body": corpo_atualizado},
                transport,
            )
            if not isinstance(resposta, dict):
                raise GitHubAPIError()
            existente = {**existente, **resposta}
        mutacao_tentada = existente.get("state") == "closed"
        resultado = _registrar_issue_existente(
            conn, fingerprint, repositorio, existente, config, transport
        )
        resultado["atualizada"] = conteudo_atualizado
        return resultado
    except Exception as erro:
        seguro = erro if isinstance(erro, GitHubAPIError) else GitHubAPIError()
        _gravar_erro(conn, fingerprint, seguro, mutacao_tentada)
        return {
            "criada": False,
            "erro": str(erro)
            if isinstance(erro, GitHubAPIError)
            else "Falha de comunicação com a GitHub API",
        }


def criar_issue(
    finding: dict[str, Any],
    ativo: dict[str, Any] | None,
    conn,
    config: ConfigTickets,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Create or reconcile a GitHub issue; dry-run never calls or writes."""
    fingerprint = finding.get("fingerprint")
    if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
        return {"criada": False, "ignorada": True, "motivo": "fingerprint_invalido"}
    finding_persistido = _finding_ticket(conn, fingerprint)
    if finding_persistido is None:
        return {"criada": False, "ignorada": True, "motivo": "finding_inexistente"}
    motivo = _motivo_nao_elegivel(finding_persistido, config, ignorar_vinculo=True)
    if motivo:
        return {
            "criada": False,
            "ignorada": True,
            "motivo": motivo,
        }
    finding = finding_persistido
    if ativo and ativo.get("repositorio") != finding.get("repositorio"):
        ativo = None
    repositorio = _repositorio(finding)
    titulo, corpo = _corpo_issue_gerenciado(finding, ativo, config)
    marcador = f"<!-- elma-fingerprint:{fingerprint} -->"
    if config.dry_run:
        return {
            "criada": False,
            "dry_run": True,
            "repositorio": repositorio,
            "titulo": titulo,
            "corpo": corpo,
        }
    if not config.token:
        return {"criada": False, "ignorada": True, "motivo": "token_ausente"}
    if _issue_vinculada(finding):
        return _reconciliar_issue_vinculada(finding, ativo, conn, config, transport)
    if not _reservar_criacao(conn, fingerprint):
        return {"criada": False, "em_andamento": True}

    mutacao_tentada = False
    try:
        existente = _buscar_issue_existente(
            config, repositorio, marcador, transport
        )
        if existente:
            mutacao_tentada = existente.get("state") == "closed"
            return _registrar_issue_existente(
                conn, fingerprint, repositorio, existente, config, transport
            )
        mutacao_tentada = True
        response, _ = _request(
            config,
            "POST",
            f"{_API_BASE}/repos/{repositorio}/issues",
            {"title": titulo, "body": corpo},
            transport,
        )
        if (
            not isinstance(response, dict)
            or not isinstance(response.get("number"), int)
            or not isinstance(response.get("html_url"), str)
        ):
            raise GitHubAPIError()
        _gravar_issue(
            conn,
            fingerprint,
            response["html_url"],
            response["number"],
            "aberta",
            incrementar_tentativa=True,
        )
        return {
            "criada": True,
            "issue_url": response["html_url"],
            "issue_numero": response["number"],
            "issue_estado": "aberta",
        }
    except Exception as erro:
        seguro = erro if isinstance(erro, GitHubAPIError) else GitHubAPIError()
        _gravar_erro(conn, fingerprint, seguro, mutacao_tentada)
        return {"criada": False, "erro": str(erro) if isinstance(erro, GitHubAPIError) else "Falha de comunicação com a GitHub API"}


def criar_issue_confirmado(
    fingerprint: str,
    conn,
    config: ConfigTickets | None = None,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Create a ticket after manual confirmation when policy and config allow it."""
    finding = _finding_ticket(conn, fingerprint)
    if finding is None:
        return {"criada": False, "ignorada": True, "motivo": "finding_inexistente"}
    ativo = None
    if finding.get("repositorio"):
        row = conn.execute(
            "SELECT nome, repositorio FROM ativos WHERE repositorio = ?",
            (finding["repositorio"],),
        ).fetchone()
        if row:
            ativo = {"nome": row[0], "repositorio": row[1]}
    return criar_issue(
        finding,
        ativo,
        conn,
        config or carregar_config(),
        transport,
    )


def _patch_estado_issue(
    config: ConfigTickets,
    repositorio: str,
    numero: int,
    estado: str,
    transport: Transport | None,
) -> tuple[str, int]:
    response, _ = _request(
        config,
        "PATCH",
        f"{_API_BASE}/repos/{repositorio}/issues/{numero}",
        {"state": "closed" if estado == "fechada" else "open"},
        transport,
    )
    url = response.get("html_url") if isinstance(response, dict) else None
    numero_resposta = response.get("number") if isinstance(response, dict) else None
    if not isinstance(url, str) or not isinstance(numero_resposta, int):
        raise GitHubAPIError()
    return url, numero_resposta


def _alterar_estado_issue(
    fingerprint: str,
    estado: str,
    conn,
    config: ConfigTickets,
    transport: Transport | None,
) -> dict[str, Any]:
    finding = _finding_ticket(conn, fingerprint)
    if finding is None or not finding.get("issue_numero") or not finding.get("repositorio"):
        return {"atualizada": False, "ignorada": True}
    if not config.ativo:
        return {"atualizada": False, "ignorada": True}
    repositorio = finding["repositorio"]
    if not _REPOSITORIO_GITHUB.fullmatch(repositorio):
        return {"atualizada": False, "ignorada": True}
    if finding.get("issue_estado") == estado:
        return {"atualizada": True, "sem_alteracao": True}
    if config.dry_run:
        return {
            "atualizada": False,
            "dry_run": True,
            "repositorio": repositorio,
            "issue_numero": finding["issue_numero"],
            "estado": estado,
        }
    if not config.token:
        return {"atualizada": False, "ignorada": True}
    try:
        url, numero = _patch_estado_issue(
            config, repositorio, finding["issue_numero"], estado, transport
        )
        _gravar_issue(conn, fingerprint, url, numero, estado, incrementar_tentativa=True)
        return {"atualizada": True, "issue_estado": estado, "issue_url": url}
    except Exception as erro:
        seguro = erro if isinstance(erro, GitHubAPIError) else GitHubAPIError()
        _gravar_erro(conn, fingerprint, seguro, incrementar_tentativa=True)
        return {"atualizada": False, "erro": str(seguro)}


def fechar_issue(
    fingerprint: str,
    conn,
    config: ConfigTickets,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Close the linked GitHub issue if ticket integration is enabled."""
    return _alterar_estado_issue(fingerprint, "fechada", conn, config, transport)


def reabrir_issue(
    fingerprint: str,
    conn,
    config: ConfigTickets,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Reopen the linked GitHub issue if ticket integration is enabled."""
    return _alterar_estado_issue(fingerprint, "aberta", conn, config, transport)


def sincronizar_issues_apos_ingestao(
    conn,
    reabertos: list[str] | None = None,
    fechados: list[str] | None = None,
    config: ConfigTickets | None = None,
    transport: Transport | None = None,
) -> dict[str, int]:
    """Reopen/close linked issues after an import changed finding statuses.

    Safe no-op when ticketing is disabled or a finding has no linked issue, so
    callers can invoke it unconditionally after an ingestion. Returns the number
    of issues reopened/closed (dry-run previews count as acted upon).
    """
    config = config or carregar_config()
    if not config.ativo:
        return {"reabertas": 0, "fechadas": 0}
    reabertas = 0
    for fingerprint in reabertos or []:
        resultado = reabrir_issue(fingerprint, conn, config, transport)
        if resultado.get("atualizada") or resultado.get("dry_run"):
            reabertas += 1
    fechadas = 0
    for fingerprint in fechados or []:
        resultado = fechar_issue(fingerprint, conn, config, transport)
        if resultado.get("atualizada") or resultado.get("dry_run"):
            fechadas += 1
    return {"reabertas": reabertas, "fechadas": fechadas}
