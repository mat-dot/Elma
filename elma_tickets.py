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


_REPOSITORIO_GITHUB = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>]+")
_CONTROLES = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_API_BASE = "https://api.github.com"
_RESERVA_CRIACAO_TTL = timedelta(minutes=10)


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
    texto = str(valor or "")
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
        corpo = (
            "A Elma detectou um finding potencialmente sensível. "
            "Detalhes do scanner foram omitidos por segurança.\n\n"
            f"- Fingerprint: `{fingerprint}`\n"
            f"- Severidade: {severidade}"
            f"{link_painel}"
        )
        return titulo[:256], corpo[:60000]

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
        f"{link_painel}"
    )
    return titulo[:256], corpo[:60000]


def deve_criar_issue(
    finding: dict[str, Any], config: ConfigTickets
) -> bool:
    """Return whether policy permits creating a new issue for this finding."""
    return _motivo_nao_elegivel(finding, config) is None


def _motivo_nao_elegivel(
    finding: dict[str, Any], config: ConfigTickets
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
    if finding.get("issue_url") or finding.get("issue_numero") is not None:
        return "issue_ja_vinculada"
    if finding.get("issue_estado"):
        return "issue_ja_vinculada"
    if not config.dry_run and not config.token:
        return "token_ausente"
    return None


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
              severidade, possivel_segredo, tipo_scan, repositorio, issue_url,
                  issue_numero, issue_estado, issue_erro, issue_tentativas
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
    motivo = _motivo_nao_elegivel(finding_persistido, config)
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
    titulo, corpo = montar_corpo_issue(finding, ativo, config.dashboard_url)
    marcador = f"<!-- elma-fingerprint:{fingerprint} -->"
    corpo = f"{corpo}\n\n{marcador}"
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
    if not _reservar_criacao(conn, fingerprint):
        return {"criada": False, "em_andamento": True}

    mutacao_tentada = False
    try:
        existente = _buscar_issue_existente(
            config, repositorio, marcador, transport
        )
        if existente:
            estado = "fechada" if existente.get("state") == "closed" else "aberta"
            _gravar_issue(
                conn,
                fingerprint,
                existente["html_url"],
                existente["number"],
                estado,
                incrementar_tentativa=False,
            )
            return {
                "criada": False,
                "reconciliada": True,
                "issue_url": existente["html_url"],
                "issue_numero": existente["number"],
                "issue_estado": estado,
            }
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
        response, _ = _request(
            config,
            "PATCH",
            f"{_API_BASE}/repos/{repositorio}/issues/{finding['issue_numero']}",
            {"state": "closed" if estado == "fechada" else "open"},
            transport,
        )
        url = response.get("html_url") if isinstance(response, dict) else None
        numero = response.get("number") if isinstance(response, dict) else None
        if not isinstance(url, str) or not isinstance(numero, int):
            raise GitHubAPIError()
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
