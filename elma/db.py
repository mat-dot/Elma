# Elma ASPM - Challenge FIAP x PRIDE 2026
# Copyright (C) 2026 Equipe Abutres
# SPDX-License-Identifier: BSD-3-Clause
# Licenciado sob BSD 3-Clause. Veja o arquivo LICENSE.md.

"""
elma.db — Camada de memória do Elma (o "banco" que falta pra virar ASPM).

O que faz:
- Cria/abre um banco SQLite local (elma_findings.db) com uma tabela `findings`.
- Calcula um fingerprint estável pra cada achado do motor_sast_resiliente.
- Diz, pra cada achado novo, se ele já existe no banco (e com qual status).
- Deixa você marcar manualmente um achado como falso_positivo / corrigido.

Não depende de LLM nenhum. É só hash + SQLite.
"""

import hashlib
import re
import sqlite3
from datetime import datetime, timedelta, timezone

from .guardrails import mascarar_segredos
from .risco import calcular_componentes_score
from .severity import normalizar_severidade
from .sla import calcular_sla, resolver_sla_dias, resumir_sla
from . import metricas

CAMINHO_BANCO_PADRAO = "elma_findings.db"
TIPOS_SCAN = ("sast", "sca", "secrets", "iac", "container", "k8s", "dast")
MIGRACAO_SEVERIDADE_CANONICA = 1
MIGRACAO_MASCARAMENTO_SEGREDOS = 2
MIGRACAO_MASCARAMENTO_V2 = 3
MIGRACAO_FECHAMENTO_AUTOMATICO = 4
MIGRACAO_ATIVOS = 5
MIGRACAO_HISTORICO_IMPORTACOES = 6
MIGRACAO_DESCARTADOS_IMPORTACAO = 7
MIGRACAO_TICKETS = 8
MIGRACAO_RESERVA_TICKETS = 9
MIGRACAO_REMEDIACAO_IA = 10
ULTIMA_MIGRACAO = MIGRACAO_REMEDIACAO_IA
TIPOS_ATIVO = ("webapp", "api", "lib")
EXPOSICOES_ATIVO = ("internet", "interna")
SEVERIDADES_AGREGACAO = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")
STATUS_AGREGACAO = ("novo", "confirmado", "falso_positivo", "corrigido")


class FingerprintConflictError(ValueError):
    """Raised when both legacy and tool-aware keys exist for one finding."""

    def __init__(self, conflicts: list[dict]):
        self.conflicts = conflicts
        detalhes = "; ".join(
            f"legado={conflito['fingerprint_legado']} ({conflito['status_legado']}), "
            f"atual={conflito['fingerprint_atual']} ({conflito['status_atual']})"
            for conflito in conflicts
        )
        super().__init__(
            "Conflito de fingerprints; revise manualmente os registros sem mesclá-los: "
            + detalhes
        )


def inicializar_banco(caminho_banco: str = CAMINHO_BANCO_PADRAO) -> sqlite3.Connection:
    """Abre conexão e garante que o schema está aplicado.

    Uso recomendado para entrada única (CLI, scripts, unittests) e no
    lifespan da aplicação FastAPI. Idempotente: se as migrações já foram
    aplicadas, só abre a conexão e retorna."""
    conn = sqlite3.connect(caminho_banco, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    migrar(conn)
    return conn


def _schema_atualizado(conn: sqlite3.Connection) -> bool:
    """Return True when the newest applied migration has reached the current schema."""
    try:
        ultimo_version = conn.execute(
            "SELECT MAX(version) FROM elma_schema_migrations"
        ).fetchone()[0]
    except sqlite3.OperationalError:
        return False
    return ultimo_version is not None and ultimo_version >= ULTIMA_MIGRACAO


def conectar(caminho_banco: str = CAMINHO_BANCO_PADRAO) -> sqlite3.Connection:
    """Abre conexão SQLite e aplica migrações quando o schema ainda não está atualizado.

    O critério é a versão máxima registrada em ``elma_schema_migrations``.
    Bancos legados sem a tabela de migração, ou com ela vazia, descem para
    :func:`migrar` de forma idempotente antes de retornar.
    """
    conn = sqlite3.connect(caminho_banco, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    if not _schema_atualizado(conn):
        migrar(conn)
    return conn


def migrar(conn: sqlite3.Connection) -> None:
    """Cria/atualiza schema do banco. Roda **uma única vez** no startup.

    Safe para ser chamada repetidamente: migrações idempotentes usam
    ``CREATE TABLE IF NOT EXISTS``, ``ALTER TABLE ADD COLUMN`` com checagem
    prévia e a tabela ``elma_schema_migrations`` como registro de versões
    já aplicadas."""
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            fingerprint     TEXT PRIMARY KEY,
            regra           TEXT,
            arquivo         TEXT,
            linha           INTEGER,
            trecho          TEXT,
            status          TEXT DEFAULT 'novo',   -- novo | confirmado | falso_positivo | corrigido
            primeira_vez    TEXT,
            ultima_vez      TEXT,
            ferramenta      TEXT,
            severidade      TEXT,
            origem          TEXT,
            mensagem        TEXT,
            repositorio     TEXT,
            possivel_segredo INTEGER,
            fingerprint_legado TEXT,
            sugestao_ia TEXT,
            confianca_ia INTEGER,
            justificativa_ia TEXT,
            sugestao_ia_gerada_em TEXT,
            remediacao_ia TEXT,
            remediacao_ia_gerada_em TEXT,
            tipo_scan TEXT,
            fechado_automaticamente_em TEXT
        )
        """
    )
    colunas_existentes = {
        linha[1] for linha in conn.execute("PRAGMA table_info(findings)")
    }
    novas_colunas = {
        "ferramenta": "TEXT",
        "severidade": "TEXT",
        "origem": "TEXT",
        "mensagem": "TEXT",
        "repositorio": "TEXT",
        "possivel_segredo": "INTEGER",
        "fingerprint_legado": "TEXT",
        "sugestao_ia": "TEXT",
        "confianca_ia": "INTEGER",
        "justificativa_ia": "TEXT",
        "sugestao_ia_gerada_em": "TEXT",
        "remediacao_ia": "TEXT",
        "remediacao_ia_gerada_em": "TEXT",
        "tipo_scan": "TEXT",
        "fechado_automaticamente_em": "TEXT",
    }
    for coluna, tipo in novas_colunas.items():
        if coluna not in colunas_existentes:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {coluna} {tipo}")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS elma_schema_migrations "
        "(version INTEGER PRIMARY KEY)"
    )
    migracao_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_SEVERIDADE_CANONICA,),
    ).fetchone()
    if migracao_aplicada is None:
        registros = conn.execute(
            "SELECT fingerprint, severidade FROM findings"
        ).fetchall()
        conn.executemany(
            "UPDATE findings SET severidade = ? WHERE fingerprint = ?",
            [
                (normalizar_severidade(severidade), fingerprint)
                for fingerprint, severidade in registros
            ],
        )
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_SEVERIDADE_CANONICA,),
        )
    migracao_mascaramento_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_MASCARAMENTO_SEGREDOS,),
    ).fetchone()
    if migracao_mascaramento_aplicada is None:
        colunas_existentes = {
            linha[1] for linha in conn.execute("PRAGMA table_info(findings)")
        }
        campos = (
            "regra", "arquivo", "trecho", "mensagem", "repositorio",
            "possivel_segredo",
        )
        selecao = ", ".join(
            campo if campo in colunas_existentes else f"NULL AS {campo}"
            for campo in campos
        )
        registros = conn.execute(
            f"SELECT fingerprint, {selecao} FROM findings"
        ).fetchall()
        for (
            fingerprint,
            regra,
            arquivo_original,
            trecho_original,
            mensagem_original,
            repositorio,
            flag_original,
        ) in registros:
            fingerprint_legado = _calcular_fingerprint_legado(
                {
                    "regra": regra,
                    "arquivo": arquivo_original,
                    "trecho": trecho_original,
                    "mensagem": mensagem_original,
                    "repositorio": repositorio,
                }
            )
            arquivo = mascarar_segredos(arquivo_original or "")
            trecho = mascarar_segredos(trecho_original or "")
            mensagem = mascarar_segredos(mensagem_original or "")
            possivel_segredo = bool(flag_original) or any(
                mascarado != original
                for mascarado, original in (
                    (arquivo, arquivo_original or ""),
                    (trecho, trecho_original or ""),
                    (mensagem, mensagem_original or ""),
                )
            )
            atualizacoes = ["fingerprint_legado = ?", "possivel_segredo = ?"]
            valores = [fingerprint_legado, int(possivel_segredo)]
            for coluna, valor in (
                ("arquivo", arquivo),
                ("trecho", trecho),
                ("mensagem", mensagem),
            ):
                if coluna in colunas_existentes:
                    atualizacoes.append(f"{coluna} = ?")
                    valores.append(valor)
            valores.append(fingerprint)
            conn.execute(
                f"UPDATE findings SET {', '.join(atualizacoes)} WHERE fingerprint = ?",
                valores,
            )
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_MASCARAMENTO_SEGREDOS,),
        )
    migracao_mascaramento_v2_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_MASCARAMENTO_V2,),
    ).fetchone()
    if migracao_mascaramento_v2_aplicada is None:
        colunas_existentes = {
            linha[1] for linha in conn.execute("PRAGMA table_info(findings)")
        }
        campos_texto = ("arquivo", "trecho", "mensagem", "justificativa_ia")
        selecao = ", ".join(
            campo if campo in colunas_existentes else f"NULL AS {campo}"
            for campo in campos_texto
        )
        registros = conn.execute(
            f"SELECT fingerprint, {selecao}, possivel_segredo FROM findings"
        ).fetchall()
        for registro in registros:
            fingerprint, *valores_registro = registro
            textos_originais = valores_registro[:-1]
            flag_original = valores_registro[-1]
            textos_mascarados = tuple(
                mascarar_segredos(texto) if texto is not None else None
                for texto in textos_originais
            )
            possivel_segredo = bool(flag_original) or any(
                original is not None and mascarado != original
                for original, mascarado in zip(textos_originais, textos_mascarados)
            )
            atualizacoes = []
            valores = []
            for campo, valor in zip(campos_texto, textos_mascarados):
                if campo in colunas_existentes:
                    atualizacoes.append(f"{campo} = ?")
                    valores.append(valor)
            if "possivel_segredo" in colunas_existentes:
                atualizacoes.append("possivel_segredo = ?")
                valores.append(int(possivel_segredo))
            if atualizacoes:
                valores.append(fingerprint)
                conn.execute(
                    f"UPDATE findings SET {', '.join(atualizacoes)} "
                    "WHERE fingerprint = ?",
                    valores,
                )
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_MASCARAMENTO_V2,),
        )
    migracao_fechamento_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_FECHAMENTO_AUTOMATICO,),
    ).fetchone()
    if migracao_fechamento_aplicada is None:
        colunas_existentes = {
            linha[1] for linha in conn.execute("PRAGMA table_info(findings)")
        }
        if "fechado_automaticamente_em" not in colunas_existentes:
            conn.execute(
                "ALTER TABLE findings ADD COLUMN fechado_automaticamente_em TEXT"
            )
            colunas_existentes.add("fechado_automaticamente_em")
        campos_texto = ("arquivo", "trecho", "mensagem", "justificativa_ia")
        selecao = ", ".join(
            campo if campo in colunas_existentes else f"NULL AS {campo}"
            for campo in campos_texto
        )
        registros = conn.execute(
            f"SELECT fingerprint, {selecao}, possivel_segredo FROM findings"
        ).fetchall()
        for registro in registros:
            fingerprint, *valores_registro = registro
            textos_originais = valores_registro[:-1]
            flag_original = valores_registro[-1]
            textos_mascarados = tuple(
                mascarar_segredos(texto) if texto is not None else None
                for texto in textos_originais
            )
            possivel_segredo = bool(flag_original) or any(
                original is not None and mascarado != original
                for original, mascarado in zip(textos_originais, textos_mascarados)
            )
            atualizacoes = []
            valores = []
            for campo, valor in zip(campos_texto, textos_mascarados):
                if campo in colunas_existentes:
                    atualizacoes.append(f"{campo} = ?")
                    valores.append(valor)
            if "possivel_segredo" in colunas_existentes:
                atualizacoes.append("possivel_segredo = ?")
                valores.append(int(possivel_segredo))
            if atualizacoes:
                valores.append(fingerprint)
                conn.execute(
                    f"UPDATE findings SET {', '.join(atualizacoes)} "
                    "WHERE fingerprint = ?",
                    valores,
                )
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_FECHAMENTO_AUTOMATICO,),
        )
    migracao_ativos_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_ATIVOS,),
    ).fetchone()
    if migracao_ativos_aplicada is None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS ativos (
                   repositorio TEXT PRIMARY KEY NOT NULL,
                   nome TEXT NOT NULL,
                   tipo TEXT NOT NULL DEFAULT 'webapp'
                       CHECK (tipo IN ('webapp', 'api', 'lib')),
                   exposicao TEXT NOT NULL DEFAULT 'interna'
                       CHECK (exposicao IN ('internet', 'interna')),
                   criticidade INTEGER NOT NULL DEFAULT 3
                       CHECK (criticidade BETWEEN 1 AND 5),
                   url_alvo TEXT,
                   criado_em TEXT NOT NULL
               )"""
        )
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_ATIVOS,),
        )
    migracao_historico_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_HISTORICO_IMPORTACOES,),
    ).fetchone()
    if migracao_historico_aplicada is None:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS importacoes (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   repositorio TEXT,
                   ferramenta TEXT,
                   tipo_scan TEXT,
                   data TEXT NOT NULL,
                   lidos INTEGER NOT NULL DEFAULT 0,
                   novos INTEGER NOT NULL DEFAULT 0,
                   reabertos INTEGER NOT NULL DEFAULT 0,
                   fechados INTEGER NOT NULL DEFAULT 0
               )"""
        )
        repositorios = conn.execute(
            "SELECT DISTINCT repositorio FROM findings "
            "WHERE repositorio IS NOT NULL AND repositorio != ''"
        ).fetchall()
        for (repositorio,) in repositorios:
            registrar_ativo_se_ausente(repositorio, conn)
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_HISTORICO_IMPORTACOES,),
        )
    migracao_descartados_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_DESCARTADOS_IMPORTACAO,),
    ).fetchone()
    if migracao_descartados_aplicada is None:
        colunas_importacoes = {
            linha[1] for linha in conn.execute("PRAGMA table_info(importacoes)")
        }
        if "descartados" not in colunas_importacoes:
            conn.execute(
                "ALTER TABLE importacoes ADD COLUMN descartados INTEGER NOT NULL DEFAULT 0"
            )
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_DESCARTADOS_IMPORTACAO,),
        )
    migracao_tickets_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_TICKETS,),
    ).fetchone()
    if migracao_tickets_aplicada is None:
        colunas_findings = {
            linha[1] for linha in conn.execute("PRAGMA table_info(findings)")
        }
        novas_colunas_ticket = {
            "issue_url": "TEXT",
            "issue_numero": "INTEGER",
            "issue_estado": (
                "TEXT CHECK (issue_estado IS NULL OR "
                "issue_estado IN ('aberta', 'fechada'))"
            ),
            "issue_erro": "TEXT",
            "issue_tentativas": (
                "INTEGER NOT NULL DEFAULT 0 CHECK (issue_tentativas >= 0)"
            ),
        }
        for coluna, definicao in novas_colunas_ticket.items():
            if coluna not in colunas_findings:
                conn.execute(
                    f"ALTER TABLE findings ADD COLUMN {coluna} {definicao}"
                )
        conn.execute(
            """CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_github_issue
               ON findings (repositorio, issue_numero)
               WHERE issue_numero IS NOT NULL"""
        )
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_TICKETS,),
        )
    migracao_reserva_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_RESERVA_TICKETS,),
    ).fetchone()
    if migracao_reserva_aplicada is None:
        colunas_findings = {
            linha[1] for linha in conn.execute("PRAGMA table_info(findings)")
        }
        if "issue_reservado_em" not in colunas_findings:
            conn.execute("ALTER TABLE findings ADD COLUMN issue_reservado_em TEXT")
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_RESERVA_TICKETS,),
        )
    migracao_remediacao_aplicada = conn.execute(
        "SELECT 1 FROM elma_schema_migrations WHERE version = ?",
        (MIGRACAO_REMEDIACAO_IA,),
    ).fetchone()
    if migracao_remediacao_aplicada is None:
        colunas_findings = {
            linha[1] for linha in conn.execute("PRAGMA table_info(findings)")
        }
        for coluna in ("remediacao_ia", "remediacao_ia_gerada_em"):
            if coluna not in colunas_findings:
                conn.execute(f"ALTER TABLE findings ADD COLUMN {coluna} TEXT")
        conn.execute(
            "INSERT INTO elma_schema_migrations (version) VALUES (?)",
            (MIGRACAO_REMEDIACAO_IA,),
        )
    conn.commit()


def registrar_ativo_se_ausente(
    repositorio: str | None, conn: sqlite3.Connection
) -> bool:
    """Register a repository with conservative asset defaults if needed."""
    if not repositorio:
        return False
    nome = repositorio.rstrip("/").rsplit("/", 1)[-1] or repositorio
    criado_em = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """INSERT OR IGNORE INTO ativos
           (repositorio, nome, tipo, exposicao, criticidade, criado_em)
           VALUES (?, ?, 'webapp', 'interna', 3, ?)""",
        (repositorio, nome, criado_em),
    )
    return cursor.rowcount > 0


def registrar_importacao(
    conn: sqlite3.Connection,
    repositorio: str | None,
    ferramenta: str | None,
    tipo_scan: str | None,
    lidos: int,
    novos: int,
    reabertos: int,
    fechados: int,
    data: str | None = None,
    descartados: int = 0,
) -> None:
    """Persist a summary row for one completed ingestion."""
    conn.execute(
        """INSERT INTO importacoes
              (repositorio, ferramenta, tipo_scan, data, lidos, novos, reabertos,
                fechados, descartados)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            repositorio,
            ferramenta,
            tipo_scan,
            data or datetime.now(timezone.utc).isoformat(),
            lidos,
            novos,
            reabertos,
            fechados,
            descartados,
        ),
    )
    conn.commit()


def atualizar_ativo(
    repositorio: str,
    campos: dict,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Update editable asset metadata, opening the default DB if omitted."""
    if not repositorio:
        raise ValueError("repositorio é obrigatório")
    campos_permitidos = {"nome", "tipo", "exposicao", "criticidade", "url_alvo"}
    desconhecidos = set(campos) - campos_permitidos
    if desconhecidos:
        raise ValueError(f"campos de ativo inválidos: {sorted(desconhecidos)}")
    if "nome" in campos and (not isinstance(campos["nome"], str) or not campos["nome"].strip()):
        raise ValueError("nome precisa ser texto não vazio")
    if "tipo" in campos and campos["tipo"] not in TIPOS_ATIVO:
        raise ValueError(f"tipo precisa ser um de: {TIPOS_ATIVO}")
    if "exposicao" in campos and campos["exposicao"] not in EXPOSICOES_ATIVO:
        raise ValueError(f"exposicao precisa ser um de: {EXPOSICOES_ATIVO}")
    if "criticidade" in campos and (
        isinstance(campos["criticidade"], bool)
        or not isinstance(campos["criticidade"], int)
        or not 1 <= campos["criticidade"] <= 5
    ):
        raise ValueError("criticidade precisa ser um inteiro entre 1 e 5")
    if "url_alvo" in campos and campos["url_alvo"] is not None and not isinstance(
        campos["url_alvo"], str
    ):
        raise ValueError("url_alvo precisa ser texto ou null")

    propria_conexao = conn is None
    conn = conn or conectar()
    try:
        registrar_ativo_se_ausente(repositorio, conn)
        if not campos:
            conn.commit()
            return True
        atribuicoes = ", ".join(f"{campo} = ?" for campo in campos)
        conn.execute(
            f"UPDATE ativos SET {atribuicoes} WHERE repositorio = ?",
            (*campos.values(), repositorio),
        )
        conn.commit()
        return True
    finally:
        if propria_conexao:
            conn.close()


def _normalizar_trecho(trecho: str) -> str:
    """Remove espaços/indentação extra pra não quebrar o hash com reformatação boba."""
    return re.sub(r"\s+", " ", (trecho or "")).strip()


def _calcular_fingerprint_legado(achado: dict) -> str:
    """Reproduz o fingerprint anterior à inclusão da ferramenta na identidade."""
    extra = achado.get("extra") or {}
    regra = (
        achado.get("check_id")
        or achado.get("regra")
        or extra.get("message")
        or achado.get("mensagem")
        or "regra_desconhecida"
    )
    arquivo = mascarar_segredos(achado.get("path") or achado.get("arquivo") or "")
    trecho = extra.get("lines") if "lines" in extra else achado.get("trecho", "")
    evidencia = mascarar_segredos(_normalizar_trecho(trecho))
    base = f"{regra}|{arquivo}|{evidencia}"
    repositorio = achado.get("repositorio")
    if repositorio:
        base = f"{repositorio}|{base}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def _usa_fingerprint_com_ferramenta(achado: dict) -> bool:
    ferramenta = achado.get("tool_name") or achado.get("ferramenta")
    origem = achado.get("source_format") or achado.get("origem")
    return bool(ferramenta) and origem not in {"Semgrep JSON", "Elma local"}


def calcular_fingerprint(achado: dict) -> str:
    """
    Gera um hash estável a partir de: regra (check_id ou mensagem) + arquivo +
    evidência, todos mascarados (trecho normalizado ou, sem snippet, a mensagem).
    Assim o mesmo achado continua sendo reconhecido mesmo que a linha mude um
    pouco, e o hash não depende do valor bruto de um segredo no trecho/arquivo.
    """
    regra = achado.get("check_id") or achado.get("extra", {}).get("message", "regra_desconhecida")
    arquivo = mascarar_segredos(achado.get("path", ""))
    trecho = mascarar_segredos(
        _normalizar_trecho(achado.get("extra", {}).get("lines", ""))
    )
    repositorio = achado.get("repositorio")

    ferramenta = achado.get("tool_name") or achado.get("ferramenta")
    origem = achado.get("source_format") or achado.get("origem")
    if _usa_fingerprint_com_ferramenta(achado):
        extra = achado.get("extra", {})
        mensagem = extra.get("message") or achado.get("message", "")
        evidencia = trecho or mascarar_segredos(mensagem)
        base = f"{ferramenta}|{regra}|{arquivo}|{evidencia}"
        if repositorio:
            base = f"{repositorio}|{base}"
    else:
        return _calcular_fingerprint_legado(achado)
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def _criar_detalhe_conflito(
    fingerprint_legado: str,
    fingerprint_atual: str,
    status_legado: str,
    status_atual: str,
    achado: dict,
) -> dict:
    return {
        "fingerprint_legado": fingerprint_legado,
        "fingerprint_atual": fingerprint_atual,
        "status_legado": status_legado,
        "status_atual": status_atual,
        "arquivo": achado.get("path") or achado.get("arquivo") or "",
        "linha": (achado.get("start") or {}).get("line") or achado.get("linha"),
        "regra": achado.get("check_id") or achado.get("regra") or "",
    }


def _achado_mascarado(
    achado: dict,
    arquivo: str,
    trecho: str,
    mensagem: str,
    possivel_segredo: bool,
) -> dict:
    """Return a sanitized copy for callers while leaving hash input untouched."""
    resultado = dict(achado)
    resultado["possivel_segredo"] = possivel_segredo
    if "path" in resultado or "arquivo" not in resultado:
        resultado["path"] = arquivo
    if "arquivo" in resultado:
        resultado["arquivo"] = arquivo
    if "trecho" in resultado:
        resultado["trecho"] = trecho
    if "mensagem" in resultado:
        resultado["mensagem"] = mensagem
    if "message" in resultado:
        resultado["message"] = mensagem
    extra = resultado.get("extra")
    if isinstance(extra, dict):
        extra = dict(extra)
        if "lines" in extra:
            extra["lines"] = trecho
        if "message" in extra:
            extra["message"] = mensagem
        resultado["extra"] = extra
    return resultado


def filtrar_achados_novos(
    resultados: list[dict],
    conn: sqlite3.Connection,
    agora: str | None = None,
    contagens: dict[str, int] | None = None,
    reabertos_fps: list[str] | None = None,
) -> list[dict]:
    """
    Recebe a lista crua de achados (o que motor_sast_resiliente devolve em ["results"])
    e devolve só o que precisa aparecer pro usuário: achados novos ou ainda 'confirmado'.
    O que já foi marcado 'falso_positivo' é descartado silenciosamente.
    O que estava 'corrigido' e voltou a aparecer é reaberto como 'novo' (regressão).
    """
    agora = agora or datetime.now(timezone.utc).isoformat()
    para_mostrar = []

    conflitos = listar_conflitos_fingerprint(conn)
    for achado in resultados:
        if not _usa_fingerprint_com_ferramenta(achado):
            continue
        fp_atual = calcular_fingerprint(achado)
        fp_legado = _calcular_fingerprint_legado(achado)
        if fp_atual == fp_legado:
            continue
        atual = conn.execute(
            "SELECT status FROM findings WHERE fingerprint = ?", (fp_atual,)
        ).fetchone()
        legado = conn.execute(
            "SELECT status FROM findings WHERE fingerprint = ?", (fp_legado,)
        ).fetchone()
        if atual is not None and legado is not None:
            conflitos.append(
                _criar_detalhe_conflito(
                    fp_legado,
                    fp_atual,
                    legado[0],
                    atual[0],
                    achado,
                )
            )
    if conflitos:
        raise FingerprintConflictError(conflitos)

    for repositorio in dict.fromkeys(
        achado.get("repositorio") for achado in resultados if achado.get("repositorio")
    ):
        registrar_ativo_se_ausente(repositorio, conn)

    for achado in resultados:
        fp = calcular_fingerprint(achado)
        fp_legado = _calcular_fingerprint_legado(achado)
        linha = achado.get("start", {}).get("line", 0)
        regra = (
            achado.get("check_id")
            or achado.get("regra")
            or "regra_desconhecida"
        )
        arquivo_original = achado.get("path") or achado.get("arquivo") or ""
        trecho_original = achado.get("extra", {}).get("lines", achado.get("trecho", ""))
        ferramenta = achado.get("tool_name") or achado.get("ferramenta")
        severidade = achado.get("severity") or achado.get("severidade")
        origem = achado.get("source_format") or achado.get("origem")
        mensagem_original = (
            achado.get("extra", {}).get("message")
            or achado.get("message")
            or achado.get("mensagem")
            or ""
        )
        repositorio = achado.get("repositorio")
        tipo_scan = achado.get("tipo_scan")
        arquivo = mascarar_segredos(arquivo_original or "")
        trecho = mascarar_segredos(trecho_original or "")
        mensagem = mascarar_segredos(mensagem_original or "")
        possivel_segredo = bool(achado.get("possivel_segredo")) or any(
            mascarado != original
            for mascarado, original in (
                (arquivo, arquivo_original or ""),
                (trecho, trecho_original or ""),
                (mensagem, mensagem_original or ""),
            )
        )
        achado_saida = _achado_mascarado(
            achado, arquivo, trecho, mensagem, possivel_segredo
        )

        existente = conn.execute(
            "SELECT fingerprint, status FROM findings WHERE fingerprint = ?", (fp,)
        ).fetchone()
        if existente is None and fp_legado != fp:
            existente = conn.execute(
                "SELECT fingerprint, status FROM findings WHERE fingerprint = ?",
                (fp_legado,),
            ).fetchone()

        if existente is None:
            conn.execute(
                """INSERT INTO findings
                         (fingerprint, regra, arquivo, linha, trecho, status, primeira_vez,
                          ultima_vez, ferramenta, severidade, origem, mensagem, repositorio,
                          possivel_segredo, fingerprint_legado, tipo_scan)
                         VALUES (?, ?, ?, ?, ?, 'novo', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     (fp, regra, arquivo, linha, trecho, agora, agora, ferramenta,
                      severidade, origem, mensagem, repositorio,
                      int(possivel_segredo), fp_legado, tipo_scan),
            )
            para_mostrar.append(achado_saida)
            if contagens is not None:
                contagens["novos"] = contagens.get("novos", 0) + 1
        else:
            fingerprint_existente, status = existente
            conn.execute(
                """UPDATE findings
                   SET ultima_vez = ?,
                       ferramenta = COALESCE(?, ferramenta),
                       severidade = COALESCE(?, severidade),
                       origem = COALESCE(?, origem),
                       mensagem = COALESCE(?, mensagem),
                       repositorio = COALESCE(?, repositorio),
                       tipo_scan = COALESCE(?, tipo_scan),
                       fechado_automaticamente_em =
                           CASE WHEN status = 'corrigido' THEN NULL
                                ELSE fechado_automaticamente_em END,
                       arquivo = ?, trecho = ?, possivel_segredo = ?,
                       fingerprint_legado = COALESCE(fingerprint_legado, ?)
                   WHERE fingerprint = ?""",
                (
                    agora,
                    ferramenta or None,
                    severidade or None,
                    origem or None,
                    mensagem or None,
                    repositorio or None,
                    tipo_scan,
                    arquivo,
                    trecho,
                    int(possivel_segredo),
                    fp_legado,
                    fingerprint_existente,
                ),
            )
            if status == "falso_positivo":
                pass  # ignora, não mostra de novo
            elif status == "corrigido":
                conn.execute(
                    """UPDATE findings SET status = 'novo', primeira_vez = ?
                       WHERE fingerprint = ?""",
                    (agora, fingerprint_existente),
                )
                para_mostrar.append(achado_saida)  # regressão: voltou a aparecer
                if contagens is not None:
                    contagens["reabertos"] = contagens.get("reabertos", 0) + 1
                if reabertos_fps is not None:
                    reabertos_fps.append(fingerprint_existente)
            else:
                para_mostrar.append(achado_saida)

    conn.commit()
    return para_mostrar


def fechar_ausentes(
    conn: sqlite3.Connection,
    repositorio: str | None,
    ferramenta: str | None,
    tipo_scan: str | None,
    inicio_execucao: str,
    force: bool = False,
    sucesso_explicito: bool = False,
    fechados_fps: list[str] | None = None,
) -> tuple[int, str | None]:
    """Close open findings missing from a successful scan in this exact scope."""
    if not repositorio:
        return 0, "Fechamento automático ignorado: informe um repositório."
    if not tipo_scan:
        return 0, "Fechamento automático ignorado: informe o tipo do scan."
    if not ferramenta:
        return 0, "Fechamento automático ignorado: ferramenta não identificada."

    escopo = (repositorio, ferramenta, tipo_scan)
    abertos = conn.execute(
        """SELECT COUNT(*) FROM findings
           WHERE repositorio = ? AND ferramenta = ? AND tipo_scan = ?
             AND status IN ('novo', 'confirmado')""",
        escopo,
    ).fetchone()[0]
    ausentes = conn.execute(
        """SELECT fingerprint FROM findings
           WHERE repositorio = ? AND ferramenta = ? AND tipo_scan = ?
             AND status IN ('novo', 'confirmado')
             AND (ultima_vez IS NULL OR ultima_vez < ?)""",
        (*escopo, inicio_execucao),
    ).fetchall()
    quantidade_ausente = len(ausentes)
    if (
        not force
        and not sucesso_explicito
        and quantidade_ausente > 10
        and quantidade_ausente * 2 > abertos
    ):
        return (
            0,
            "Fechamento automático bloqueado: seriam fechados "
            f"{quantidade_ausente} de {abertos} findings abertos "
            "(mais de 50% e mais de 10). Use --force-close para liberar.",
        )
    if not ausentes:
        return 0, None

    fechado_em = datetime.now(timezone.utc).isoformat()
    cursor = conn.executemany(
        """UPDATE findings
           SET status = 'corrigido', fechado_automaticamente_em = ?
           WHERE fingerprint = ? AND status IN ('novo', 'confirmado')
             AND repositorio = ? AND ferramenta = ? AND tipo_scan = ?
             AND (ultima_vez IS NULL OR ultima_vez < ?)""",
        [
            (fechado_em, registro[0], *escopo, inicio_execucao)
            for registro in ausentes
        ],
    )
    conn.commit()
    if fechados_fps is not None:
        fechados_fps.extend(registro[0] for registro in ausentes)
    return cursor.rowcount, None


def marcar_status(fingerprint: str, novo_status: str, conn: sqlite3.Connection) -> bool:
    """Triagem manual: marca um achado como 'falso_positivo', 'confirmado' ou 'corrigido'."""
    validos = {"novo", "confirmado", "falso_positivo", "corrigido"}
    if novo_status not in validos:
        raise ValueError(f"status precisa ser um de: {validos}")
    cur = conn.execute(
        "UPDATE findings SET status = ? WHERE fingerprint = ?", (novo_status, fingerprint)
    )
    conn.commit()
    return cur.rowcount > 0


def atualizar_sugestao_ia(
    fingerprint: str,
    sugestao: str,
    confianca: int,
    justificativa: str,
    conn: sqlite3.Connection,
) -> bool:
    """Persist a consultative AI suggestion without changing finding triage."""
    sugestoes_validas = {
        "provavel_falso_positivo",
        "provavel_real",
        "indeterminado",
    }
    if sugestao not in sugestoes_validas:
        raise ValueError(f"sugestao precisa ser uma de: {sorted(sugestoes_validas)}")
    if isinstance(confianca, bool) or not isinstance(confianca, int) or not 0 <= confianca <= 10:
        raise ValueError("confianca precisa ser um inteiro entre 0 e 10")
    if not isinstance(justificativa, str):
        raise ValueError("justificativa precisa ser texto")
    justificativa = mascarar_segredos(justificativa)
    gerada_em = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """UPDATE findings
           SET sugestao_ia = ?, confianca_ia = ?, justificativa_ia = ?,
               sugestao_ia_gerada_em = ?
           WHERE fingerprint = ?""",
        (sugestao, confianca, justificativa, gerada_em, fingerprint),
    )
    conn.commit()
    return cur.rowcount > 0


def atualizar_remediacao_ia(
    fingerprint: str,
    remediacao: str,
    conn: sqlite3.Connection,
) -> bool:
    """Persist consultative AI remediation guidance without changing triage."""
    if not isinstance(remediacao, str):
        raise ValueError("remediacao precisa ser texto")
    remediacao = mascarar_segredos(remediacao)
    gerada_em = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        """UPDATE findings
           SET remediacao_ia = ?, remediacao_ia_gerada_em = ?
           WHERE fingerprint = ?""",
        (remediacao, gerada_em, fingerprint),
    )
    conn.commit()
    return cur.rowcount > 0


def listar_achados(
    conn: sqlite3.Connection,
    status: str | None = None,
    severidade: str | None = None,
    tipo_scan: str | None = None,
) -> list[dict]:
    """Lista achados filtrando opcionalmente por status, severidade e tipo."""
    validos = {"novo", "confirmado", "falso_positivo", "corrigido"}
    if status is not None and status not in validos:
        raise ValueError(f"status precisa ser um de: {validos}")
    if tipo_scan is not None and tipo_scan not in TIPOS_SCAN:
        raise ValueError(f"tipo precisa ser um de: {TIPOS_SCAN}")

    query = """
        SELECT fingerprint, regra, arquivo, linha, trecho, status, primeira_vez,
               ultima_vez, ferramenta, severidade, origem, mensagem, repositorio,
               possivel_segredo, fingerprint_legado, sugestao_ia, confianca_ia,
               justificativa_ia, sugestao_ia_gerada_em, remediacao_ia,
               remediacao_ia_gerada_em, tipo_scan,
                             fechado_automaticamente_em, issue_url, issue_numero, issue_estado,
                             issue_erro, issue_tentativas
        FROM findings
    """
    filtros = []
    parametros = []
    if status is not None:
        filtros.append("status = ?")
        parametros.append(status)
    if severidade is not None:
        filtros.append("UPPER(severidade) = UPPER(?)")
        parametros.append(severidade)
    if tipo_scan is not None:
        filtros.append("tipo_scan = ?")
        parametros.append(tipo_scan)
    if filtros:
        query += " WHERE " + " AND ".join(filtros)
    query += """
        ORDER BY CASE UPPER(COALESCE(severidade, ''))
                     WHEN 'CRITICAL' THEN 0
                     WHEN 'HIGH' THEN 1
                     WHEN 'MEDIUM' THEN 2
                     WHEN 'LOW' THEN 3
                     WHEN 'INFO' THEN 4
                     ELSE 5
                 END,
                 arquivo, linha, fingerprint
    """
    cursor = conn.execute(query, parametros)
    colunas = [coluna[0] for coluna in cursor.description]
    return [dict(zip(colunas, linha)) for linha in cursor.fetchall()]


def resumir_postura(conn: sqlite3.Connection) -> dict:
    """Return severity/status totals and recent/secret finding KPIs."""
    por_severidade = {severidade: 0 for severidade in SEVERIDADES_AGREGACAO}
    por_status = {status: 0 for status in STATUS_AGREGACAO}
    for severidade, total in conn.execute(
        "SELECT UPPER(COALESCE(severidade, 'UNKNOWN')), COUNT(*) "
        "FROM findings GROUP BY UPPER(COALESCE(severidade, 'UNKNOWN'))"
    ):
        chave = severidade if severidade in por_severidade else "UNKNOWN"
        por_severidade[chave] += total
    for status, total in conn.execute(
        "SELECT COALESCE(status, 'novo'), COUNT(*) FROM findings GROUP BY status"
    ):
        if status in por_status:
            por_status[status] = total

    limite = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    novos_7d = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE primeira_vez >= ?", (limite,)
    ).fetchone()[0]
    possiveis_segredos = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE possivel_segredo = 1"
    ).fetchone()[0]
    achados_sla = [
        {"severidade": severidade, "status": status, "primeira_vez": primeira_vez}
        for severidade, status, primeira_vez in conn.execute(
            "SELECT severidade, status, primeira_vez FROM findings"
        )
    ]
    return {
        "total": sum(por_severidade.values()),
        "por_severidade": por_severidade,
        "por_status": por_status,
        "novos_7d": novos_7d,
        "possiveis_segredos": possiveis_segredos,
        "sla": resumir_sla(achados_sla),
    }


def resumir_metricas(conn: sqlite3.Connection) -> dict:
    """Return derived aging/MTTR/trend metrics plus the SLA summary.

    Pure read: pulls the finding timestamps and the import history and defers
    all computation to :mod:`elma.metricas` (no persistence, no migration).
    """
    achados = [
        {
            "status": status,
            "severidade": severidade,
            "primeira_vez": primeira_vez,
            "fechado_automaticamente_em": fechado_em,
        }
        for status, severidade, primeira_vez, fechado_em in conn.execute(
            "SELECT status, severidade, primeira_vez, fechado_automaticamente_em "
            "FROM findings"
        )
    ]
    importacoes = [
        {"data": data, "novos": novos, "fechados": fechados, "lidos": lidos}
        for data, novos, fechados, lidos in conn.execute(
            "SELECT data, novos, fechados, lidos FROM importacoes"
        )
    ]
    return metricas.resumir_metricas(achados, importacoes)


def resumir_ativos(conn: sqlite3.Connection) -> list[dict]:
    """Summarize each asset's findings and missing scan types."""
    ativos = {}
    ultimo_scan_importado = {
        (repositorio, tipo_scan): data
        for repositorio, tipo_scan, data in conn.execute(
            """SELECT repositorio, tipo_scan, MAX(data)
               FROM importacoes
               WHERE repositorio IS NOT NULL AND tipo_scan IS NOT NULL
               GROUP BY repositorio, tipo_scan"""
        )
    }
    cursor = conn.execute(
        """SELECT a.repositorio, a.nome, a.tipo, a.exposicao, a.criticidade,
                  a.url_alvo, a.criado_em, f.tipo_scan, f.severidade,
                  COUNT(f.fingerprint), MAX(f.ultima_vez)
           FROM ativos AS a
           LEFT JOIN findings AS f ON f.repositorio = a.repositorio
           GROUP BY a.repositorio, f.tipo_scan, f.severidade
           ORDER BY a.nome COLLATE NOCASE, a.repositorio"""
    )
    for (
        repositorio,
        nome,
        tipo,
        exposicao,
        criticidade,
        url_alvo,
        criado_em,
        tipo_scan,
        severidade,
        total,
        ultimo_scan,
    ) in cursor:
        ativo = ativos.setdefault(
            repositorio,
            {
                "repositorio": repositorio,
                "nome": nome,
                "tipo": tipo,
                "exposicao": exposicao,
                "criticidade": criticidade,
                "url_alvo": url_alvo,
                "criado_em": criado_em,
                "total_findings": 0,
                "por_severidade": {
                    key: 0 for key in SEVERIDADES_AGREGACAO
                },
                "por_tipo_scan": {
                    scan: {
                        "total": 0,
                        "por_severidade": {
                            key: 0 for key in SEVERIDADES_AGREGACAO
                        },
                        "ultimo_scan": None,
                    }
                    for scan in TIPOS_SCAN
                },
                "sem_tipo_scan": 0,
                "lacunas": list(TIPOS_SCAN),
            },
        )
        if tipo_scan is None:
            ativo["sem_tipo_scan"] += total
            continue
        scan = ativo["por_tipo_scan"].get(tipo_scan)
        if scan is None:
            continue
        nivel = severidade if severidade in SEVERIDADES_AGREGACAO else "UNKNOWN"
        scan["total"] += total
        scan["por_severidade"][nivel] += total
        scan["ultimo_scan"] = max(
            (scan["ultimo_scan"], ultimo_scan),
            key=lambda item: item or "",
        )
        ativo["total_findings"] += total
        ativo["por_severidade"][nivel] += total

    for ativo in ativos.values():
        for tipo_scan, resumo in ativo["por_tipo_scan"].items():
            data_importacao = ultimo_scan_importado.get(
                (ativo["repositorio"], tipo_scan)
            )
            resumo["ultimo_scan"] = max(
                (resumo["ultimo_scan"], data_importacao),
                key=lambda item: item or "",
            )
        ativo["lacunas"] = [
            tipo_scan
            for tipo_scan, resumo in ativo["por_tipo_scan"].items()
            if resumo["ultimo_scan"] is None
        ]
    return list(ativos.values())


def listar_fila(
    conn: sqlite3.Connection,
    filtros: dict | None = None,
    limit: int = 50,
    offset: int = 0,
    sla_dias: dict | None = None,
) -> dict:
    """Return a score-sorted, filtered and paginated finding queue."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError("limit precisa ser um inteiro entre 1 e 200")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError("offset precisa ser um inteiro não negativo")
    filtros = filtros or {}
    permitidos = {
        "repositorio", "status", "severidade", "tipo_scan", "exposicao",
        "criticidade_min", "possivel_segredo", "atrasado",
    }
    desconhecidos = set(filtros) - permitidos
    if desconhecidos:
        raise ValueError(f"filtros inválidos: {sorted(desconhecidos)}")
    if filtros.get("exposicao") is not None and filtros["exposicao"] not in EXPOSICOES_ATIVO:
        raise ValueError(f"exposicao precisa ser um de: {EXPOSICOES_ATIVO}")
    criticidade_min = filtros.get("criticidade_min")
    if criticidade_min is not None and (
        isinstance(criticidade_min, bool)
        or not isinstance(criticidade_min, int)
        or not 1 <= criticidade_min <= 5
    ):
        raise ValueError("criticidade_min precisa ser um inteiro entre 1 e 5")

    achados = listar_achados(
        conn,
        status=filtros.get("status"),
        severidade=filtros.get("severidade"),
        tipo_scan=filtros.get("tipo_scan"),
    )
    colunas_ativo = (
        "repositorio", "nome", "tipo", "exposicao", "criticidade", "url_alvo", "criado_em"
    )
    ativos = {
        ativo["repositorio"]: ativo
        for linha in conn.execute(
            "SELECT repositorio, nome, tipo, exposicao, criticidade, url_alvo, criado_em "
            "FROM ativos"
        ).fetchall()
        for ativo in [dict(zip(colunas_ativo, linha))]
    }
    fila = []
    sla_dias = sla_dias if sla_dias is not None else resolver_sla_dias()
    for achado in achados:
        repositorio = achado.get("repositorio")
        if filtros.get("repositorio") is not None and repositorio != filtros["repositorio"]:
            continue
        ativo = ativos.get(repositorio)
        if filtros.get("exposicao") and (ativo or {}).get("exposicao") != filtros["exposicao"]:
            continue
        if criticidade_min is not None and (ativo or {}).get("criticidade", 0) < criticidade_min:
            continue
        if (
            filtros.get("possivel_segredo") is not None
            and bool(achado.get("possivel_segredo"))
            != bool(filtros["possivel_segredo"])
        ):
            continue
        componentes = calcular_componentes_score(achado, ativo)
        sla = calcular_sla(achado, sla_dias=sla_dias)
        if (
            filtros.get("atrasado") is not None
            and sla["atrasado"] != bool(filtros["atrasado"])
        ):
            continue
        fila.append(
            {
                **achado,
                "ativo": ativo,
                "score": componentes["score"],
                "score_componentes": componentes,
                "sla": sla,
            }
        )

    fila.sort(key=lambda achado: (-achado["score"], achado["fingerprint"]))
    total = len(fila)
    return {
        "items": fila[offset : offset + limit],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def resumir_status_regra(achado: dict, conn: sqlite3.Connection) -> dict | None:
    """Count current statuses for this repository, scanner, and rule."""
    repositorio = achado.get("repositorio")
    ferramenta = achado.get("ferramenta")
    regra = achado.get("regra")
    if not repositorio or not ferramenta or not regra:
        return None

    contagens = {
        status: 0 for status in ("novo", "confirmado", "falso_positivo", "corrigido")
    }
    registros = conn.execute(
        """SELECT status, COUNT(*)
           FROM findings
           WHERE repositorio = ? AND ferramenta = ? AND regra = ?
           GROUP BY status""",
        (repositorio, ferramenta, regra),
    ).fetchall()
    contagens.update({status: total for status, total in registros if status in contagens})
    return contagens


def obter_achado(fingerprint: str, conn: sqlite3.Connection) -> dict | None:
    """Retorna um achado pelo fingerprint ou None se não existir."""
    cursor = conn.execute(
        """
        SELECT fingerprint, regra, arquivo, linha, trecho, status, primeira_vez,
               ultima_vez, ferramenta, severidade, origem, mensagem, repositorio,
               possivel_segredo, sugestao_ia, confianca_ia, justificativa_ia,
                             sugestao_ia_gerada_em, remediacao_ia, remediacao_ia_gerada_em,
                             tipo_scan, fechado_automaticamente_em,
                             issue_url, issue_numero, issue_estado, issue_erro, issue_tentativas
        FROM findings
        WHERE fingerprint = ?
        """,
        (fingerprint,),
    )
    linha = cursor.fetchone()
    if linha is None:
        return None
    colunas = [coluna[0] for coluna in cursor.description]
    achado = dict(zip(colunas, linha))
    achado["sla"] = calcular_sla(achado)
    return achado


def listar_conflitos_fingerprint(conn: sqlite3.Connection) -> list[dict]:
    """Find exact legacy/current fingerprint pairs already stored in the database."""
    achados = listar_achados(conn)
    por_fingerprint = {achado["fingerprint"]: achado for achado in achados}
    conflitos = []
    pares_encontrados = set()

    for atual in achados:
        if not _usa_fingerprint_com_ferramenta(atual):
            continue
        fingerprint_legado = atual.get("fingerprint_legado")
        if not fingerprint_legado:
            continue
        fingerprint_atual = atual["fingerprint"]
        if fingerprint_legado == fingerprint_atual:
            continue
        legado = por_fingerprint.get(fingerprint_legado)
        if legado is None:
            continue

        par = (fingerprint_legado, fingerprint_atual)
        if par in pares_encontrados:
            continue
        pares_encontrados.add(par)
        conflitos.append(
            _criar_detalhe_conflito(
                fingerprint_legado,
                fingerprint_atual,
                legado.get("status") or "novo",
                atual.get("status") or "novo",
                atual,
            )
        )

    return conflitos


if __name__ == "__main__":
    # Teste rápido manual: roda duas vezes com o mesmo achado fake e mostra
    # que na segunda vez ele não duplica.
    conn = conectar(":memory:")
    achado_fake = {
        "check_id": "python.sqli.hardcoded-select",
        "path": "app.py",
        "start": {"line": 10},
        "extra": {"message": "SQL Injection", "lines": "query = 'SELECT * FROM users WHERE id=' + id"},
    }
    print("1ª rodada:", len(filtrar_achados_novos([achado_fake], conn)), "achado(s) pra mostrar (novo)")
    print("2ª rodada:", len(filtrar_achados_novos([achado_fake], conn)), "achado(s) pra mostrar (ainda 'novo', continua aparecendo até você triar)")

    fp = calcular_fingerprint(achado_fake)
    marcar_status(fp, "falso_positivo", conn)
    print("3ª rodada (após marcar como FP):", len(filtrar_achados_novos([achado_fake], conn)), "achado(s) pra mostrar (deve ser 0)")
