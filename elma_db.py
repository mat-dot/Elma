"""
elma_db.py — Camada de memória do Elma (o "banco" que falta pra virar ASPM).

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
from datetime import datetime, timezone

from elma_severity import normalizar_severidade

CAMINHO_BANCO_PADRAO = "elma_findings.db"
MIGRACAO_SEVERIDADE_CANONICA = 1


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


def conectar(caminho_banco: str = CAMINHO_BANCO_PADRAO) -> sqlite3.Connection:
    """Abre a conexão e garante que a tabela existe."""
    conn = sqlite3.connect(caminho_banco)
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
            repositorio     TEXT
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
    conn.commit()
    return conn


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
    arquivo = achado.get("path") or achado.get("arquivo") or ""
    trecho = extra.get("lines") if "lines" in extra else achado.get("trecho", "")
    base = f"{regra}|{arquivo}|{_normalizar_trecho(trecho)}"
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
    Gera um hash estável a partir de: regra (check_id ou mensagem) + arquivo + trecho normalizado.
    Assim o mesmo achado continua sendo reconhecido mesmo que a linha mude um pouco.
    """
    regra = achado.get("check_id") or achado.get("extra", {}).get("message", "regra_desconhecida")
    arquivo = achado.get("path", "")
    trecho = _normalizar_trecho(achado.get("extra", {}).get("lines", ""))
    repositorio = achado.get("repositorio")

    ferramenta = achado.get("tool_name") or achado.get("ferramenta")
    origem = achado.get("source_format") or achado.get("origem")
    if _usa_fingerprint_com_ferramenta(achado):
        extra = achado.get("extra", {})
        mensagem = extra.get("message") or achado.get("message", "")
        linha = achado.get("start", {}).get("line", 0)
        evidencia = trecho or f"{mensagem}|{linha}"
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


def filtrar_achados_novos(resultados: list[dict], conn: sqlite3.Connection) -> list[dict]:
    """
    Recebe a lista crua de achados (o que motor_sast_resiliente devolve em ["results"])
    e devolve só o que precisa aparecer pro usuário: achados novos ou ainda 'confirmado'.
    O que já foi marcado 'falso_positivo' é descartado silenciosamente.
    O que estava 'corrigido' e voltou a aparecer é reaberto como 'novo' (regressão).
    """
    agora = datetime.now(timezone.utc).isoformat()
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

    for achado in resultados:
        fp = calcular_fingerprint(achado)
        fp_legado = _calcular_fingerprint_legado(achado)
        linha = achado.get("start", {}).get("line", 0)
        regra = achado.get("check_id") or achado.get("extra", {}).get("message", "")
        arquivo = achado.get("path", "")
        trecho = achado.get("extra", {}).get("lines", "")
        ferramenta = achado.get("tool_name") or achado.get("ferramenta")
        severidade = achado.get("severity") or achado.get("severidade")
        origem = achado.get("source_format") or achado.get("origem")
        mensagem = achado.get("extra", {}).get("message") or achado.get("message", "")
        repositorio = achado.get("repositorio")

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
                          ultima_vez, ferramenta, severidade, origem, mensagem, repositorio)
                         VALUES (?, ?, ?, ?, ?, 'novo', ?, ?, ?, ?, ?, ?, ?)""",
                     (fp, regra, arquivo, linha, trecho, agora, agora, ferramenta,
                      severidade, origem, mensagem, repositorio),
            )
            para_mostrar.append(achado)
        else:
            fingerprint_existente, status = existente
            conn.execute(
                """UPDATE findings
                   SET ultima_vez = ?,
                       ferramenta = COALESCE(?, ferramenta),
                       severidade = COALESCE(?, severidade),
                       origem = COALESCE(?, origem),
                       mensagem = COALESCE(?, mensagem),
                       repositorio = COALESCE(?, repositorio)
                   WHERE fingerprint = ?""",
                (
                    agora,
                    ferramenta or None,
                    severidade or None,
                    origem or None,
                    mensagem or None,
                    repositorio or None,
                    fingerprint_existente,
                ),
            )
            if status == "falso_positivo":
                pass  # ignora, não mostra de novo
            elif status == "corrigido":
                conn.execute(
                    """UPDATE findings SET status = 'novo'
                       WHERE fingerprint = ?""",
                    (fingerprint_existente,),
                )
                para_mostrar.append(achado)  # regressão: voltou a aparecer
            else:
                para_mostrar.append(achado)

    conn.commit()
    return para_mostrar


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


def listar_achados(
    conn: sqlite3.Connection,
    status: str | None = None,
    severidade: str | None = None,
) -> list[dict]:
    """Lista achados filtrando opcionalmente por status e severidade."""
    validos = {"novo", "confirmado", "falso_positivo", "corrigido"}
    if status is not None and status not in validos:
        raise ValueError(f"status precisa ser um de: {validos}")

    query = """
        SELECT fingerprint, regra, arquivo, linha, trecho, status, primeira_vez,
             ultima_vez, ferramenta, severidade, origem, mensagem, repositorio
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


def obter_achado(fingerprint: str, conn: sqlite3.Connection) -> dict | None:
    """Retorna um achado pelo fingerprint ou None se não existir."""
    cursor = conn.execute(
        """
        SELECT fingerprint, regra, arquivo, linha, trecho, status, primeira_vez,
             ultima_vez, ferramenta, severidade, origem, mensagem, repositorio
        FROM findings
        WHERE fingerprint = ?
        """,
        (fingerprint,),
    )
    linha = cursor.fetchone()
    if linha is None:
        return None
    colunas = [coluna[0] for coluna in cursor.description]
    return dict(zip(colunas, linha))


def listar_conflitos_fingerprint(conn: sqlite3.Connection) -> list[dict]:
    """Find exact legacy/current fingerprint pairs already stored in the database."""
    achados = listar_achados(conn)
    por_fingerprint = {achado["fingerprint"]: achado for achado in achados}
    conflitos = []
    pares_encontrados = set()

    for atual in achados:
        if not _usa_fingerprint_com_ferramenta(atual):
            continue
        fingerprint_legado = _calcular_fingerprint_legado(atual)
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
