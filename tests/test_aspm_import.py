import hashlib
import json
import os
import sqlite3
import tempfile
import unittest

from elma.db import (
    FingerprintConflictError,
    ULTIMA_MIGRACAO,
    atualizar_ativo,
    calcular_fingerprint,
    conectar,
    fechar_ausentes,
    filtrar_achados_novos,
    listar_conflitos_fingerprint,
)
from elma.guardrails import mascarar_segredos
from elma.importer import (
    carregar_sarif_com_escopo,
    importar_sarif_para_banco_com_fechamento,
    importar_sarif_para_banco,
    marcar_sarif_sucesso_explicito,
    parse_sarif,
    parse_sarif_com_escopo,
)


FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "fixtures", "trivy.sarif")
ROOT = os.path.dirname(os.path.dirname(__file__))
SEMGREP_FIXTURE_PATH = os.path.join(ROOT, "sarif-reports", "semgrep.sarif")


class SarifImportTests(unittest.TestCase):
    def setUp(self):
        with open(FIXTURE_PATH, "r", encoding="utf-8") as fixture:
            self.document = json.load(fixture)

    def test_parses_trivy_finding_metadata(self):
        finding = parse_sarif(self.document)[0]

        self.assertEqual(finding["tool_name"], "Trivy")
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["path"], "Dockerfile")
        self.assertEqual(finding["start"]["line"], 1)
        self.assertEqual(finding["extra"]["lines"], "FROM alpine:3.19")

    def test_ingesting_repository_registers_default_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "findings.db")
            total, _ = importar_sarif_para_banco(
                FIXTURE_PATH, database_path, "org/example-app"
            )
            self.assertGreater(total, 0)

            conn = conectar(database_path)
            try:
                asset = conn.execute(
                    """SELECT repositorio, nome, tipo, exposicao, criticidade
                       FROM ativos"""
                ).fetchone()
                self.assertEqual(
                    asset,
                    ("org/example-app", "example-app", "webapp", "interna", 3),
                )
                atualizar_ativo(
                    "org/example-app",
                    {"exposicao": "internet", "criticidade": 5, "tipo": "api"},
                    conn,
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT tipo, exposicao, criticidade FROM ativos"
                    ).fetchone(),
                    ("api", "internet", 5),
                )
                with self.assertRaisesRegex(ValueError, "criticidade"):
                    atualizar_ativo("org/example-app", {"criticidade": 6}, conn)
            finally:
                conn.close()

    def test_migration_six_backfills_assets_from_existing_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "legacy.db")
            conn = conectar(database_path)
            conn.executemany(
                "INSERT INTO findings (fingerprint, repositorio) VALUES (?, ?)",
                [("legacy-1", "mat-dot/app"), ("legacy-2", "mat-dot/app")],
            )
            conn.execute(
                "DELETE FROM elma_schema_migrations WHERE version >= 6"
            )
            conn.commit()
            conn.close()

            conn = conectar(database_path)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT repositorio, nome, tipo, exposicao, criticidade "
                        "FROM ativos"
                    ).fetchall(),
                    [("mat-dot/app", "app", "webapp", "interna", 3)],
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT MAX(version) FROM elma_schema_migrations"
                    ).fetchone()[0],
                    ULTIMA_MIGRACAO,
                )
            finally:
                conn.close()

    def test_scan_type_is_optional_and_does_not_change_fingerprint(self):
        without_type = parse_sarif(self.document)[0]
        with_type = parse_sarif(self.document, "iac")[0]
        secrets_type = parse_sarif(self.document, "secrets")[0]

        self.assertIsNone(without_type["tipo_scan"])
        self.assertEqual(with_type["tipo_scan"], "iac")
        self.assertEqual(secrets_type["tipo_scan"], "secrets")
        self.assertEqual(
            calcular_fingerprint(without_type), calcular_fingerprint(with_type)
        )
        with self.assertRaisesRegex(ValueError, "tipo precisa ser"):
            parse_sarif(self.document, "unknown")

    def test_scoped_parser_excludes_failed_or_erroring_tool_runs(self):
        document = json.loads(json.dumps(self.document))
        run = document["runs"][0]
        run["tool"]["driver"]["name"] = "Scanner"
        _, tools = parse_sarif_com_escopo(document, "sast")
        self.assertEqual(tools, {"Scanner"})

        run["invocations"] = [{"executionSuccessful": True}]
        findings, tools = parse_sarif_com_escopo(document, "sast")
        self.assertEqual(len(findings), 1)
        self.assertEqual(tools, {"Scanner"})

        run["invocations"] = [{"executionSuccessful": False}]
        _, tools = parse_sarif_com_escopo(document, "sast")
        self.assertEqual(tools, set())

        run["invocations"] = [
            {"toolExecutionNotifications": [{"level": "error"}]}
        ]
        _, tools = parse_sarif_com_escopo(document, "sast")
        self.assertEqual(tools, set())

        document["runs"].append(json.loads(json.dumps(run)))
        document["runs"][0]["invocations"] = [{"executionSuccessful": True}]
        _, tools = parse_sarif_com_escopo(document, "sast")
        self.assertEqual(tools, set())

    def test_empty_scan_requires_explicit_success_invocation(self):
        document = json.loads(json.dumps(self.document))
        run = document["runs"][0]
        run["results"] = []

        sem_sucesso = set()
        sem_confirmacao = set()
        _, tools = parse_sarif_com_escopo(
            document,
            "container",
            sucessos_explicitos=sem_sucesso,
            ferramentas_sem_sucesso_explicito=sem_confirmacao,
        )
        self.assertEqual(tools, set())
        self.assertEqual(sem_sucesso, set())
        self.assertEqual(sem_confirmacao, {"Trivy"})

        run["invocations"] = [{"executionSuccessful": True}]
        sucessos = set()
        _, tools = parse_sarif_com_escopo(
            document, "container", sucessos_explicitos=sucessos
        )
        self.assertEqual(tools, {"Trivy"})
        self.assertEqual(sucessos, {"Trivy"})

        run["invocations"] = [{"executionSuccessful": False}]
        _, tools = parse_sarif_com_escopo(document, "container")
        self.assertEqual(tools, set())

    def test_trivy_success_marker_is_added_only_to_trivy_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            sarif_path = os.path.join(directory, "empty.sarif")
            document = json.loads(json.dumps(self.document))
            semgrep_run = json.loads(json.dumps(document["runs"][0]))
            semgrep_run["tool"]["driver"]["name"] = "Semgrep"
            document["runs"].append(semgrep_run)
            with open(sarif_path, "w", encoding="utf-8") as sarif_file:
                json.dump(document, sarif_file)

            marcar_sarif_sucesso_explicito(sarif_path)
            with open(sarif_path, "r", encoding="utf-8") as sarif_file:
                marked_document = json.load(sarif_file)

        invocations = marked_document["runs"][0]["invocations"]
        self.assertEqual(invocations[-1], {"executionSuccessful": True})
        self.assertNotIn("invocations", marked_document["runs"][1])

    def test_zero_result_sarif_requires_explicit_success_or_cli_force(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "findings.db")
            sarif_path = os.path.join(directory, "empty.sarif")
            document = json.loads(json.dumps(self.document))
            document["runs"][0]["results"] = []
            with open(sarif_path, "w", encoding="utf-8") as sarif_file:
                json.dump(document, sarif_file)

            conn = conectar(database_path)
            conn.executemany(
                """INSERT INTO findings
                   (fingerprint, status, ultima_vez, repositorio, ferramenta, tipo_scan)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                [
                    (
                        "missing-open",
                        "confirmado",
                        "2020-01-01T00:00:00+00:00",
                        "org/repo",
                        "Trivy",
                        "container",
                    ),
                    (
                        "false-positive",
                        "falso_positivo",
                        "2020-01-01T00:00:00+00:00",
                        "org/repo",
                        "Trivy",
                        "container",
                    ),
                    (
                        "other-type",
                        "novo",
                        "2020-01-01T00:00:00+00:00",
                        "org/repo",
                        "Trivy",
                        "sca",
                    ),
                ],
            )
            conn.commit()
            conn.close()

            total, ativos, fechados, avisos = importar_sarif_para_banco_com_fechamento(
                sarif_path, database_path, "org/repo", "container"
            )

            self.assertEqual((total, ativos, fechados), (0, 0, 0))
            self.assertTrue(any("executionSuccessful" in aviso for aviso in avisos))
            total, ativos, fechados, avisos = importar_sarif_para_banco_com_fechamento(
                sarif_path,
                database_path,
                "org/repo",
                "container",
                force_close=True,
            )
            self.assertEqual((total, ativos, fechados, avisos), (0, 0, 1, []))
            conn = conectar(database_path)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM findings WHERE fingerprint = 'missing-open'"
                    ).fetchone()[0],
                    "corrigido",
                )
                self.assertTrue(
                    conn.execute(
                        "SELECT fechado_automaticamente_em FROM findings "
                        "WHERE fingerprint = 'missing-open'"
                    ).fetchone()[0]
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM findings WHERE fingerprint = 'false-positive'"
                    ).fetchone()[0],
                    "falso_positivo",
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT status FROM findings WHERE fingerprint = 'other-type'"
                    ).fetchone()[0],
                    "novo",
                )
            finally:
                conn.close()

    def test_explicitly_successful_empty_scan_bypasses_bulk_close_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "findings.db")
            sarif_path = os.path.join(directory, "empty.sarif")
            document = json.loads(json.dumps(self.document))
            document["runs"][0]["results"] = []
            document["runs"][0]["invocations"] = [
                {"executionSuccessful": True}
            ]
            with open(sarif_path, "w", encoding="utf-8") as sarif_file:
                json.dump(document, sarif_file)

            conn = conectar(database_path)
            conn.executemany(
                """INSERT INTO findings
                   (fingerprint, status, ultima_vez, repositorio, ferramenta, tipo_scan)
                   VALUES (?, 'novo', '2020-01-01T00:00:00+00:00',
                           'org/repo', 'Trivy', 'container')""",
                [(f"missing-{index}",) for index in range(11)],
            )
            conn.commit()
            conn.close()

            total, ativos, fechados, avisos = importar_sarif_para_banco_com_fechamento(
                sarif_path, database_path, "org/repo", "container"
            )
            self.assertEqual((total, ativos, fechados, avisos), (0, 0, 11, []))

    def test_mass_close_guard_uses_preclose_open_count_and_force_override(self):
        conn = conectar(":memory:")
        inicio = "2025-01-01T00:00:00+00:00"
        registros = [
            (
                f"fp-{index}",
                "novo",
                "2020-01-01T00:00:00+00:00" if index < 11 else inicio,
                "org/repo",
                "Scanner",
                "sast",
            )
            for index in range(20)
        ]
        registros.append(
            (
                "fp-fp",
                "falso_positivo",
                "2020-01-01T00:00:00+00:00",
                "org/repo",
                "Scanner",
                "sast",
            )
        )
        conn.executemany(
            """INSERT INTO findings
               (fingerprint, status, ultima_vez, repositorio, ferramenta, tipo_scan)
               VALUES (?, ?, ?, ?, ?, ?)""",
            registros,
        )
        conn.commit()

        fechados, aviso = fechar_ausentes(
            conn, "org/repo", "Scanner", "sast", inicio
        )
        self.assertEqual(fechados, 0)
        self.assertIn("bloqueado", aviso)
        self.assertEqual(
            conn.execute(
                "SELECT COUNT(*) FROM findings WHERE status = 'novo'"
            ).fetchone()[0],
            20,
        )

        fechados, aviso = fechar_ausentes(
            conn, "org/repo", "Scanner", "sast", inicio, force=True
        )
        self.assertEqual((fechados, aviso), (11, None))
        self.assertEqual(
            conn.execute(
                "SELECT status FROM findings WHERE fingerprint = 'fp-fp'"
            ).fetchone()[0],
            "falso_positivo",
        )
        conn.close()

    def test_parser_detects_secrets_without_masking_raw_text(self):
        document = json.loads(json.dumps(self.document))
        result = document["runs"][0]["results"][0]
        result["message"]["text"] = "token=abcdefghijk"
        physical = result["locations"][0]["physicalLocation"]
        physical["artifactLocation"]["uri"] = "src/api_key=abcdefghijk.py"
        physical["region"]["snippet"] = {"text": "password=abcdefghijk"}

        finding = parse_sarif(document)[0]

        self.assertTrue(finding["possivel_segredo"])
        self.assertEqual(finding["extra"]["message"], "token=abcdefghijk")
        self.assertEqual(finding["path"], "src/api_key=abcdefghijk.py")
        self.assertEqual(finding["extra"]["lines"], "password=abcdefghijk")

    def test_uses_rule_default_level_when_result_has_no_severity(self):
        document = json.loads(json.dumps(self.document))
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]
        result = document["runs"][0]["results"][0]
        rule["properties"] = {}
        rule["defaultConfiguration"] = {"level": "error"}
        result["properties"] = {}
        result.pop("level", None)

        finding = parse_sarif(document)[0]

        self.assertEqual(finding["severity"], "HIGH")

    def test_result_level_overrides_rule_default_level(self):
        document = json.loads(json.dumps(self.document))
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]
        result = document["runs"][0]["results"][0]
        rule["properties"] = {}
        rule["defaultConfiguration"] = {"level": "error"}
        result["properties"] = {}
        result["level"] = "warning"

        finding = parse_sarif(document)[0]

        self.assertEqual(finding["severity"], "MEDIUM")

    def test_preserves_numeric_security_severity_from_rule_properties(self):
        document = json.loads(json.dumps(self.document))
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]
        document["runs"][0]["results"][0]["properties"] = {}
        rule["properties"] = {"security-severity": "7.5"}

        finding = parse_sarif(document)[0]

        self.assertEqual(finding["severity"], "HIGH")

    def test_missing_or_unrecognized_severity_is_unknown(self):
        document = json.loads(json.dumps(self.document))
        rule = document["runs"][0]["tool"]["driver"]["rules"][0]
        result = document["runs"][0]["results"][0]
        rule["properties"] = {}
        rule.pop("defaultConfiguration", None)
        result["properties"] = {}
        result.pop("level", None)

        self.assertEqual(parse_sarif(document)[0]["severity"], "UNKNOWN")

        result["level"] = "not-a-severity"
        self.assertEqual(parse_sarif(document)[0]["severity"], "UNKNOWN")

    def test_real_semgrep_rule_default_level_is_normalized_and_persisted(self):
        with open(SEMGREP_FIXTURE_PATH, "r", encoding="utf-8") as fixture:
            semgrep_document = json.load(fixture)

        aliases = {
            "error": "HIGH",
            "warning": "MEDIUM",
            "note": "LOW",
            "none": "INFO",
        }
        for run in semgrep_document["runs"]:
            rules = {
                rule.get("id"): rule
                for rule in run["tool"]["driver"].get("rules", [])
            }
            for result in run.get("results", []):
                rule = rules.get(result.get("ruleId"), {})
                result_properties = result.get("properties", {})
                rule_properties = rule.get("properties", {})
                result_tags = result_properties.get("tags", [])
                rule_tags = rule_properties.get("tags", [])
                has_tag_severity = any(
                    isinstance(tag, str) and tag.upper() in aliases.keys() | {
                        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"
                    }
                    for tag in [*result_tags, *rule_tags]
                )
                if (
                    not result_properties.get("security-severity")
                    and not result_properties.get("severity")
                    and not rule_properties.get("security-severity")
                    and not rule_properties.get("severity")
                    and not has_tag_severity
                    and not result.get("level")
                    and rule.get("defaultConfiguration", {}).get("level") in aliases
                ):
                    isolated_document = {
                        "version": semgrep_document["version"],
                        "runs": [
                            {
                                "tool": run["tool"],
                                "results": [result],
                            }
                        ],
                    }
                    finding = parse_sarif(isolated_document)[0]
                    self.assertEqual(
                        finding["severity"],
                        aliases[rule["defaultConfiguration"]["level"]],
                    )

                    conn = conectar(":memory:")
                    try:
                        filtrar_achados_novos([finding], conn)
                        stored_severity = conn.execute(
                            "SELECT severidade FROM findings"
                        ).fetchone()[0]
                        self.assertEqual(stored_severity, finding["severity"])
                        self.assertIn(stored_severity, {
                            "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"
                        })
                    finally:
                        conn.close()
                    return

        self.fail("SARIF Semgrep semgrep.sarif sem caso de level só em defaultConfiguration")

    def test_imports_file_into_sqlite(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "findings.db")
            total, apresentados = importar_sarif_para_banco(FIXTURE_PATH, database_path)

            self.assertEqual((total, apresentados), (1, 1))
            conn = sqlite3.connect(database_path)
            try:
                count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
                self.assertEqual(count, 1)
                self.assertEqual(
                    conn.execute(
                        "SELECT descartados FROM importacoes"
                    ).fetchone()[0],
                    0,
                )
            finally:
                conn.close()

    def test_empty_sarif_registers_repository_and_import_history(self):
        document = {"version": "2.1.0", "runs": []}
        with tempfile.TemporaryDirectory() as directory:
            sarif_path = os.path.join(directory, "empty.sarif")
            database_path = os.path.join(directory, "findings.db")
            with open(sarif_path, "w", encoding="utf-8") as sarif_file:
                json.dump(document, sarif_file)

            self.assertEqual(
                importar_sarif_para_banco(
                    sarif_path, database_path, "org/teste"
                ),
                (0, 0),
            )
            self.assertTrue(os.path.exists(database_path))
            conn = conectar(database_path)
            try:
                self.assertEqual(
                    conn.execute(
                        "SELECT repositorio, nome, tipo, exposicao, criticidade FROM ativos"
                    ).fetchone(),
                    ("org/teste", "teste", "webapp", "interna", 3),
                )
                self.assertEqual(
                    conn.execute(
                        "SELECT lidos, novos, reabertos, fechados FROM importacoes"
                    ).fetchone(),
                    (0, 0, 0, 0),
                )
            finally:
                conn.close()

    def test_import_history_tracks_new_and_reopened_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "findings.db")
            importar_sarif_para_banco(
                FIXTURE_PATH, database_path, "org/teste", "container"
            )
            conn = conectar(database_path)
            conn.execute("UPDATE findings SET status = 'corrigido'")
            conn.commit()
            conn.close()

            importar_sarif_para_banco(
                FIXTURE_PATH, database_path, "org/teste", "container"
            )
            conn = conectar(database_path)
            try:
                historico = conn.execute(
                    "SELECT repositorio, ferramenta, tipo_scan, lidos, novos, "
                    "reabertos, fechados, descartados FROM importacoes ORDER BY id"
                ).fetchall()
                self.assertEqual(
                    historico,
                    [
                        ("org/teste", "Trivy", "container", 1, 1, 0, 0, 0),
                        ("org/teste", "Trivy", "container", 1, 0, 1, 0, 0),
                    ],
                )
            finally:
                conn.close()

    def test_masks_persisted_and_returned_text_without_changing_fingerprints(self):
        finding = {
            "check_id": "test-rule",
            "path": "src/api_key=abcdefghijk.py",
            "tool_name": "TestScanner",
            "source_format": "SARIF 2.1.0",
            "extra": {
                "message": "token=abcdefghijk",
                "lines": "password=abcdefghijk",
            },
        }
        fingerprint_original = calcular_fingerprint(finding)
        conn = conectar(":memory:")
        try:
            apresentados = filtrar_achados_novos([finding], conn)
            exibido = apresentados[0]
            self.assertEqual(calcular_fingerprint(finding), fingerprint_original)
            self.assertEqual(finding["extra"]["message"], "token=abcdefghijk")
            self.assertTrue(exibido["possivel_segredo"])
            self.assertEqual(exibido["extra"]["message"], "token=[REDACTED]")
            self.assertEqual(exibido["extra"]["lines"], "password=[REDACTED]")
            self.assertEqual(exibido["path"], "src/api_key=[REDACTED]")

            stored = conn.execute(
                "SELECT fingerprint, arquivo, trecho, mensagem, possivel_segredo, "
                "fingerprint_legado FROM findings"
            ).fetchone()
            self.assertEqual(stored[0], fingerprint_original)
            self.assertNotIn("abcdefghijk", " ".join(stored[1:4]))
            self.assertEqual(stored[4], 1)
            self.assertEqual(len(stored[5]), 64)
            self.assertEqual(listar_conflitos_fingerprint(conn), [])
        finally:
            conn.close()

    def test_secret_migration_preserves_fingerprints_and_is_idempotent(self):
        secret = "abcdefghijk"
        rule = "test-rule"
        path = f"src/api_key={secret}.py"
        snippet = f"password={secret}"
        message = f"token={secret}"
        legacy = hashlib.sha256(
            f"{rule}|{mascarar_segredos(path)}|{mascarar_segredos(snippet)}".encode()
        ).hexdigest()

        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "legacy-secrets.db")
            old = sqlite3.connect(database_path)
            old.execute(
                """CREATE TABLE findings (
                    fingerprint TEXT PRIMARY KEY, regra TEXT, arquivo TEXT,
                    linha INTEGER, trecho TEXT, status TEXT,
                    primeira_vez TEXT, ultima_vez TEXT, mensagem TEXT
                )"""
            )
            old.execute(
                """INSERT INTO findings
                   (fingerprint, regra, arquivo, trecho, status, primeira_vez,
                    ultima_vez, mensagem)
                   VALUES ('primary-fingerprint', ?, ?, ?, 'confirmado',
                           'first-seen', 'last-seen', ?)""",
                (rule, path, snippet, message),
            )
            old.commit()
            old.close()

            for _ in range(2):
                conn = conectar(database_path)
                try:
                    row = conn.execute(
                        """SELECT fingerprint, fingerprint_legado, arquivo, trecho,
                                  mensagem, possivel_segredo, status, primeira_vez,
                                  ultima_vez
                           FROM findings"""
                    ).fetchone()
                    self.assertEqual(row[0], "primary-fingerprint")
                    self.assertEqual(row[1], legacy)
                    self.assertNotIn(secret, " ".join(row[2:5]))
                    self.assertEqual(
                        row[5:], (1, "confirmado", "first-seen", "last-seen")
                    )
                    self.assertEqual(listar_conflitos_fingerprint(conn), [])
                finally:
                    conn.close()

    def test_repository_scopes_fingerprints_and_is_persisted(self):
        finding = parse_sarif(self.document)[0]
        first_project = dict(finding, repositorio="org/project-one")
        second_project = dict(finding, repositorio="org/project-two")
        conn = conectar(":memory:")
        try:
            self.assertNotEqual(
                calcular_fingerprint(first_project),
                calcular_fingerprint(second_project),
            )
            self.assertEqual(
                len(filtrar_achados_novos([first_project, second_project], conn)), 2
            )
            self.assertEqual(
                conn.execute(
                    "SELECT repositorio FROM findings ORDER BY repositorio"
                ).fetchall(),
                [("org/project-one",), ("org/project-two",)],
            )
        finally:
            conn.close()

    def test_fingerprint_sem_snippet_e_estavel_quando_a_linha_muda(self):
        base = {
            "check_id": "AVD-DS-0002",
            "path": "Dockerfile",
            "tool_name": "Trivy",
            "source_format": "SARIF 2.1.0",
            "extra": {"message": "imagem base sem tag fixa"},
        }
        self.assertEqual(
            calcular_fingerprint(dict(base, start={"line": 10})),
            calcular_fingerprint(dict(base, start={"line": 42})),
        )

    def test_fingerprint_nao_depende_do_valor_bruto_do_segredo(self):
        def achado(segredo):
            return {
                "check_id": "secret-rule",
                "path": "src/config.py",
                "tool_name": "Semgrep",
                "source_format": "SARIF 2.1.0",
                "start": {"line": 3},
                "extra": {
                    "message": f"token={segredo}",
                    "lines": f"password={segredo}",
                },
            }

        self.assertEqual(
            calcular_fingerprint(achado("abcdefghijk")),
            calcular_fingerprint(achado("outrosegredo1")),
        )

    def test_rejects_unsupported_sarif_version(self):
        document = dict(self.document, version="2.0.0")
        with self.assertRaisesRegex(ValueError, "2.1.0"):
            parse_sarif(document)

    def test_skips_malformed_run_and_continues(self):
        document = dict(
            self.document,
            runs=[{"tool": {"driver": []}}, self.document["runs"][0]],
        )
        with self.assertLogs("elma.importer", level="WARNING") as captured:
            findings = parse_sarif(document)

        self.assertEqual(len(findings), 1)
        self.assertIn("run SARIF 0", captured.output[0])

    def test_skips_malformed_result_and_continues(self):
        run = json.loads(json.dumps(self.document["runs"][0]))
        run["results"][0:0] = [{"locations": "invalid"}, None]
        document = dict(self.document, runs=[run])

        with self.assertLogs("elma.importer", level="WARNING") as captured:
            findings = parse_sarif(document)

        self.assertEqual(len(findings), 1)
        self.assertEqual(len(captured.output), 2)
        self.assertIn("resultado SARIF 0 do run 0", captured.output[0])
        self.assertIn("resultado SARIF 1 do run 0", captured.output[1])

    def test_counts_ignored_runs_and_results_without_changing_parser_contract(self):
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "BrokenScanner", "rules": []}},
                    "results": [
                        {"locations": "invalid"},
                        None,
                        {
                            "ruleId": "valid-rule",
                            "level": "note",
                            "message": {"text": "ok"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/a.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        },
                    ],
                }
            ],
        }
        ignorados = {"runs": 0, "resultados": 0}
        findings = parse_sarif(document, ignorados=ignorados)

        self.assertEqual(len(findings), 1)
        self.assertEqual(ignorados["resultados"], 2)
        self.assertEqual(ignorados["runs"], 0)

        broken_run = {"version": "2.1.0", "runs": [{"tool": "x"}]}
        acounts = {"runs": 0, "resultados": 0}
        self.assertEqual(parse_sarif(broken_run, ignorados=acounts), [])
        self.assertEqual(acounts["runs"], 1)
        self.assertEqual(acounts["resultados"], 0)

    def test_importers_count_ignored_results_without_changing_return_contract(self):
        document = json.loads(json.dumps(self.document))
        document["runs"][0]["results"].extend(
            [
                {"locations": "invalid"},
                None,
                {"locations": [None]},
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            sarif_path = os.path.join(directory, "partial.sarif")
            database_path = os.path.join(directory, "findings.db")
            with open(sarif_path, "w", encoding="utf-8") as sarif_file:
                json.dump(document, sarif_file)

            import_counts = {"runs": 0, "resultados": 0}
            imported = importar_sarif_para_banco(
                sarif_path,
                database_path,
                "org/repo",
                ignorados=import_counts,
            )
            self.assertEqual(imported, (1, 1))
            self.assertEqual(import_counts, {"runs": 0, "resultados": 3})

            scoped_counts = {"runs": 0, "resultados": 0}
            scoped = carregar_sarif_com_escopo(
                sarif_path, ignorados=scoped_counts
            )
            self.assertEqual(len(scoped), 2)
            self.assertEqual(scoped_counts, {"runs": 0, "resultados": 3})
            self.assertEqual(scoped[1], set())

    def test_migrates_legacy_database_and_persists_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "legacy.db")
            legacy = sqlite3.connect(database_path)
            legacy.execute(
                """CREATE TABLE findings (
                    fingerprint TEXT PRIMARY KEY, regra TEXT, arquivo TEXT,
                    linha INTEGER, trecho TEXT, status TEXT DEFAULT 'novo',
                    primeira_vez TEXT, ultima_vez TEXT
                )"""
            )
            legacy.execute(
                """INSERT INTO findings
                   (fingerprint, regra, arquivo, status)
                   VALUES ('legacy-fingerprint', 'old-rule', 'old.py', 'confirmado')"""
            )
            legacy.commit()
            legacy.close()

            conn = conectar(database_path)
            try:
                status = conn.execute(
                    "SELECT status FROM findings WHERE fingerprint = 'legacy-fingerprint'"
                ).fetchone()[0]
                self.assertEqual(status, "confirmado")
                colunas = {
                    coluna[1] for coluna in conn.execute("PRAGMA table_info(findings)")
                }
                self.assertIn("repositorio", colunas)
                self.assertIn("tipo_scan", colunas)
                self.assertIsNone(
                    conn.execute(
                        "SELECT repositorio FROM findings "
                        "WHERE fingerprint = 'legacy-fingerprint'"
                    ).fetchone()[0]
                )

                finding = parse_sarif(self.document, "container")[0]
                filtrar_achados_novos([finding], conn)
                stored = conn.execute(
                    "SELECT ferramenta, severidade, origem, mensagem, tipo_scan "
                    "FROM findings "
                    "WHERE ferramenta = 'Trivy'"
                ).fetchone()
                self.assertEqual(
                    stored,
                    (
                        "Trivy",
                        "HIGH",
                        "SARIF 2.1.0",
                        "Specify a non-root USER in the container.",
                        "container",
                    ),
                )
                filtrar_achados_novos([parse_sarif(self.document)[0]], conn)
                self.assertEqual(
                    conn.execute(
                        "SELECT tipo_scan FROM findings WHERE ferramenta = 'Trivy'"
                    ).fetchone()[0],
                    "container",
                )
                # Import omissions must not mutate any finding status.
                filtrar_achados_novos([], conn)
                status = conn.execute(
                    "SELECT status FROM findings WHERE fingerprint = 'legacy-fingerprint'"
                ).fetchone()[0]
                self.assertEqual(status, "confirmado")
            finally:
                conn.close()

    def test_backfills_legacy_severities_without_changing_triage(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "legacy-severity.db")
            legacy = sqlite3.connect(database_path)
            legacy.execute(
                "CREATE TABLE findings (fingerprint TEXT PRIMARY KEY, status TEXT, severidade TEXT)"
            )
            legacy.executemany(
                "INSERT INTO findings VALUES (?, ?, ?)",
                [
                    ("error", "confirmado", "error"),
                    ("warning", "falso_positivo", "warning"),
                    ("score", "corrigido", "7.5"),
                    ("missing", "novo", None),
                    ("invalid", "confirmado", "unrecognized"),
                ],
            )
            legacy.commit()
            legacy.close()

            conn = conectar(database_path)
            try:
                rows = conn.execute(
                    "SELECT fingerprint, status, severidade FROM findings ORDER BY fingerprint"
                ).fetchall()
                self.assertEqual(
                    rows,
                    [
                        ("error", "confirmado", "HIGH"),
                        ("invalid", "confirmado", "UNKNOWN"),
                        ("missing", "novo", "UNKNOWN"),
                        ("score", "corrigido", "HIGH"),
                        ("warning", "falso_positivo", "MEDIUM"),
                    ],
                )
            finally:
                conn.close()

    def test_sarif_reuses_legacy_fingerprint_and_preserves_triage(self):
        finding = parse_sarif(self.document)[0]
        legacy_base = (
            f"{finding['check_id']}|{finding['path']}|"
            f"{finding['extra']['lines']}"
        )
        legacy_fingerprint = hashlib.sha256(legacy_base.encode("utf-8")).hexdigest()

        for initial_status in ("novo", "confirmado", "falso_positivo", "corrigido"):
            with self.subTest(status=initial_status):
                conn = conectar(":memory:")
                try:
                    conn.execute(
                        """INSERT INTO findings
                           (fingerprint, regra, arquivo, linha, trecho, status,
                            primeira_vez, ultima_vez)
                           VALUES (?, ?, ?, ?, ?, ?, 'first-seen-original', 'old-seen')""",
                        (
                            legacy_fingerprint,
                            finding["check_id"],
                            finding["path"],
                            finding["start"]["line"],
                            finding["extra"]["lines"],
                            initial_status,
                        ),
                    )
                    apresentados = filtrar_achados_novos([finding], conn)
                    row = conn.execute(
                        """SELECT fingerprint, status, primeira_vez, ferramenta,
                                  severidade, origem, mensagem
                           FROM findings"""
                    ).fetchone()

                    self.assertEqual(
                        len(apresentados), 0 if initial_status == "falso_positivo" else 1
                    )
                    self.assertEqual(
                        (row[0], row[1], row[3], row[4], row[5], row[6]),
                        (
                            legacy_fingerprint,
                            "novo" if initial_status == "corrigido" else initial_status,
                            "Trivy",
                            "HIGH",
                            "SARIF 2.1.0",
                            "Specify a non-root USER in the container.",
                        ),
                    )
                    if initial_status == "corrigido":
                        # Fix C: reabrir por regressão zera o relógio de SLA.
                        self.assertNotEqual(row[2], "first-seen-original")
                    else:
                        self.assertEqual(row[2], "first-seen-original")
                    self.assertEqual(
                        conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 1
                    )

                    primeira_vez_esperada = row[2]
                    filtrar_achados_novos([finding], conn)
                    self.assertEqual(
                        conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 1
                    )
                    self.assertEqual(
                        conn.execute(
                            "SELECT primeira_vez FROM findings WHERE fingerprint = ?",
                            (legacy_fingerprint,),
                        ).fetchone()[0],
                        primeira_vez_esperada,
                    )
                finally:
                    conn.close()

    def test_existing_legacy_and_current_keys_raise_without_mutating_rows(self):
        finding = parse_sarif(self.document)[0]
        legacy_base = (
            f"{finding['check_id']}|{finding['path']}|"
            f"{finding['extra']['lines']}"
        )
        legacy_fingerprint = hashlib.sha256(legacy_base.encode("utf-8")).hexdigest()
        current_fingerprint = calcular_fingerprint(finding)
        conn = conectar(":memory:")
        try:
            for fingerprint, status in (
                (legacy_fingerprint, "falso_positivo"),
                (current_fingerprint, "novo"),
            ):
                conn.execute(
                    """INSERT INTO findings
                       (fingerprint, regra, arquivo, linha, trecho, status,
                                ferramenta, severidade, origem, mensagem, fingerprint_legado)
                              VALUES (?, ?, ?, ?, ?, ?, 'Trivy', 'HIGH', 'SARIF 2.1.0', ?, ?)""",
                    (
                        fingerprint,
                        finding["check_id"],
                        finding["path"],
                        finding["start"]["line"],
                        finding["extra"]["lines"],
                        status,
                        finding["extra"]["message"],
                        legacy_fingerprint,
                    ),
                )
            conn.commit()

            outro_achado = dict(finding, path="OtherDockerfile")
            with self.assertRaisesRegex(FingerprintConflictError, "Conflito de fingerprints") as captured:
                filtrar_achados_novos([outro_achado, finding], conn)

            self.assertIn(legacy_fingerprint, str(captured.exception))
            self.assertIn(current_fingerprint, str(captured.exception))
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 2
            )
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM findings WHERE fingerprint = ?",
                    (legacy_fingerprint,),
                ).fetchone()[0],
                "falso_positivo",
            )
            self.assertEqual(len(listar_conflitos_fingerprint(conn)), 1)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()