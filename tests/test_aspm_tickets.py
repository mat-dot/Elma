import json
import os
import sqlite3
import tempfile
import threading
import unittest

from elma.db import conectar, listar_achados, migrar, obter_achado
from elma.db import MIGRACAO_RESERVA_TICKETS, MIGRACAO_TICKETS
from elma.tickets import (
    ConfigTickets,
    GitHubAPIError,
    carregar_config,
    criar_issue,
    criar_issue_confirmado,
    deve_criar_issue,
    fechar_issue,
    montar_corpo_issue,
    reabrir_issue,
    sincronizar_issues_apos_ingestao,
)


class TicketTests(unittest.TestCase):
    def setUp(self):
        self.conn = conectar(":memory:")
        self.fingerprint = "a" * 64
        self.conn.execute(
            """INSERT INTO findings
               (fingerprint, status, repositorio, regra, arquivo, linha, trecho,
                mensagem, severidade, possivel_segredo, tipo_scan, issue_tentativas)
               VALUES (?, 'confirmado', 'org/repo', 'test-rule', 'src/app.py', 12,
                       'masked snippet', 'masked message', 'CRITICAL', 0, 'sast', 0)""",
            (self.fingerprint,),
        )
        self.conn.commit()
        self.finding = {
            "fingerprint": self.fingerprint,
            "status": "confirmado",
            "repositorio": "org/repo",
            "regra": "test-rule",
            "arquivo": "src/app.py",
            "linha": 12,
            "trecho": "masked snippet",
            "mensagem": "masked message",
            "severidade": "CRITICAL",
            "possivel_segredo": 0,
            "tipo_scan": "sast",
        }
        self.ativo = {"nome": "repo"}
        self.config = ConfigTickets(
            ativo=True,
            dry_run=False,
            token="test-github-token",
            dashboard_url="https://elma.example/painel",
        )

    def tearDown(self):
        self.conn.close()

    def test_ticket_config_is_off_and_dry_run_by_default(self):
        config = carregar_config({})

        self.assertFalse(config.ativo)
        self.assertTrue(config.dry_run)
        self.assertIsNone(config.token)

    def test_creation_policy_requires_confirmation_repository_and_activation(self):
        self.assertTrue(deve_criar_issue(self.finding, self.config))
        self.assertFalse(
            deve_criar_issue(
                self.finding | {"severidade": "HIGH"}, self.config
            )
        )
        self.assertFalse(
            deve_criar_issue(
                self.finding | {"status": "novo"}, self.config
            )
        )
        self.assertFalse(
            deve_criar_issue(
                self.finding | {"repositorio": "https://github.com/org/repo"},
                self.config,
            )
        )
        self.assertFalse(
            deve_criar_issue(
                self.finding,
                ConfigTickets(ativo=False, dry_run=True),
            )
        )
        self.assertFalse(
            deve_criar_issue(
                self.finding,
                ConfigTickets(ativo=True, dry_run=False, token=None),
            )
        )

    def test_issue_body_neutralizes_untrusted_scanner_content(self):
        finding = self.finding | {
            "regra": "@alice <img src=x> [click](https://attacker.example)",
            "arquivo": "src/@bob/<script>.py",
            "mensagem": "<script>alert(1)</script> https://attacker.example @team",
            "trecho": "``` @everyone",
        }

        title, body = montar_corpo_issue(
            finding, self.ativo, "https://elma.example"
        )

        self.assertNotIn("@alice", title)
        self.assertNotIn("@bob", title)
        self.assertNotIn("attacker.example", title + body)
        self.assertNotIn("<script>", title + body)
        self.assertIn("[at]", title + body)
        self.assertIn("https://elma.example/painel", body)
        self.assertIn(self.fingerprint, body)
        self.assertIn("src/", body)

    def test_secret_issue_includes_context_with_secret_values_redacted(self):
        finding = self.finding | {
            "possivel_segredo": 1,
            "regra": "secret-rule",
            "arquivo": "private/secret.py",
            "linha": 99,
            "mensagem": "token=top-secret-value",
            "trecho": "password=top-secret-value",
            "ferramenta": "Trivy",
            "remediacao_ia": "Revogue token=top-secret-value e use um secret manager.",
        }

        title, body = montar_corpo_issue(finding, self.ativo)

        self.assertIn("Possível segredo", title)
        self.assertNotIn("top-secret-value", title + body)
        self.assertIn("secret-rule", body)
        self.assertIn("private/secret.py:99", body)
        self.assertIn("Trivy", body)
        self.assertIn("token=[REDACTED]", body)
        self.assertIn("password=[REDACTED]", body)
        self.assertIn("gerada por IA", body)
        self.assertIn("secret manager", body)
        self.assertIn(self.fingerprint, body)
        self.assertIn("CRITICAL", body)

    def test_secrets_scan_is_redacted_even_when_secret_flag_is_false(self):
        finding = self.finding | {
            "tipo_scan": "secrets",
            "possivel_segredo": 0,
            "regra": "aws-access-key-id",
            "arquivo": "config/prod.env",
            "linha": 27,
            "mensagem": "AWS access key found in configuration file",
            "trecho": "AKIA[REDACTED]",
        }

        title, body = montar_corpo_issue(finding, self.ativo)

        self.assertIn("Possível segredo", title)
        self.assertIn("aws-access-key-id", body)
        self.assertIn("config/prod.env:27", body)
        self.assertIn("AWS access key found", body)
        self.assertIn("AKIA[REDACTED]", body)
        self.assertIn(self.fingerprint, body)

    def test_issue_body_includes_ai_remediation_as_sanitized_code_block(self):
        finding = self.finding | {
            "remediacao_ia": "Rode ```curl https://attacker.example``` e avise @oncall.",
        }

        title, body = montar_corpo_issue(finding, self.ativo, "https://elma.example")

        self.assertIn("gerada por IA", body)
        self.assertNotIn("https://attacker.example", body)
        self.assertNotIn("@oncall", body)
        self.assertIn("[link removido]", body)
        self.assertIn("[at]oncall", body)
        # A seção vem depois da mensagem do scanner e antes do link do painel.
        self.assertLess(body.index("Mensagem do scanner"), body.index("gerada por IA"))
        self.assertLess(body.index("gerada por IA"), body.index("/painel"))

    def test_issue_body_without_remediation_has_no_ai_section(self):
        title, body = montar_corpo_issue(self.finding, self.ativo)

        self.assertNotIn("gerada por IA", body)

    def test_secret_issue_includes_sanitized_ai_remediation(self):
        finding = self.finding | {
            "possivel_segredo": 1,
            "remediacao_ia": "Gire token=top-secret-value imediatamente.",
        }

        title, body = montar_corpo_issue(finding, self.ativo)

        self.assertIn("Possível segredo", title)
        self.assertIn("gerada por IA", body)
        self.assertIn("Gire token=[REDACTED]", body)
        self.assertNotIn("top-secret-value", body)

    def test_secrets_scan_type_includes_sanitized_ai_remediation(self):
        finding = self.finding | {
            "tipo_scan": "secrets",
            "possivel_segredo": 0,
            "remediacao_ia": "Gire o token imediatamente.",
        }

        title, body = montar_corpo_issue(finding, self.ativo)

        self.assertIn("Possível segredo", title)
        self.assertIn("gerada por IA", body)
        self.assertIn("Gire o token", body)

    def test_dry_run_preview_carries_persisted_remediation(self):
        self.conn.execute(
            "UPDATE findings SET remediacao_ia = ? WHERE fingerprint = ?",
            ("Troque a senha hardcoded por um secret gerenciado.", self.fingerprint),
        )
        self.conn.commit()
        config = ConfigTickets(
            ativo=True,
            dry_run=True,
            dashboard_url="https://elma.example/painel",
        )

        result = criar_issue(self.finding, self.ativo, self.conn, config)

        self.assertIn("gerada por IA", result["corpo"])
        self.assertIn("secret gerenciado", result["corpo"])

    def test_secret_dry_run_preview_includes_context_and_persisted_remediation(self):
        self.conn.execute(
            """UPDATE findings SET possivel_segredo = 1, tipo_scan = 'secrets',
               ferramenta = 'Trivy', regra = 'aws-access-key-id',
               arquivo = 'config/prod.env', linha = 27,
               mensagem = 'AWS access key found', trecho = 'AKIA[REDACTED]',
               remediacao_ia = ? WHERE fingerprint = ?""",
            ("Revogue a chave e use um secret manager.", self.fingerprint),
        )
        self.conn.commit()
        config = ConfigTickets(
            ativo=True,
            dry_run=True,
            dashboard_url="https://elma.example/painel",
        )

        result = criar_issue(self.finding, self.ativo, self.conn, config)

        body = result["corpo"]
        self.assertTrue(result["dry_run"])
        self.assertIn("Trivy", body)
        self.assertIn("aws-access-key-id", body)
        self.assertIn("config/prod.env:27", body)
        self.assertIn("AWS access key found", body)
        self.assertIn("AKIA[REDACTED]", body)
        self.assertIn("Revogue a chave", body)

    def test_dry_run_returns_preview_without_transport_or_database_write(self):
        calls = []
        config = ConfigTickets(
            ativo=True,
            dry_run=True,
            dashboard_url="https://elma.example/painel",
        )
        result = criar_issue(
            self.finding,
            self.ativo,
            self.conn,
            config,
            transport=lambda *args: calls.append(args),
        )

        self.assertTrue(result["dry_run"])
        self.assertEqual(calls, [])
        row = self.conn.execute(
            "SELECT issue_numero, issue_tentativas FROM findings"
        ).fetchone()
        self.assertEqual(row, (None, 0))

    def test_create_issue_uses_fingerprint_marker_and_persists_link(self):
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append((method, url, headers, body))
            if method == "GET":
                return 200, [], {}
            payload = json.loads(body)
            self.assertIn(self.fingerprint, payload["body"])
            return 201, {
                "number": 17,
                "html_url": "https://github.com/org/repo/issues/17",
            }, {}

        result = criar_issue(
            self.finding, self.ativo, self.conn, self.config, transport
        )

        self.assertTrue(result["criada"])
        self.assertEqual([call[0] for call in calls], ["GET", "POST"])
        row = self.conn.execute(
            "SELECT issue_url, issue_numero, issue_estado, issue_erro, "
            "issue_tentativas FROM findings"
        ).fetchone()
        self.assertEqual(
            row,
            ("https://github.com/org/repo/issues/17", 17, "aberta", None, 1),
        )

    def test_create_issue_uses_persisted_masked_finding_not_caller_text(self):
        finding_cru = self.finding | {
            "mensagem": "token=raw-unmasked-secret",
            "arquivo": "raw-unmasked-path.py",
        }
        payloads = []

        def transport(method, url, headers, body, timeout):
            if method == "GET":
                return 200, [], {}
            payloads.append(json.loads(body))
            return 201, {
                "number": 18,
                "html_url": "https://github.com/org/repo/issues/18",
            }, {}

        result = criar_issue(
            finding_cru, self.ativo, self.conn, self.config, transport
        )

        self.assertTrue(result["criada"])
        self.assertIn("masked message", payloads[0]["body"])
        self.assertNotIn("raw-unmasked-secret", payloads[0]["body"])
        self.assertNotIn("raw-unmasked-path.py", payloads[0]["body"])

    def test_create_reconciles_existing_fingerprint_without_duplicate_post(self):
        marker = f"<!-- elma-fingerprint:{self.fingerprint} -->"
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append(method)
            return 200, [
                {
                    "number": 4,
                    "html_url": "https://github.com/org/repo/issues/4",
                    "state": "open",
                    "body": marker,
                }
            ], {}

        result = criar_issue(
            self.finding, self.ativo, self.conn, self.config, transport
        )

        self.assertTrue(result["reconciliada"])
        self.assertFalse(result["reaberta"])
        self.assertEqual(calls, ["GET"])
        self.assertEqual(
            self.conn.execute(
                "SELECT issue_numero, issue_estado, issue_tentativas FROM findings"
            ).fetchone(),
            (4, "aberta", 0),
        )

    def test_reconfirmation_updates_legacy_secret_issue_with_safe_details(self):
        marker = f"<!-- elma-fingerprint:{self.fingerprint} -->"
        legacy_body = (
            "A Elma detectou um finding potencialmente sensível. "
            "Detalhes do scanner foram omitidos por segurança.\n\n"
            f"- Fingerprint: `{self.fingerprint}`\n- Severidade: CRITICAL\n\n{marker}"
        )
        self.conn.execute(
            """UPDATE findings SET status = 'confirmado', repositorio = 'org/repo',
               possivel_segredo = 1, tipo_scan = 'secrets', ferramenta = 'Trivy',
               regra = 'aws-access-key-id', arquivo = 'config/prod.env', linha = 27,
               mensagem = 'AWS key token=top-secret-value', trecho = 'AKIA[REDACTED]',
               remediacao_ia = 'Revogue a chave e use um secret manager.',
               issue_url = 'https://github.com/org/repo/issues/4', issue_numero = 4,
               issue_estado = 'aberta' WHERE fingerprint = ?""",
            (self.fingerprint,),
        )
        self.conn.commit()
        patches = []

        def transport(method, url, headers, body, timeout):
            if method == "GET":
                return 200, [{
                    "number": 4,
                    "html_url": "https://github.com/org/repo/issues/4",
                    "state": "open",
                    "title": "Possível segredo detectado (CRITICAL)",
                    "body": legacy_body,
                }], {}
            patches.append(json.loads(body))
            return 200, {
                "number": 4,
                "html_url": "https://github.com/org/repo/issues/4",
                "state": "open",
            }, {}

        result = criar_issue(
            self.finding, self.ativo, self.conn, self.config, transport
        )

        self.assertTrue(result["reconciliada"])
        self.assertTrue(result["atualizada"])
        self.assertEqual(len(patches), 1)
        self.assertIn("aws-access-key-id", patches[0]["body"])
        self.assertIn("config/prod.env:27", patches[0]["body"])
        self.assertIn("secret manager", patches[0]["body"])
        self.assertNotIn("top-secret-value", patches[0]["body"])
        self.assertIn(marker, patches[0]["body"])

    def test_reconciling_closed_issue_reopens_it_instead_of_creating_another(self):
        marker = f"<!-- elma-fingerprint:{self.fingerprint} -->"
        calls = []
        patches = []

        def transport(method, url, headers, body, timeout):
            calls.append(method)
            if method == "GET":
                return 200, [
                    {
                        "number": 4,
                        "html_url": "https://github.com/org/repo/issues/4",
                        "state": "closed",
                        "body": marker,
                    }
                ], {}
            patches.append(json.loads(body))
            return 200, {
                "number": 4,
                "html_url": "https://github.com/org/repo/issues/4",
                "state": "open",
            }, {}

        result = criar_issue(
            self.finding, self.ativo, self.conn, self.config, transport
        )

        self.assertTrue(result["reconciliada"])
        self.assertTrue(result["reaberta"])
        self.assertEqual(result["issue_estado"], "aberta")
        # Nenhuma issue nova: só a busca e o PATCH de reabertura.
        self.assertEqual(calls, ["GET", "PATCH"])
        self.assertEqual(patches, [{"state": "open"}])
        self.assertEqual(
            self.conn.execute(
                "SELECT issue_numero, issue_estado, issue_tentativas FROM findings"
            ).fetchone(),
            (4, "aberta", 0),
        )

    def test_manual_reconfirmation_reopens_locally_closed_issue(self):
        self.conn.execute(
            """UPDATE findings SET issue_url = ?, issue_numero = 4,
               issue_estado = 'fechada'""",
            ("https://github.com/org/repo/issues/4",),
        )
        self.conn.commit()
        marker = f"<!-- elma-fingerprint:{self.fingerprint} -->"
        calls = []

        def transport(method, url, headers, body, timeout):
            calls.append(method)
            if method == "GET":
                return 200, [
                    {
                        "number": 4,
                        "html_url": "https://github.com/org/repo/issues/4",
                        "state": "closed",
                        "body": marker,
                    }
                ], {}
            return 200, {
                "number": 4,
                "html_url": "https://github.com/org/repo/issues/4",
                "state": "open",
            }, {}

        result = criar_issue_confirmado(
            self.fingerprint, self.conn, self.config, transport
        )

        self.assertTrue(result["reaberta"])
        self.assertEqual(calls, ["GET", "PATCH"])
        self.assertEqual(
            self.conn.execute(
                "SELECT issue_numero, issue_estado FROM findings"
            ).fetchone(),
            (4, "aberta"),
        )

    def test_reopen_failure_during_reconciliation_persists_sanitized_error(self):
        marker = f"<!-- elma-fingerprint:{self.fingerprint} -->"

        def transport(method, url, headers, body, timeout):
            if method == "GET":
                return 200, [
                    {
                        "number": 4,
                        "html_url": "https://github.com/org/repo/issues/4",
                        "state": "closed",
                        "body": marker,
                    }
                ], {}
            return 403, {"message": "forbidden"}, {}

        result = criar_issue(
            self.finding, self.ativo, self.conn, self.config, transport
        )

        self.assertFalse(result.get("criada"))
        self.assertIn("403", result["erro"])
        row = self.conn.execute(
            "SELECT issue_url, issue_numero, issue_erro, issue_tentativas, "
            "issue_reservado_em FROM findings"
        ).fetchone()
        self.assertEqual(row[0], None)
        self.assertEqual(row[1], None)
        self.assertIn("403", row[2])
        self.assertEqual(row[3], 1)
        self.assertIsNone(row[4])

    def test_close_and_reopen_update_remote_and_local_state(self):
        self.conn.execute(
            """UPDATE findings SET issue_url = ?, issue_numero = 17,
               issue_estado = 'aberta'""",
            ("https://github.com/org/repo/issues/17",),
        )
        self.conn.commit()
        states = []

        def transport(method, url, headers, body, timeout):
            state = json.loads(body)["state"]
            states.append(state)
            return 200, {
                "number": 17,
                "html_url": "https://github.com/org/repo/issues/17",
            }, {}

        closed = fechar_issue(self.fingerprint, self.conn, self.config, transport)
        reopened = reabrir_issue(self.fingerprint, self.conn, self.config, transport)

        self.assertTrue(closed["atualizada"])
        self.assertTrue(reopened["atualizada"])
        self.assertEqual(states, ["closed", "open"])
        self.assertEqual(
            self.conn.execute(
                "SELECT issue_estado, issue_tentativas FROM findings"
            ).fetchone(),
            ("aberta", 2),
        )

    def test_api_failure_persists_sanitized_error_and_attempt(self):
        def transport(method, url, headers, body, timeout):
            if method == "GET":
                return 200, [], {}
            raise GitHubAPIError(403)

        result = criar_issue(
            self.finding, self.ativo, self.conn, self.config, transport
        )

        self.assertFalse(result["criada"])
        error, attempts = self.conn.execute(
            "SELECT issue_erro, issue_tentativas FROM findings"
        ).fetchone()
        self.assertEqual(error, "GitHub API retornou HTTP 403")
        self.assertEqual(attempts, 1)
        self.assertNotIn(self.config.token, error)

    def test_reconciliation_read_error_does_not_count_as_mutation(self):
        def transport(method, url, headers, body, timeout):
            raise GitHubAPIError(503)

        result = criar_issue(
            self.finding, self.ativo, self.conn, self.config, transport
        )

        self.assertFalse(result["criada"])
        self.assertEqual(
            self.conn.execute(
                "SELECT issue_tentativas FROM findings"
            ).fetchone()[0],
            0,
        )
        self.assertEqual(
            self.conn.execute("SELECT issue_erro FROM findings").fetchone()[0],
            "GitHub API retornou HTTP 503",
        )

    def test_concurrent_create_reservation_prevents_duplicate_post(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "tickets.db")
            setup = conectar(database_path)
            setup.execute(
                """INSERT INTO findings
                   (fingerprint, status, repositorio, regra, arquivo, mensagem,
                    severidade, possivel_segredo, tipo_scan)
                   VALUES (?, 'confirmado', 'org/repo', 'rule', 'app.py',
                           'message', 'CRITICAL', 0, 'sast')""",
                (self.fingerprint,),
            )
            setup.commit()
            setup.close()

            get_started = threading.Event()
            release_get = threading.Event()
            calls = []
            calls_lock = threading.Lock()

            def transport(method, url, headers, body, timeout):
                with calls_lock:
                    calls.append(method)
                if method == "GET":
                    get_started.set()
                    if not release_get.wait(timeout=3):
                        raise TimeoutError("test transport timeout")
                    return 200, [], {}
                return 201, {
                    "number": 31,
                    "html_url": "https://github.com/org/repo/issues/31",
                }, {}

            first_result = {}

            def first_create():
                conn = conectar(database_path)
                try:
                    first_result.update(
                        criar_issue(
                            self.finding,
                            self.ativo,
                            conn,
                            self.config,
                            transport,
                        )
                    )
                finally:
                    conn.close()

            worker = threading.Thread(target=first_create)
            worker.start()
            self.assertTrue(get_started.wait(timeout=3))
            second_conn = conectar(database_path)
            try:
                second_result = criar_issue(
                    self.finding,
                    self.ativo,
                    second_conn,
                    self.config,
                    transport,
                )
            finally:
                second_conn.close()
            release_get.set()
            worker.join(timeout=3)

            self.assertFalse(worker.is_alive())
            self.assertTrue(first_result["criada"])
            self.assertTrue(second_result["em_andamento"])
            self.assertEqual(calls, ["GET", "POST"])
            verify = conectar(database_path)
            try:
                self.assertEqual(
                    verify.execute(
                        "SELECT issue_numero, issue_tentativas "
                        "FROM findings WHERE fingerprint = ?",
                        (self.fingerprint,),
                    ).fetchone(),
                    (31, 1),
                )
            finally:
                verify.close()

    def test_expired_creation_reservation_can_be_reclaimed(self):
        self.conn.execute(
            "UPDATE findings SET issue_erro = 'criando', "
            "issue_reservado_em = '2000-01-01T00:00:00+00:00'"
        )
        self.conn.commit()

        def transport(method, url, headers, body, timeout):
            if method == "GET":
                return 200, [], {}
            return 201, {
                "number": 32,
                "html_url": "https://github.com/org/repo/issues/32",
            }, {}

        result = criar_issue(
            self.finding, self.ativo, self.conn, self.config, transport
        )

        self.assertTrue(result["criada"])
        self.assertEqual(
            self.conn.execute(
                "SELECT issue_reservado_em FROM findings"
            ).fetchone()[0],
            None,
        )

    def test_migration_eight_adds_ticket_columns_and_constraints(self):
        columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(findings)")
        }
        self.assertTrue(
            {
                "issue_url",
                "issue_numero",
                "issue_estado",
                "issue_erro",
                "issue_tentativas",
                "issue_reservado_em",
            }.issubset(columns)
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM elma_schema_migrations WHERE version = ?",
                (MIGRACAO_TICKETS,),
            ).fetchone()[0],
            1,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE findings SET issue_estado = 'open' WHERE fingerprint = ?",
                (self.fingerprint,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "UPDATE findings SET issue_tentativas = -1 WHERE fingerprint = ?",
                (self.fingerprint,),
            )

    def test_migration_eight_upgrades_version_seven_database_idempotently(self):
        self.conn.execute("DROP INDEX idx_findings_github_issue")
        for column in (
            "issue_reservado_em",
            "issue_tentativas",
            "issue_erro",
            "issue_estado",
            "issue_numero",
            "issue_url",
        ):
            self.conn.execute(f"ALTER TABLE findings DROP COLUMN {column}")
        self.conn.execute(
            "DELETE FROM elma_schema_migrations WHERE version IN (?, ?)",
            (MIGRACAO_TICKETS, MIGRACAO_RESERVA_TICKETS),
        )
        self.conn.commit()

        migrar(self.conn)
        migrar(self.conn)

        columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(findings)")
        }
        self.assertTrue(
            {
                "issue_url",
                "issue_numero",
                "issue_estado",
                "issue_erro",
                "issue_tentativas",
                "issue_reservado_em",
            }.issubset(columns)
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM elma_schema_migrations WHERE version = ?",
                (MIGRACAO_TICKETS,),
            ).fetchone()[0],
            1,
        )
        self.assertEqual(
            self.conn.execute(
                "SELECT COUNT(*) FROM elma_schema_migrations WHERE version = ?",
                (MIGRACAO_RESERVA_TICKETS,),
            ).fetchone()[0],
            1,
        )

    def test_finding_queries_include_ticket_state(self):
        for finding in (obter_achado(self.fingerprint, self.conn), listar_achados(self.conn)[0]):
            self.assertIn("issue_url", finding)
            self.assertIn("issue_numero", finding)
            self.assertEqual(finding["issue_tentativas"], 0)

    def test_issue_number_is_unique_within_repository(self):
        self.conn.execute(
            "UPDATE findings SET issue_url = ?, issue_numero = 17, "
            "issue_estado = 'aberta' WHERE fingerprint = ?",
            ("https://github.com/org/repo/issues/17", self.fingerprint),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                """INSERT INTO findings
                   (fingerprint, status, repositorio, issue_numero)
                   VALUES (?, 'confirmado', 'org/repo', 17)""",
                ("b" * 64,),
            )

    def test_sincronizar_issues_is_noop_when_tickets_disabled(self):
        calls = []
        config = ConfigTickets(ativo=False, dry_run=False, token="test-github-token")

        result = sincronizar_issues_apos_ingestao(
            self.conn,
            [self.fingerprint],
            ["b" * 64],
            config,
            transport=lambda *args: calls.append(args),
        )

        self.assertEqual(result, {"reabertas": 0, "fechadas": 0})
        self.assertEqual(calls, [])

    def test_sincronizar_issues_reopens_and_closes_linked_issues(self):
        reopened_fp = "b" * 64
        self.conn.execute(
            "UPDATE findings SET issue_url = ?, issue_numero = 17, "
            "issue_estado = 'aberta' WHERE fingerprint = ?",
            ("https://github.com/org/repo/issues/17", self.fingerprint),
        )
        self.conn.execute(
            """INSERT INTO findings
               (fingerprint, status, repositorio, regra, arquivo, mensagem,
                severidade, possivel_segredo, tipo_scan, issue_url, issue_numero,
                issue_estado)
               VALUES (?, 'corrigido', 'org/repo', 'r', 'a.py', 'm', 'HIGH', 0,
                       'sast', ?, 18, 'fechada')""",
            (reopened_fp, "https://github.com/org/repo/issues/18"),
        )
        self.conn.commit()
        states = []

        def transport(method, url, headers, body, timeout):
            state = json.loads(body)["state"]
            numero = 17 if state == "closed" else 18
            states.append((numero, state))
            return 200, {
                "number": numero,
                "html_url": f"https://github.com/org/repo/issues/{numero}",
            }, {}

        result = sincronizar_issues_apos_ingestao(
            self.conn,
            [reopened_fp],
            [self.fingerprint],
            self.config,
            transport,
        )

        self.assertEqual(result, {"reabertas": 1, "fechadas": 1})
        self.assertEqual(sorted(states), [(17, "closed"), (18, "open")])


if __name__ == "__main__":
    unittest.main()
