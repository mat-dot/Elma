import asyncio
import contextlib
import io
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from elma import api as elma_api
from elma.cli import main as cli_main
from elma.db import calcular_fingerprint, conectar, registrar_importacao
from elma.importer import parse_sarif


def _document(level="warning", execution_successful=None):
    results = []
    if level is not None:
        results.append(
            {
                "ruleId": "test-rule",
                "level": level,
                "message": {"text": "test finding"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/test.py"},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )
    run = {
        "tool": {"driver": {"name": "TestScanner", "rules": []}},
        "results": results,
    }
    if execution_successful is not None:
        run["invocations"] = [
            {"executionSuccessful": execution_successful}
        ]
    return {
        "version": "2.1.0",
        "runs": [run],
    }


class FakeRequest:
    def __init__(self, body, content_length=None):
        self.body = body
        self.headers = {}
        if content_length is not None:
            self.headers["content-length"] = str(content_length)
        self.stream_started = False

    async def stream(self):
        self.stream_started = True
        yield self.body


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.tempdir.name, "findings.db")
        self.environment = patch.dict(
            os.environ,
            {"ELMA_API_KEY": "test-secret", "ELMA_DB_PATH": self.database},
            clear=False,
        )
        self.environment.start()
        self.database_path = patch.object(elma_api, "CAMINHO_BANCO", self.database)
        self.database_path.start()

    def tearDown(self):
        self.database_path.stop()
        self.environment.stop()
        self.tempdir.cleanup()

    def _post(self, body, content_length=None, authorization="Bearer test-secret"):
        request = FakeRequest(body, content_length)
        response = asyncio.run(
            elma_api.receber_findings(request, authorization=authorization)
        )
        return request, response

    def test_authentication_happens_before_reading_body(self):
        request = FakeRequest(b"{}")

        with self.assertRaises(HTTPException) as captured:
            asyncio.run(elma_api.receber_findings(request, authorization=None))

        self.assertEqual(captured.exception.status_code, 401)
        self.assertFalse(request.stream_started)

    def test_rejects_declared_oversized_body_before_reading(self):
        request = FakeRequest(b"{}", elma_api.TAMANHO_MAXIMO_SARIF + 1)

        with self.assertRaises(HTTPException) as captured:
            asyncio.run(
                elma_api.receber_findings(
                    request,
                    authorization="Bearer test-secret",
                )
            )

        self.assertEqual(captured.exception.status_code, 413)
        self.assertFalse(request.stream_started)

    def test_enforces_limit_when_content_length_is_missing(self):
        request = FakeRequest(b"x" * 5)
        with patch.object(elma_api, "TAMANHO_MAXIMO_SARIF", 4):
            with self.assertRaises(HTTPException) as captured:
                asyncio.run(
                    elma_api.receber_findings(
                        request,
                        authorization="Bearer test-secret",
                    )
                )

        self.assertEqual(captured.exception.status_code, 413)

    def test_pass_and_fail_return_200_with_gate_result_in_body(self):
        body = json.dumps({"sarif": _document("warning")}).encode()
        _, passed = self._post(body, len(body))
        self.assertIsInstance(passed, JSONResponse)
        self.assertEqual(passed.status_code, 200)
        passed_result = json.loads(passed.body)
        self.assertTrue(passed_result["aprovado"])
        self.assertEqual(passed_result["novos"], 1)

        body = json.dumps({"sarif": _document("error")}).encode()
        _, failed = self._post(body, len(body))
        self.assertEqual(failed.status_code, 200)
        result = json.loads(failed.body)
        self.assertFalse(result["aprovado"])
        self.assertEqual(result["bloqueadores"], 1)
        self.assertEqual(result["detalhes_bloqueadores"][0]["severidade"], "HIGH")
        self.assertEqual(result["novos"], 0)
        conn = conectar(self.database)
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM importacoes").fetchone()[0],
                2,
            )
        finally:
            conn.close()

    def test_malformed_sarif_is_reported_and_blocks_gate(self):
        document = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "BrokenScanner", "rules": []}},
                    "results": [
                        {"locations": "invalid"},
                        None,
                        {"message": {"text": "ok"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 1}}}]},
                    ],
                }
            ],
        }
        body = json.dumps({"sarif": document}).encode()
        _, response = self._post(body, len(body))
        result = json.loads(response.body)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(result["aprovado"])
        self.assertEqual(result["resultados_ignorados"], 2)
        self.assertIn("sarif_malformado", result["motivo_reprovacao"])
        conn = conectar(self.database)
        try:
            self.assertEqual(
                conn.execute(
                    "SELECT descartados FROM importacoes"
                ).fetchone()[0],
                2,
            )
        finally:
            conn.close()

    def test_repository_scopes_identical_findings(self):
        for repository in ("org/project-one", "org/project-two"):
            body = json.dumps(
                {"sarif": _document(), "repositorio": repository}
            ).encode()
            _, response = self._post(body, len(body))
            self.assertEqual(response.status_code, 200)

        import sqlite3

        conn = sqlite3.connect(self.database)
        try:
            self.assertEqual(
                conn.execute(
                    "SELECT repositorio FROM findings ORDER BY repositorio"
                ).fetchall(),
                [("org/project-one",), ("org/project-two",)],
            )
        finally:
            conn.close()

    def test_optional_scan_type_is_stored_without_changing_fingerprint(self):
        document = _document()
        original_fingerprint = calcular_fingerprint(parse_sarif(document)[0])
        typed_finding = parse_sarif(document, "k8s")[0]
        self.assertEqual(
            calcular_fingerprint(typed_finding), original_fingerprint
        )

        body = json.dumps(
            {"sarif": document, "tipo_scan": "k8s"}
        ).encode()
        _, response = self._post(body, len(body))

        self.assertEqual(response.status_code, 200)
        conn = sqlite3.connect(self.database)
        try:
            self.assertEqual(
                conn.execute("SELECT tipo_scan FROM findings").fetchone()[0],
                "k8s",
            )
            self.assertEqual(
                conn.execute("SELECT fingerprint FROM findings").fetchone()[0],
                original_fingerprint,
            )
        finally:
            conn.close()

    def test_authenticated_dashboard_endpoints_and_status_update(self):
        with TestClient(elma_api.app) as client:
            unauthenticated = client.get("/postura")
            self.assertEqual(unauthenticated.status_code, 401)

            response = client.post(
                "/findings",
                headers={"Authorization": "Bearer test-secret"},
                json={
                    "sarif": _document("error"),
                    "repositorio": "org/project",
                    "tipo_scan": "sast",
                },
            )
            self.assertEqual(response.status_code, 200, response.text)
            fingerprint = calcular_fingerprint(
                parse_sarif(_document("error"), "sast")[0]
                | {"repositorio": "org/project"}
            )
            headers = {"Authorization": "Bearer test-secret"}

            posture = client.get("/postura", headers=headers)
            self.assertEqual(posture.status_code, 200)
            self.assertEqual(posture.json()["total"], 1)

            assets = client.get("/ativos", headers=headers)
            self.assertEqual(assets.status_code, 200)
            self.assertEqual(assets.json()["items"][0]["repositorio"], "org/project")

            queue = client.get("/findings?limit=1", headers=headers)
            self.assertEqual(queue.status_code, 200)
            self.assertEqual(queue.json()["items"][0]["fingerprint"], fingerprint)
            self.assertIn("score_componentes", queue.json()["items"][0])
            self.assertEqual(
                client.get("/findings?limit=201", headers=headers).status_code,
                422,
            )

            detail = client.get(f"/findings/{fingerprint}", headers=headers)
            self.assertEqual(detail.status_code, 200)
            self.assertEqual(detail.json()["score_componentes"]["peso_severidade"], 7)

            updated_asset = client.patch(
                "/ativos/org%2Fproject",
                headers=headers,
                json={"exposicao": "internet", "criticidade": 5},
            )
            self.assertEqual(updated_asset.status_code, 200, updated_asset.text)
            self.assertEqual(updated_asset.json()["exposicao"], "internet")

            status = client.post(
                f"/findings/{fingerprint}/status",
                headers=headers,
                json={"status": "falso_positivo"},
            )
            self.assertEqual(status.status_code, 200, status.text)
            updated_detail = client.get(f"/findings/{fingerprint}", headers=headers)
            self.assertEqual(updated_detail.json()["status"], "falso_positivo")
            self.assertEqual(updated_detail.json()["score"], 0.0)

    def test_ai_analysis_endpoint_persists_advisory_for_single_finding(self):
        conn = conectar(self.database)
        fingerprint = "fp-ai-1"
        conn.execute(
            """INSERT INTO findings
               (fingerprint, status, repositorio, severidade, ferramenta, tipo_scan,
                regra, arquivo, linha, mensagem, trecho, primeira_vez, ultima_vez)
               VALUES (?, 'novo', 'org/project', 'HIGH', 'Trivy', 'sast',
                       'test-rule', 'src/app.py', 42, 'issue', 'print(123)',
                       '2025-01-01T00:00:00+00:00', '2025-01-02T00:00:00+00:00')""",
            (fingerprint,),
        )
        conn.commit()
        conn.close()

        with patch(
            "elma.api.gerar_sugestoes_estruturadas",
            return_value=[
                {
                    "fingerprint": fingerprint,
                    "sugestao": "provavel_real",
                    "confianca": 8,
                    "justificativa": "Evidência forte; revisão humana recomendada.",
                }
            ],
        ) as run_ai, TestClient(elma_api.app) as client:
            response = client.post(
                f"/findings/{fingerprint}/analyze",
                headers={"Authorization": "Bearer test-secret"},
                json={"provider": "ollama", "model": "llama3.1"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["updated"], 1)
        run_ai.assert_called_once()
        self.assertEqual(run_ai.call_args.kwargs["provider"], "ollama")
        self.assertEqual(run_ai.call_args.kwargs["model"], "llama3.1")

        conn = conectar(self.database)
        try:
            row = conn.execute(
                "SELECT sugestao_ia, confianca_ia, justificativa_ia FROM findings WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "provavel_real")
        self.assertEqual(row[1], 8)
        self.assertIn("Evidência forte", row[2])

    def test_ai_analysis_returns_503_when_provider_fails(self):
        fingerprint = "fp-ai-provider-error"
        self._seed_finding(fingerprint)

        with patch(
            "elma.api.gerar_sugestoes_estruturadas",
            side_effect=RuntimeError("falha na chamada de IA: provider indisponível"),
        ), TestClient(elma_api.app) as client:
            response = client.post(
                f"/findings/{fingerprint}/analyze",
                headers={"Authorization": "Bearer test-secret"},
                json={"provider": "ollama", "model": "llama3.1:8b"},
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn("provider indisponível", response.json()["detail"])

    def test_ai_config_exposes_env_models_per_provider(self):
        with patch.dict(
            os.environ,
            {
                "ELMA_CLOUD_MODEL": "gemini-custom",
                "ELMA_OLLAMA_MODEL": "llama-custom",
            },
            clear=False,
        ), TestClient(elma_api.app) as client:
            response = client.get(
                "/ai/config", headers={"Authorization": "Bearer test-secret"}
            )
        self.assertEqual(response.status_code, 200, response.text)
        dados = response.json()
        self.assertEqual(dados["model"], "gemini-custom")
        self.assertEqual(
            dados["modelos"],
            {"gemini": "gemini-custom", "ollama": "llama-custom"},
        )

    def test_manual_critical_confirmation_triggers_ticket_helper(self):
        fingerprint = "c" * 64
        conn = conectar(self.database)
        conn.execute(
            """INSERT INTO findings
               (fingerprint, status, repositorio, severidade, tipo_scan)
               VALUES (?, 'novo', 'org/project', 'CRITICAL', 'sast')""",
            (fingerprint,),
        )
        conn.commit()
        conn.close()

        ticket_result = {"dry_run": True, "titulo": "preview", "corpo": "body"}
        with patch(
            "elma.api.criar_issue_confirmado", return_value=ticket_result
        ) as create_ticket, TestClient(elma_api.app) as client:
            response = client.post(
                f"/findings/{fingerprint}/status",
                headers={"Authorization": "Bearer test-secret"},
                json={"status": "confirmado"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["ticket"], ticket_result)
        create_ticket.assert_called_once()

    def test_auto_close_api_reports_guard_and_rejects_missing_scope(self):
        conn = conectar(self.database)
        inicio = "2025-01-01T00:00:00+00:00"
        rows = [
            (
                f"fp-{index}",
                "novo",
                "2020-01-01T00:00:00+00:00" if index < 11 else inicio,
                "org/repo",
                "TestScanner",
                "sast",
            )
            for index in range(20)
        ]
        conn.executemany(
            """INSERT INTO findings
               (fingerprint, status, ultima_vez, repositorio, ferramenta, tipo_scan)
               VALUES (?, ?, ?, ?, ?, ?)""",
            rows,
        )
        conn.commit()
        conn.close()

        document = _document(level="warning")
        body = json.dumps(
            {
                "sarif": document,
                "repositorio": "org/repo",
                "tipo_scan": "sast",
                "fechar_ausentes": True,
            }
        ).encode()
        _, response = self._post(body, len(body))
        payload = json.loads(response.body)
        self.assertEqual(payload["fechados_automaticamente"], 0)
        self.assertTrue(any("bloqueado" in aviso.lower() for aviso in payload["avisos"]))
        self.assertTrue(payload["aprovado"])
        self.assertTrue(payload["fechamento_bloqueado"])
        self.assertTrue(payload["motivo_fechamento"])

        conn = conectar(self.database)
        historico_antes = conn.execute(
            "SELECT COUNT(*) FROM importacoes"
        ).fetchone()[0]
        conn.close()
        for payload in (
            {
                "sarif": document,
                "tipo_scan": "sast",
                "fechar_ausentes": True,
            },
            {
                "sarif": document,
                "repositorio": "org/repo",
                "fechar_ausentes": True,
            },
        ):
            body = json.dumps(payload).encode()
            with self.assertRaises(HTTPException) as captured:
                self._post(body, len(body))
            self.assertEqual(captured.exception.status_code, 422)
        conn = conectar(self.database)
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM importacoes").fetchone()[0],
                historico_antes,
            )
        finally:
            conn.close()

    def test_verified_clean_api_scan_closes_large_scope_without_failing_approval(self):
        conn = conectar(self.database)
        conn.executemany(
            """INSERT INTO findings
               (fingerprint, status, ultima_vez, repositorio, ferramenta, tipo_scan)
               VALUES (?, 'confirmado', '2020-01-01T00:00:00+00:00',
                       'org/repo', 'TestScanner', 'sast')""",
            [(f"clean-{index}",) for index in range(11)],
        )
        conn.commit()
        conn.close()

        body = json.dumps(
            {
                "sarif": _document(level=None, execution_successful=True),
                "repositorio": "org/repo",
                "tipo_scan": "sast",
                "fechar_ausentes": True,
            }
        ).encode()
        _, response = self._post(body, len(body))
        payload = json.loads(response.body)
        self.assertTrue(payload["aprovado"])
        self.assertFalse(payload["fechamento_bloqueado"])
        self.assertEqual(payload["fechados_automaticamente"], 11)

    def test_partial_sarif_does_not_close_three_findings(self):
        def seed_findings(prefix):
            conn = conectar(self.database)
            conn.executemany(
                """INSERT INTO findings
                   (fingerprint, status, ultima_vez, repositorio, ferramenta, tipo_scan)
                   VALUES (?, 'novo', '2020-01-01T00:00:00+00:00',
                           'org/repo', 'TestScanner', 'sast')""",
                [(f"{prefix}-{index}",) for index in range(3)],
            )
            conn.commit()
            conn.close()

        def post_scan(document):
            body = json.dumps(
                {
                    "sarif": document,
                    "repositorio": "org/repo",
                    "tipo_scan": "sast",
                    "fechar_ausentes": True,
                }
            ).encode()
            _, response = self._post(body, len(body))
            return json.loads(response.body)

        seed_findings("unverified")
        unverified_result = post_scan(_document(level=None))
        self.assertTrue(unverified_result["aprovado"])
        self.assertTrue(unverified_result["fechamento_bloqueado"])
        self.assertEqual(unverified_result["fechados_automaticamente"], 0)
        conn = conectar(self.database)
        conn.execute(
            "UPDATE findings SET status = 'falso_positivo' "
            "WHERE fingerprint LIKE 'unverified-%'"
        )
        conn.commit()
        conn.close()

        seed_findings("clean")
        clean_result = post_scan(
            _document(level=None, execution_successful=True)
        )
        self.assertEqual(clean_result["fechados_automaticamente"], 3)
        self.assertTrue(clean_result["aprovado"])
        self.assertFalse(clean_result["fechamento_bloqueado"])
        self.assertEqual(clean_result["avisos"], [])

        partial_document = _document(level=None)
        partial_document["runs"][0]["results"] = [{"locations": "invalid"}]
        seed_findings("partial")
        partial_result = post_scan(partial_document)
        self.assertEqual(partial_result["resultados_ignorados"], 1)
        self.assertEqual(partial_result["fechados_automaticamente"], 0)

        conn = conectar(self.database)
        try:
            statuses = conn.execute(
                "SELECT status FROM findings WHERE fingerprint LIKE 'partial-%' "
                "ORDER BY fingerprint"
            ).fetchall()
            self.assertEqual(statuses, [("novo",)] * 3)
        finally:
            conn.close()

    def test_fingerprint_conflict_prevents_api_auto_close(self):
        conn = conectar(self.database)
        conn.execute(
            """INSERT INTO findings
               (fingerprint, status, ultima_vez, repositorio, ferramenta, tipo_scan)
               VALUES ('keep-open', 'novo', '2020-01-01T00:00:00+00:00',
                       'org/repo', 'TestScanner', 'sast')"""
        )
        conn.commit()
        conn.close()

        body = json.dumps(
            {
                "sarif": _document(),
                "repositorio": "org/repo",
                "tipo_scan": "sast",
                "fechar_ausentes": True,
            }
        ).encode()
        with patch(
            "elma.api.filtrar_achados_novos",
            side_effect=elma_api.FingerprintConflictError([]),
        ), patch("elma.api.fechar_ausentes_para_ferramentas") as close_missing:
            with self.assertRaises(HTTPException) as error:
                self._post(body, len(body))

        self.assertEqual(error.exception.status_code, 409)
        close_missing.assert_not_called()
        conn = sqlite3.connect(self.database)
        try:
            self.assertEqual(
                conn.execute(
                    "SELECT status FROM findings WHERE fingerprint = 'keep-open'"
                ).fetchone()[0],
                "novo",
            )
        finally:
            conn.close()

    def test_masks_secrets_in_blocker_response_and_database(self):
        document = _document("error")
        result = document["runs"][0]["results"][0]
        result["message"]["text"] = "token=abcdefghijk"
        physical = result["locations"][0]["physicalLocation"]
        physical["artifactLocation"]["uri"] = "src/api_key=abcdefghijk.py"
        physical["region"]["snippet"] = {"text": "password=abcdefghijk"}
        body = json.dumps({"sarif": document, "repositorio": "org/project"}).encode()

        _, response = self._post(body, len(body))

        payload = json.loads(response.body)
        detail = payload["detalhes_bloqueadores"][0]
        self.assertTrue(detail["possivel_segredo"])
        self.assertNotIn("abcdefghijk", response.body.decode())
        self.assertIn("[REDACTED]", detail["mensagem"])

        import sqlite3

        conn = sqlite3.connect(self.database)
        try:
            values = conn.execute(
                "SELECT arquivo, trecho, mensagem, possivel_segredo FROM findings"
            ).fetchone()
            self.assertNotIn("abcdefghijk", " ".join(values[:3]))
            self.assertEqual(values[3], 1)
        finally:
            conn.close()

    def test_cli_and_api_store_same_repository_scoped_fingerprint(self):
        repository = "org/teste"
        document = _document()
        finding = parse_sarif(document)[0]
        finding["repositorio"] = repository
        expected_fingerprint = calcular_fingerprint(finding)

        sarif_path = os.path.join(self.tempdir.name, "same-finding.sarif")
        with open(sarif_path, "w", encoding="utf-8") as sarif_file:
            json.dump(document, sarif_file)
        cli_database = os.path.join(self.tempdir.name, "cli.db")
        api_database = os.path.join(self.tempdir.name, "api.db")

        with contextlib.redirect_stdout(io.StringIO()):
            cli_result = cli_main(
                [
                    "import-sarif",
                    sarif_path,
                    "--repo",
                    repository,
                    "--db",
                    cli_database,
                ]
            )
        self.assertEqual(cli_result, 0)

        with (
            patch.dict(
                os.environ,
                {"ELMA_API_KEY": "test-key", "ELMA_DB_PATH": api_database},
                clear=False,
            ),
            patch.object(elma_api, "CAMINHO_BANCO", api_database),
            TestClient(elma_api.app) as client,
        ):
            response = client.post(
                "/findings",
                headers={"Authorization": "Bearer test-key"},
                json={"sarif": document, "repositorio": repository},
            )
        self.assertEqual(response.status_code, 200, response.text)

        fingerprints = []
        for database in (cli_database, api_database):
            conn = sqlite3.connect(database)
            try:
                fingerprints.append(
                    conn.execute("SELECT fingerprint FROM findings").fetchall()
                )
            finally:
                conn.close()
        self.assertEqual(fingerprints, [[(expected_fingerprint,)], [(expected_fingerprint,)]])

    def test_cli_and_api_record_same_import_history_tools(self):
        repository = "org/historico"
        document = {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "QuietTool"}}, "results": []}],
        }
        sarif_path = os.path.join(self.tempdir.name, "quiet.sarif")
        with open(sarif_path, "w", encoding="utf-8") as sarif_file:
            json.dump(document, sarif_file)
        cli_database = os.path.join(self.tempdir.name, "cli-history.db")
        api_database = os.path.join(self.tempdir.name, "api-history.db")

        with contextlib.redirect_stdout(io.StringIO()):
            cli_result = cli_main(
                ["ci", sarif_path, "--repo", repository, "--db", cli_database]
            )
        self.assertEqual(cli_result, 0)

        with (
            patch.dict(
                os.environ,
                {"ELMA_API_KEY": "test-key", "ELMA_DB_PATH": api_database},
                clear=False,
            ),
            patch.object(elma_api, "CAMINHO_BANCO", api_database),
            TestClient(elma_api.app) as client,
        ):
            response = client.post(
                "/findings",
                headers={"Authorization": "Bearer test-key"},
                json={"sarif": document, "repositorio": repository},
            )
        self.assertEqual(response.status_code, 200, response.text)

        historicos = []
        for database in (cli_database, api_database):
            conn = sqlite3.connect(database)
            try:
                historicos.append(
                    conn.execute(
                        "SELECT ferramenta, lidos, novos, fechados, descartados "
                        "FROM importacoes"
                    ).fetchall()
                )
            finally:
                conn.close()
        self.assertEqual(historicos[0], historicos[1])
        self.assertEqual(historicos[0], [("QuietTool", 0, 0, 0, 0)])

    def test_rejects_invalid_json_and_fail_threshold(self):
        with self.assertRaises(HTTPException) as invalid_json:
            self._post(b"not json")
        self.assertEqual(invalid_json.exception.status_code, 422)

        body = json.dumps({"sarif": _document(), "fail_on": "ERROR"}).encode()
        with self.assertRaises(HTTPException) as invalid_threshold:
            self._post(body)
        self.assertEqual(invalid_threshold.exception.status_code, 422)

        body = json.dumps(
            {"sarif": _document(), "tipo_scan": "unknown"}
        ).encode()
        with self.assertRaises(HTTPException) as invalid_scan_type:
            self._post(body)
        self.assertEqual(invalid_scan_type.exception.status_code, 422)

    def test_tipo_scan_e_fechar_ausentes_no_corpo_post_findings(self):
        """Os campos tipo_scan e fechar_ausentes devem ser aceitos no POST /findings,
        não gerar AttributeError, e serem devolvidos no corpo da resposta.
        Antes da correção, esses campos estavam em RequisicaoAtualizarAtivo e
        a requisição quebrava com 500 (AttributeError) ao acessar corpo.tipo_scan."""
        document = _document(level="warning")
        body = json.dumps(
            {
                "sarif": document,
                "repositorio": "org/projeto-teste",
                "tipo_scan": "sast",
                "fechar_ausentes": False,
            }
        ).encode()
        _, response = self._post(body, len(body))
        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["repositorio"], "org/projeto-teste")
        self.assertEqual(payload["fechar_ausentes"], False)

        import sqlite3
        conn = sqlite3.connect(self.database)
        try:
            stored = conn.execute(
                "SELECT tipo_scan, repositorio FROM findings LIMIT 1"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(stored[0], "sast")
        self.assertEqual(stored[1], "org/projeto-teste")

    def test_patch_ativos_rejeita_campos_desconhecidos_mesmo_os_antigos(self):
        """O PATCH /ativos deve rejeitar tipo_scan / fechar_ausentes, que agora
        pertencem ao POST /findings. Antes estavam no model errado e passavam
        como campos extras silenciosamente descartados (ou 422 via atualizar_ativo)."""
        with TestClient(elma_api.app) as client:
            headers = {"Authorization": "Bearer test-secret"}
            response = client.patch(
                "/ativos/org%2Fqualquer",
                headers=headers,
                json={"tipo_scan": "sast", "fechar_ausentes": True, "exposicao": "internet"},
            )
            self.assertEqual(response.status_code, 422)

    def test_autenticacao_nao_quebra_com_token_nao_ascii(self):
        """compare_digest com strings não-ASCII (ex.: token com acento/emoji)
        deve retornar 401, nunca 500 TypeError."""
        document = _document("warning")
        request = FakeRequest(json.dumps({"sarif": document}).encode())
        with self.assertRaises(HTTPException) as captured:
            asyncio.run(elma_api.receber_findings(request, authorization="Bearer ãbcd_123_🚀"))
        self.assertEqual(captured.exception.status_code, 401)

    def _seed_finding(self, fingerprint):
        conn = conectar(self.database)
        conn.execute(
            """INSERT INTO findings
               (fingerprint, status, repositorio, severidade, ferramenta, tipo_scan,
                regra, arquivo, linha, mensagem, trecho)
               VALUES (?, 'novo', 'org/project', 'HIGH', 'Trivy', 'sast',
                       'test-rule', 'src/app.py', 42, 'issue', 'print(123)')""",
            (fingerprint,),
        )
        conn.commit()
        conn.close()

    def test_analyze_single_returns_503_on_provider_misconfiguration(self):
        fingerprint = "fp-503"
        self._seed_finding(fingerprint)

        with patch(
            "elma.api.gerar_sugestoes_estruturadas",
            side_effect=ValueError(
                "configure ELMA_GOOGLE_API_KEY para usar suggest-ia"
            ),
        ), TestClient(elma_api.app) as client:
            response = client.post(
                f"/findings/{fingerprint}/analyze",
                headers={"Authorization": "Bearer test-secret"},
                json={},
            )

        self.assertEqual(response.status_code, 503, response.text)
        self.assertIn("ELMA_GOOGLE_API_KEY", response.json()["detail"])

    def test_analyze_batch_returns_503_and_enforces_limit(self):
        self._seed_finding("fp-batch")
        headers = {"Authorization": "Bearer test-secret"}

        with patch(
            "elma.api.gerar_sugestoes_estruturadas",
            side_effect=ValueError("configure ELMA_GOOGLE_API_KEY"),
        ), TestClient(elma_api.app) as client:
            failure = client.post(
                "/findings/analyze",
                headers=headers,
                json={"fingerprints": ["fp-batch"]},
            )
            oversized = client.post(
                "/findings/analyze",
                headers=headers,
                json={"fingerprints": [f"fp-{index}" for index in range(51)]},
            )

        self.assertEqual(failure.status_code, 503, failure.text)
        self.assertEqual(oversized.status_code, 422, oversized.text)

    def test_remediate_single_persists_guidance(self):
        fingerprint = "fp-rem-1"
        self._seed_finding(fingerprint)

        with patch(
            "elma.api.gerar_remediacoes_estruturadas",
            return_value=[
                {"fingerprint": fingerprint, "remediacao": "Atualize a lib X."}
            ],
        ) as run_ai, TestClient(elma_api.app) as client:
            response = client.post(
                f"/findings/{fingerprint}/remediate",
                headers={"Authorization": "Bearer test-secret"},
                json={"provider": "ollama", "model": "llama3.1"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["updated"], 1)
        run_ai.assert_called_once()
        self.assertEqual(run_ai.call_args.kwargs["provider"], "ollama")

        conn = conectar(self.database)
        try:
            row = conn.execute(
                "SELECT remediacao_ia, remediacao_ia_gerada_em FROM findings "
                "WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(row[0], "Atualize a lib X.")
        self.assertTrue(row[1])

    def test_remediate_batch_persists_and_enforces_limit(self):
        self._seed_finding("fp-rem-batch")
        headers = {"Authorization": "Bearer test-secret"}

        with patch(
            "elma.api.gerar_remediacoes_estruturadas",
            return_value=[
                {"fingerprint": "fp-rem-batch", "remediacao": "Corrija Y."}
            ],
        ), TestClient(elma_api.app) as client:
            ok = client.post(
                "/findings/remediate",
                headers=headers,
                json={"fingerprints": ["fp-rem-batch"]},
            )
            oversized = client.post(
                "/findings/remediate",
                headers=headers,
                json={"fingerprints": [f"fp-{index}" for index in range(51)]},
            )

        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(ok.json()["updated"], 1)
        self.assertEqual(oversized.status_code, 422, oversized.text)

    def test_remediate_single_returns_503_on_provider_misconfiguration(self):
        fingerprint = "fp-rem-503"
        self._seed_finding(fingerprint)

        with patch(
            "elma.api.gerar_remediacoes_estruturadas",
            side_effect=ValueError(
                "configure ELMA_GOOGLE_API_KEY para usar remediar-ia"
            ),
        ), TestClient(elma_api.app) as client:
            response = client.post(
                f"/findings/{fingerprint}/remediate",
                headers={"Authorization": "Bearer test-secret"},
                json={},
            )

        self.assertEqual(response.status_code, 503, response.text)
        self.assertIn("ELMA_GOOGLE_API_KEY", response.json()["detail"])

    def test_remediate_single_returns_404_when_missing(self):
        with patch(
            "elma.api.gerar_remediacoes_estruturadas", return_value=[]
        ), TestClient(elma_api.app) as client:
            response = client.post(
                "/findings/nao-existe/remediate",
                headers={"Authorization": "Bearer test-secret"},
                json={},
            )
        self.assertEqual(response.status_code, 404, response.text)

    def test_remediate_single_returns_503_when_remediacao_indisponivel(self):
        fingerprint = "fp-rem-unavail"
        self._seed_finding(fingerprint)

        with patch(
            "elma.api.gerar_remediacoes_estruturadas",
            return_value=[{"fingerprint": fingerprint, "remediacao": None}],
        ), TestClient(elma_api.app) as client:
            response = client.post(
                f"/findings/{fingerprint}/remediate",
                headers={"Authorization": "Bearer test-secret"},
                json={},
            )

        self.assertEqual(response.status_code, 503, response.text)

        conn = conectar(self.database)
        try:
            row = conn.execute(
                "SELECT remediacao_ia, remediacao_ia_gerada_em FROM findings "
                "WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNone(row[0])
        self.assertIsNone(row[1])

    def test_remediate_batch_returns_503_when_all_remediacoes_indisponiveis(self):
        self._seed_finding("fp-rem-b1")
        self._seed_finding("fp-rem-b2")

        with patch(
            "elma.api.gerar_remediacoes_estruturadas",
            return_value=[
                {"fingerprint": "fp-rem-b1", "remediacao": None},
                {"fingerprint": "fp-rem-b2", "remediacao": None},
            ],
        ), TestClient(elma_api.app) as client:
            response = client.post(
                "/findings/remediate",
                headers={"Authorization": "Bearer test-secret"},
                json={"fingerprints": ["fp-rem-b1", "fp-rem-b2"]},
            )

        self.assertEqual(response.status_code, 503, response.text)

    def test_remediate_batch_pula_indisponiveis_e_persiste_disponiveis(self):
        self._seed_finding("fp-rem-ok")
        self._seed_finding("fp-rem-none")

        with patch(
            "elma.api.gerar_remediacoes_estruturadas",
            return_value=[
                {"fingerprint": "fp-rem-ok", "remediacao": "Corrija Z."},
                {"fingerprint": "fp-rem-none", "remediacao": None},
            ],
        ), TestClient(elma_api.app) as client:
            response = client.post(
                "/findings/remediate",
                headers={"Authorization": "Bearer test-secret"},
                json={"fingerprints": ["fp-rem-ok", "fp-rem-none"]},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["updated"], 1)

        conn = conectar(self.database)
        try:
            ok_row = conn.execute(
                "SELECT remediacao_ia FROM findings WHERE fingerprint = ?",
                ("fp-rem-ok",),
            ).fetchone()
            none_row = conn.execute(
                "SELECT remediacao_ia, remediacao_ia_gerada_em FROM findings "
                "WHERE fingerprint = ?",
                ("fp-rem-none",),
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(ok_row[0], "Corrija Z.")
        self.assertIsNone(none_row[0])
        self.assertIsNone(none_row[1])

    def test_manual_corrected_status_calls_fechar_issue(self):
        fingerprint = "ab" * 32
        conn = conectar(self.database)
        conn.execute(
            """INSERT INTO findings
               (fingerprint, status, repositorio, severidade, tipo_scan)
               VALUES (?, 'confirmado', 'org/project', 'CRITICAL', 'sast')""",
            (fingerprint,),
        )
        conn.commit()
        conn.close()

        ticket_result = {
            "atualizada": True,
            "issue_url": "https://github.com/org/project/issues/5",
        }
        with patch(
            "elma.api.fechar_issue", return_value=ticket_result
        ) as fechar, TestClient(elma_api.app) as client:
            response = client.post(
                f"/findings/{fingerprint}/status",
                headers={"Authorization": "Bearer test-secret"},
                json={"status": "corrigido"},
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["ticket"], ticket_result)
        fechar.assert_called_once()

    def test_ingest_reports_issue_sync_counts(self):
        body = json.dumps(
            {
                "sarif": _document(level=None, execution_successful=True),
                "repositorio": "org/repo",
                "tipo_scan": "sast",
                "fechar_ausentes": True,
            }
        ).encode()

        with patch(
            "elma.api.sincronizar_issues_apos_ingestao",
            return_value={"reabertas": 2, "fechadas": 3},
        ) as sync:
            _, response = self._post(body, len(body))

        payload = json.loads(response.body)
        self.assertEqual(payload["issues_reabertas"], 2)
        self.assertEqual(payload["issues_fechadas"], 3)
        sync.assert_called_once()

    def test_lifespan_falha_cedo_com_configuracao_sla_invalida(self):
        with patch.dict(os.environ, {"ELMA_SLA_HIGH": "abc"}):
            with self.assertRaises(Exception) as capturado:
                with TestClient(elma_api.app):
                    pass
        self.assertIn("Configuração de SLA inválida", str(capturado.exception))

    def test_fila_resolve_sla_antes_dos_filtros_e_nao_vira_422(self):
        with patch.object(
            elma_api,
            "resolver_sla_dias",
            side_effect=ValueError("ELMA_SLA_HIGH precisa ser um inteiro de dias"),
        ):
            with self.assertRaises(ValueError) as capturado:
                elma_api.obter_fila_findings(
                    limit=50, offset=0, authorization="Bearer test-secret"
                )
        self.assertIn("ELMA_SLA_HIGH", str(capturado.exception))

    def test_metricas_endpoint_returns_derived_summary(self):
        conn = conectar(self.database)
        try:
            conn.execute(
                """INSERT INTO findings
                     (fingerprint, regra, arquivo, linha, status, primeira_vez,
                      ultima_vez, severidade, tipo_scan)
                   VALUES (?, 'regra', 'app.py', 1, 'novo',
                           '2026-01-01T00:00:00+00:00',
                           '2026-01-01T00:00:00+00:00', 'HIGH', 'sast')""",
                ("f" * 64,),
            )
            registrar_importacao(
                conn,
                "org/repo",
                "semgrep",
                "sast",
                lidos=4,
                novos=3,
                reabertos=0,
                fechados=1,
                data="2026-02-01T08:00:00+00:00",
            )
            conn.commit()
        finally:
            conn.close()

        with TestClient(elma_api.app) as client:
            resposta = client.get(
                "/metricas", headers={"Authorization": "Bearer test-secret"}
            )
            self.assertEqual(resposta.status_code, 200)
            corpo = resposta.json()
            sem_auth = client.get("/metricas")

        self.assertEqual(sem_auth.status_code, 401)
        self.assertEqual(set(corpo), {"aging", "mttr", "tendencia", "sla"})
        self.assertEqual(corpo["aging"]["abertos"], 1)
        self.assertEqual(corpo["mttr"]["amostra"], 0)
        self.assertEqual(
            corpo["tendencia"],
            [{"data": "2026-02-01", "novos": 3, "fechados": 1, "lidos": 4}],
        )
        self.assertEqual(corpo["sla"]["aplicaveis"], 1)


if __name__ == "__main__":
    unittest.main()