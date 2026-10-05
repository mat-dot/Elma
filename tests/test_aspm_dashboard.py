# Elma ASPM - Challenge FIAP x PRIDE 2026
# Copyright (C) 2026 Equipe Abutres
# SPDX-License-Identifier: BSD-3-Clause
# Licenciado sob BSD 3-Clause. Veja o arquivo LICENSE.md.

import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from elma.db import (
    MIGRACAO_ATIVOS,
    MIGRACAO_DESCARTADOS_IMPORTACAO,
    MIGRACAO_FECHAMENTO_AUTOMATICO,
    MIGRACAO_HISTORICO_IMPORTACOES,
    MIGRACAO_MASCARAMENTO_SEGREDOS,
    MIGRACAO_MASCARAMENTO_V2,
    MIGRACAO_REMEDIACAO_IA,
    MIGRACAO_SEVERIDADE_CANONICA,
    MIGRACAO_TICKETS,
    MIGRACAO_RESERVA_TICKETS,
    ULTIMA_MIGRACAO,
    atualizar_ativo,
    conectar,
    listar_achados,
    listar_fila,
    obter_achado,
    registrar_ativo_se_ausente,
    registrar_importacao,
    resumir_ativos,
    resumir_postura,
)


class DashboardAggregationTests(unittest.TestCase):
    def setUp(self):
        self.conn = conectar(":memory:")
        atualizar_ativo(
            "org/public",
            {"nome": "Public API", "tipo": "api", "exposicao": "internet", "criticidade": 5},
            self.conn,
        )
        atualizar_ativo(
            "org/internal",
            {"nome": "Internal Library", "tipo": "lib", "criticidade": 1},
            self.conn,
        )
        agora = datetime.now(timezone.utc).isoformat()
        semana_passada = (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()
        self._finding("fp-high", "org/public", "HIGH", "novo", "sast", agora, True)
        self._finding("fp-sca", "org/public", "LOW", "confirmado", "sca", agora)
        self._finding("fp-critical", "org/internal", "CRITICAL", "novo", "sast", semana_passada)
        self._finding("fp-fp", "org/internal", "HIGH", "falso_positivo", "sast", agora)
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def _finding(
        self, fingerprint, repo, severity, status, scan_type, seen_at, secret=False
    ):
        self.conn.execute(
            """INSERT INTO findings
               (fingerprint, repositorio, severidade, status, tipo_scan,
                primeira_vez, ultima_vez, possivel_segredo)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (fingerprint, repo, severity, status, scan_type, seen_at, seen_at, int(secret)),
        )

    def test_posture_totals_recent_findings_and_secret_count(self):
        summary = resumir_postura(self.conn)

        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["por_severidade"]["HIGH"], 2)
        self.assertEqual(summary["por_status"]["novo"], 2)
        self.assertEqual(summary["novos_7d"], 3)
        self.assertEqual(summary["possiveis_segredos"], 1)

    def test_asset_summary_includes_scan_counts_latest_time_and_gaps(self):
        summaries = {asset["repositorio"]: asset for asset in resumir_ativos(self.conn)}
        public = summaries["org/public"]

        self.assertEqual(public["total_findings"], 2)
        self.assertEqual(public["por_severidade"]["HIGH"], 1)
        self.assertEqual(public["por_tipo_scan"]["sast"]["total"], 1)
        self.assertTrue(public["por_tipo_scan"]["sast"]["ultimo_scan"])
        self.assertIn("iac", public["lacunas"])
        self.assertEqual(summaries["org/internal"]["por_tipo_scan"]["sca"]["total"], 0)

    def test_asset_scan_time_uses_history_when_scan_found_nothing(self):
        registrar_ativo_se_ausente("org/clean", self.conn)
        scan_time = "2026-09-29T12:00:00+00:00"
        registrar_importacao(
            self.conn,
            "org/clean",
            "Trivy",
            "sca",
            lidos=0,
            novos=0,
            reabertos=0,
            fechados=0,
            data=scan_time,
        )

        summaries = {asset["repositorio"]: asset for asset in resumir_ativos(self.conn)}
        clean = summaries["org/clean"]
        self.assertEqual(clean["por_tipo_scan"]["sca"]["ultimo_scan"], scan_time)
        self.assertNotIn("sca", clean["lacunas"])

    def test_queue_sorts_by_score_filters_and_paginates(self):
        page = listar_fila(self.conn, limit=1, offset=0)

        self.assertEqual(page["total"], 4)
        self.assertEqual(page["items"][0]["fingerprint"], "fp-high")
        self.assertGreater(
            page["items"][0]["score"],
            listar_fila(self.conn, {"repositorio": "org/internal"}, 10, 0)["items"][0]["score"],
        )
        filtered = listar_fila(
            self.conn,
            {"repositorio": "org/public", "tipo_scan": "sca"},
            limit=10,
        )
        self.assertEqual(filtered["total"], 1)
        self.assertEqual(filtered["items"][0]["fingerprint"], "fp-sca")
        self.assertEqual(
            listar_fila(self.conn, {"possivel_segredo": True}, limit=10)["total"], 1
        )

    def test_schema_latest_migration_tracks_all_known_versions(self):
        versoes = {
            MIGRACAO_SEVERIDADE_CANONICA,
            MIGRACAO_MASCARAMENTO_SEGREDOS,
            MIGRACAO_MASCARAMENTO_V2,
            MIGRACAO_FECHAMENTO_AUTOMATICO,
            MIGRACAO_ATIVOS,
            MIGRACAO_HISTORICO_IMPORTACOES,
            MIGRACAO_DESCARTADOS_IMPORTACAO,
            MIGRACAO_TICKETS,
            MIGRACAO_RESERVA_TICKETS,
            MIGRACAO_REMEDIACAO_IA,
        }

        self.assertEqual(ULTIMA_MIGRACAO, max(versoes))

    def test_conectar_applies_missing_migrations_for_legacy_database(self):
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "legacy.db")
            conn = sqlite3.connect(database_path)
            conn.execute(
                """
                CREATE TABLE findings (
                    fingerprint TEXT PRIMARY KEY,
                    regra TEXT,
                    arquivo TEXT,
                    linha INTEGER,
                    trecho TEXT,
                    status TEXT DEFAULT 'novo',
                    primeira_vez TEXT,
                    ultima_vez TEXT,
                    repositorio TEXT,
                    possivel_segredo INTEGER
                )
                """
            )
            conn.execute(
                "INSERT INTO findings (fingerprint, regra, arquivo, linha, trecho, status, primeira_vez, ultima_vez, repositorio, possivel_segredo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "legacy-1",
                    "test-rule",
                    "src/app.py",
                    10,
                    "token = 'abc'",
                    "novo",
                    "2024-01-01T00:00:00+00:00",
                    "2024-01-01T00:00:00+00:00",
                    "org/repo",
                    0,
                ),
            )
            conn.commit()
            conn.close()

            conn = conectar(database_path)
            try:
                self.assertTrue(
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ativos'"
                    ).fetchone()
                )
                self.assertTrue(
                    conn.execute(
                        "SELECT 1 FROM pragma_table_info('findings') WHERE name='tipo_scan'"
                    ).fetchone()
                )
                rows = listar_achados(conn)
                self.assertEqual(rows[0]["fingerprint"], "legacy-1")
                self.assertEqual(rows[0]["repositorio"], "org/repo")
                self.assertEqual(resumir_ativos(conn)[0]["repositorio"], "org/repo")
            finally:
                conn.close()

    def test_conectar_adiciona_colunas_remediacao_em_banco_versao_nove(self):
        """Bug 1: a v9 database must gain remediacao_ia via conectar(), not only migrar()."""
        with tempfile.TemporaryDirectory() as directory:
            database_path = os.path.join(directory, "v9.db")
            conn = conectar(database_path)
            conn.execute(
                "INSERT INTO findings (fingerprint, status) VALUES ('fp-v9', 'novo')"
            )
            conn.commit()
            conn.execute("ALTER TABLE findings DROP COLUMN remediacao_ia")
            conn.execute("ALTER TABLE findings DROP COLUMN remediacao_ia_gerada_em")
            conn.execute(
                "DELETE FROM elma_schema_migrations WHERE version = ?",
                (MIGRACAO_REMEDIACAO_IA,),
            )
            conn.commit()
            antes = conn.execute(
                "SELECT MAX(version) FROM elma_schema_migrations"
            ).fetchone()[0]
            self.assertEqual(antes, MIGRACAO_RESERVA_TICKETS)
            conn.close()

            conn = conectar(database_path)
            try:
                colunas = {
                    linha[1] for linha in conn.execute("PRAGMA table_info(findings)")
                }
                self.assertIn("remediacao_ia", colunas)
                self.assertIn("remediacao_ia_gerada_em", colunas)
                versao = conn.execute(
                    "SELECT MAX(version) FROM elma_schema_migrations"
                ).fetchone()[0]
                self.assertEqual(versao, ULTIMA_MIGRACAO)
                self.assertEqual(listar_achados(conn)[0]["fingerprint"], "fp-v9")
                self.assertIsNone(obter_achado("fp-v9", conn)["remediacao_ia"])
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
