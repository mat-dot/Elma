import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from elma import db as elma_db
from elma.sla import (
    SLA_DIAS_PADRAO,
    calcular_sla,
    resolver_sla_dias,
    resumir_sla,
)

AGORA = datetime(2026, 3, 1, tzinfo=timezone.utc)
_OMITIDO = object()


def _achado(severidade="HIGH", status="novo", dias_atras=0, primeira_vez=_OMITIDO):
    if primeira_vez is _OMITIDO:
        primeira_vez = (AGORA - timedelta(days=dias_atras)).isoformat()
    return {
        "fingerprint": "a" * 64,
        "severidade": severidade,
        "status": status,
        "primeira_vez": primeira_vez,
    }


class CalcularSlaTests(unittest.TestCase):
    def test_open_high_within_sla_is_not_overdue(self):
        sla = calcular_sla(_achado("HIGH", "novo", dias_atras=5), agora=AGORA)
        self.assertTrue(sla["aplicavel"])
        self.assertEqual(sla["sla_dias"], 30)
        self.assertFalse(sla["atrasado"])
        self.assertEqual(sla["dias_restantes"], 25)
        self.assertEqual(
            sla["data_limite"],
            (AGORA - timedelta(days=5) + timedelta(days=30)).date().isoformat(),
        )

    def test_aged_critical_is_overdue_with_negative_days(self):
        sla = calcular_sla(_achado("CRITICAL", "confirmado", dias_atras=40), agora=AGORA)
        self.assertTrue(sla["aplicavel"])
        self.assertTrue(sla["atrasado"])
        self.assertEqual(sla["sla_dias"], 15)
        self.assertEqual(sla["dias_restantes"], -25)

    def test_exact_due_date_is_not_overdue(self):
        sla = calcular_sla(_achado("MEDIUM", "novo", dias_atras=90), agora=AGORA)
        self.assertTrue(sla["aplicavel"])
        self.assertFalse(sla["atrasado"])
        self.assertEqual(sla["dias_restantes"], 0)

    def test_closed_statuses_are_not_applicable(self):
        for status in ("falso_positivo", "corrigido"):
            with self.subTest(status=status):
                sla = calcular_sla(
                    _achado("CRITICAL", status, dias_atras=100), agora=AGORA
                )
                self.assertFalse(sla["aplicavel"])
                self.assertFalse(sla["atrasado"])
                self.assertIsNone(sla["data_limite"])

    def test_info_and_unknown_have_no_sla(self):
        for severidade in ("INFO", "UNKNOWN"):
            with self.subTest(severidade=severidade):
                sla = calcular_sla(
                    _achado(severidade, "novo", dias_atras=400), agora=AGORA
                )
                self.assertFalse(sla["aplicavel"])
                self.assertIsNone(sla["sla_dias"])

    def test_missing_or_invalid_primeira_vez_is_not_applicable(self):
        for primeira_vez in (None, "", "nao-e-data"):
            with self.subTest(primeira_vez=primeira_vez):
                sla = calcular_sla(
                    _achado("HIGH", "novo", primeira_vez=primeira_vez), agora=AGORA
                )
                self.assertFalse(sla["aplicavel"])

    def test_lowercase_severity_is_normalized(self):
        sla = calcular_sla(_achado("high", "novo", dias_atras=5), agora=AGORA)
        self.assertEqual(sla["severidade"], "HIGH")
        self.assertEqual(sla["sla_dias"], 30)

    def test_naive_agora_is_treated_as_utc(self):
        sla = calcular_sla(
            _achado("HIGH", "novo", dias_atras=5),
            agora=datetime(2026, 3, 1),
        )
        self.assertTrue(sla["aplicavel"])
        self.assertEqual(sla["dias_restantes"], 25)

    def test_agora_as_iso_string_is_accepted(self):
        sla = calcular_sla(
            _achado("HIGH", "novo", dias_atras=5), agora=AGORA.isoformat()
        )
        self.assertEqual(sla["dias_restantes"], 25)


class ResolverSlaDiasTests(unittest.TestCase):
    def setUp(self):
        self._saved = {
            key: os.environ.get(key)
            for key in (f"ELMA_SLA_{sev}" for sev in SLA_DIAS_PADRAO)
        }

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_defaults_match_table(self):
        for key in self._saved:
            os.environ.pop(key, None)
        self.assertEqual(resolver_sla_dias(), SLA_DIAS_PADRAO)

    def test_env_override_changes_deadline(self):
        os.environ["ELMA_SLA_HIGH"] = "7"
        dias = resolver_sla_dias()
        self.assertEqual(dias["HIGH"], 7)
        sla = calcular_sla(_achado("HIGH", "novo", dias_atras=10), agora=AGORA, sla_dias=dias)
        self.assertTrue(sla["atrasado"])
        self.assertEqual(sla["dias_restantes"], -3)

    def test_override_can_enable_sla_for_info(self):
        os.environ["ELMA_SLA_INFO"] = "30"
        dias = resolver_sla_dias()
        sla = calcular_sla(_achado("INFO", "novo", dias_atras=5), agora=AGORA, sla_dias=dias)
        self.assertTrue(sla["aplicavel"])
        self.assertEqual(sla["sla_dias"], 30)

    def test_invalid_override_raises(self):
        os.environ["ELMA_SLA_HIGH"] = "abc"
        with self.assertRaises(ValueError):
            resolver_sla_dias()

    def test_negative_override_raises(self):
        os.environ["ELMA_SLA_HIGH"] = "-1"
        with self.assertRaises(ValueError):
            resolver_sla_dias()


class ResumirSlaTests(unittest.TestCase):
    def test_counts_applicable_and_overdue_by_severity(self):
        achados = [
            _achado("CRITICAL", "novo", dias_atras=40),   # overdue
            _achado("HIGH", "confirmado", dias_atras=10), # within
            _achado("HIGH", "novo", dias_atras=60),       # overdue
            _achado("INFO", "novo", dias_atras=999),      # not applicable
            _achado("CRITICAL", "corrigido", dias_atras=999),  # not applicable
        ]
        resumo = resumir_sla(achados, agora=AGORA)
        self.assertEqual(resumo["aplicaveis"], 3)
        self.assertEqual(resumo["atrasados"], 2)
        self.assertEqual(resumo["atrasados_por_severidade"], {"CRITICAL": 1, "HIGH": 1})


class IntegracaoBancoTests(unittest.TestCase):
    def setUp(self):
        self.conn = elma_db.conectar(":memory:")
        self.agora = datetime.now(timezone.utc)

    def tearDown(self):
        self.conn.close()

    def _inserir(self, fingerprint, severidade, status, dias_atras):
        primeira_vez = (self.agora - timedelta(days=dias_atras)).isoformat()
        self.conn.execute(
            """INSERT INTO findings
                 (fingerprint, regra, arquivo, linha, status, primeira_vez,
                  ultima_vez, severidade, tipo_scan)
               VALUES (?, 'regra', 'app.py', 1, ?, ?, ?, ?, 'sast')""",
            (fingerprint, status, primeira_vez, primeira_vez, severidade),
        )
        self.conn.commit()

    def test_obter_achado_inclui_sla(self):
        self._inserir("c" * 64, "HIGH", "novo", 45)
        achado = elma_db.obter_achado("c" * 64, self.conn)
        self.assertIn("sla", achado)
        self.assertTrue(achado["sla"]["atrasado"])

    def test_fila_filtra_por_atrasado(self):
        self._inserir("d" * 64, "CRITICAL", "novo", 40)  # overdue
        self._inserir("e" * 64, "LOW", "novo", 1)         # within
        atrasados = elma_db.listar_fila(self.conn, {"atrasado": True})
        dentro = elma_db.listar_fila(self.conn, {"atrasado": False})
        self.assertEqual(atrasados["total"], 1)
        self.assertEqual(atrasados["items"][0]["fingerprint"], "d" * 64)
        self.assertEqual(dentro["total"], 1)
        self.assertEqual(dentro["items"][0]["fingerprint"], "e" * 64)

    def test_postura_inclui_resumo_sla(self):
        self._inserir("f" * 64, "HIGH", "novo", 60)
        postura = elma_db.resumir_postura(self.conn)
        self.assertIn("sla", postura)
        self.assertEqual(postura["sla"]["atrasados"], 1)
        self.assertEqual(postura["sla"]["atrasados_por_severidade"], {"HIGH": 1})

    def test_regressao_reabre_e_zera_relogio_sla(self):
        achado = {
            "check_id": "regra-x",
            "path": "app.py",
            "start": {"line": 10},
            "extra": {"lines": "print('hello')", "message": "exemplo"},
            "severity": "HIGH",
            "tool_name": "Semgrep",
            "source_format": "SARIF 2.1.0",
            "tipo_scan": "sast",
        }
        fingerprint = elma_db.calcular_fingerprint(achado)
        # Corrigido visto há 100 dias: sem o reset, reabriria com SLA estourado.
        self._inserir(fingerprint, "HIGH", "corrigido", 100)

        apresentados = elma_db.filtrar_achados_novos(
            [achado], self.conn, agora=self.agora.isoformat()
        )

        self.assertEqual(len(apresentados), 1)
        status, primeira_vez, severidade = self.conn.execute(
            "SELECT status, primeira_vez, severidade FROM findings WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        self.assertEqual(status, "novo")
        sla = calcular_sla(
            {"status": status, "severidade": severidade, "primeira_vez": primeira_vez},
            agora=self.agora,
        )
        self.assertTrue(sla["aplicavel"])
        self.assertFalse(sla["atrasado"])
        self.assertEqual(sla["dias_restantes"], 30)

    def test_listar_fila_usa_sla_dias_fornecido_sem_resolver_config(self):
        self._inserir("b" * 64, "HIGH", "novo", 1)
        with patch.object(
            elma_db,
            "resolver_sla_dias",
            side_effect=AssertionError("não deveria resolver a configuração"),
        ):
            fila = elma_db.listar_fila(self.conn, {}, sla_dias=SLA_DIAS_PADRAO)
        self.assertEqual(fila["total"], 1)

    def test_listar_fila_sem_sla_dias_resolve_configuracao(self):
        self._inserir("b" * 64, "HIGH", "novo", 1)
        with patch.object(
            elma_db,
            "resolver_sla_dias",
            side_effect=ValueError("ELMA_SLA_HIGH precisa ser um inteiro de dias"),
        ):
            with self.assertRaises(ValueError):
                elma_db.listar_fila(self.conn, {})


if __name__ == "__main__":
    unittest.main()
