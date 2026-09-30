import unittest
from datetime import datetime, timedelta, timezone

from elma import db as elma_db
from elma.metricas import (
    FAIXAS_AGING,
    calcular_aging,
    calcular_mttr,
    calcular_tendencia,
    resumir_metricas,
)

AGORA = datetime(2026, 3, 1, tzinfo=timezone.utc)
_OMITIDO = object()


def _achado(
    status="novo",
    dias_atras=0,
    severidade="HIGH",
    primeira_vez=_OMITIDO,
    fechado_em=None,
):
    if primeira_vez is _OMITIDO:
        primeira_vez = (AGORA - timedelta(days=dias_atras)).isoformat()
    return {
        "fingerprint": "a" * 64,
        "status": status,
        "severidade": severidade,
        "primeira_vez": primeira_vez,
        "fechado_automaticamente_em": fechado_em,
    }


class CalcularAgingTests(unittest.TestCase):
    def test_open_findings_are_bucketed_by_age(self):
        achados = [
            _achado("novo", dias_atras=5),
            _achado("confirmado", dias_atras=45),
            _achado("novo", dias_atras=120),
        ]
        aging = calcular_aging(achados, agora=AGORA)
        self.assertEqual(aging["abertos"], 3)
        self.assertEqual(aging["idade_media_dias"], 56.7)
        self.assertEqual(aging["idade_mediana_dias"], 45)
        self.assertEqual(aging["idade_maxima_dias"], 120)
        self.assertEqual(
            aging["faixas"],
            {"0_30": 1, "31_60": 1, "61_90": 0, "90_plus": 1},
        )

    def test_closed_statuses_and_missing_timestamps_are_ignored(self):
        achados = [
            _achado("corrigido", dias_atras=200),
            _achado("falso_positivo", dias_atras=200),
            _achado("novo", primeira_vez=None),
            _achado("novo", primeira_vez="nao-e-data"),
        ]
        aging = calcular_aging(achados, agora=AGORA)
        self.assertEqual(aging["abertos"], 0)
        self.assertIsNone(aging["idade_media_dias"])
        self.assertIsNone(aging["idade_mediana_dias"])
        self.assertIsNone(aging["idade_maxima_dias"])
        self.assertEqual(
            aging["faixas"],
            {"0_30": 0, "31_60": 0, "61_90": 0, "90_plus": 0},
        )

    def test_bucket_boundaries(self):
        for dias, faixa in (
            (0, "0_30"),
            (30, "0_30"),
            (31, "31_60"),
            (60, "31_60"),
            (61, "61_90"),
            (90, "61_90"),
            (91, "90_plus"),
        ):
            with self.subTest(dias=dias):
                aging = calcular_aging([_achado(dias_atras=dias)], agora=AGORA)
                esperadas = {chave: 0 for chave, _, _ in FAIXAS_AGING}
                esperadas[faixa] = 1
                self.assertEqual(aging["faixas"], esperadas)

    def test_future_primeira_vez_is_clamped_to_zero(self):
        aging = calcular_aging([_achado(dias_atras=-10)], agora=AGORA)
        self.assertEqual(aging["abertos"], 1)
        self.assertEqual(aging["idade_maxima_dias"], 0)
        self.assertEqual(aging["faixas"]["0_30"], 1)

    def test_empty_findings(self):
        aging = calcular_aging([], agora=AGORA)
        self.assertEqual(aging["abertos"], 0)
        self.assertIsNone(aging["idade_media_dias"])


class CalcularMttrTests(unittest.TestCase):
    def test_mean_and_median_over_resolution_durations(self):
        achados = [
            _achado("corrigido", dias_atras=30, fechado_em=(AGORA - timedelta(days=20)).isoformat()),
            _achado("corrigido", dias_atras=30, fechado_em=(AGORA - timedelta(days=10)).isoformat()),
            _achado("corrigido", dias_atras=90, fechado_em=(AGORA - timedelta(days=30)).isoformat()),
        ]
        mttr = calcular_mttr(achados)
        self.assertEqual(mttr["corrigidos"], 3)
        self.assertEqual(mttr["amostra"], 3)
        self.assertEqual(mttr["mttr_dias"], 30.0)  # (20 + 20 + 60) / 3
        self.assertEqual(mttr["mttr_mediano_dias"], 20)

    def test_manually_corrected_without_timestamp_stays_out_of_sample(self):
        achados = [
            _achado("corrigido", dias_atras=30, fechado_em=(AGORA - timedelta(days=10)).isoformat()),
            _achado("corrigido", dias_atras=30, fechado_em=None),
        ]
        mttr = calcular_mttr(achados)
        self.assertEqual(mttr["corrigidos"], 2)
        self.assertEqual(mttr["amostra"], 1)
        self.assertEqual(mttr["mttr_dias"], 20)

    def test_open_findings_are_not_counted(self):
        mttr = calcular_mttr([_achado("novo", dias_atras=5), _achado("confirmado", dias_atras=5)])
        self.assertEqual(mttr, {"corrigidos": 0, "amostra": 0, "mttr_dias": None, "mttr_mediano_dias": None})

    def test_resolution_before_first_seen_is_clamped_to_zero(self):
        achados = [
            _achado("corrigido", dias_atras=10, fechado_em=(AGORA - timedelta(days=20)).isoformat())
        ]
        mttr = calcular_mttr(achados)
        self.assertEqual(mttr["amostra"], 1)
        self.assertEqual(mttr["mttr_dias"], 0)


class CalcularTendenciaTests(unittest.TestCase):
    def test_rows_of_same_day_are_summed_and_sorted_oldest_first(self):
        importacoes = [
            {"data": "2026-02-02T18:00:00+00:00", "novos": 5, "fechados": 0, "lidos": 1},
            {"data": "2026-02-01T08:00:00+00:00", "novos": 1, "fechados": 2, "lidos": 3},
            {"data": "2026-02-02T09:00:00+00:00", "novos": 2, "fechados": 1, "lidos": 3},
        ]
        tendencia = calcular_tendencia(importacoes)
        self.assertEqual(
            tendencia,
            [
                {"data": "2026-02-01", "novos": 1, "fechados": 2, "lidos": 3},
                {"data": "2026-02-02", "novos": 7, "fechados": 1, "lidos": 4},
            ],
        )

    def test_invalid_or_missing_dates_are_skipped(self):
        importacoes = [
            {"data": None, "novos": 9, "fechados": 9, "lidos": 9},
            {"data": "nao-e-data", "novos": 9, "fechados": 9, "lidos": 9},
            {"data": "2026-02-01T08:00:00+00:00", "novos": 2, "fechados": 1, "lidos": 4},
        ]
        tendencia = calcular_tendencia(importacoes)
        self.assertEqual(tendencia, [{"data": "2026-02-01", "novos": 2, "fechados": 1, "lidos": 4}])

    def test_empty_history(self):
        self.assertEqual(calcular_tendencia([]), [])


class ResumirMetricasTests(unittest.TestCase):
    def test_combines_aging_mttr_trend_and_sla(self):
        achados = [
            _achado("novo", dias_atras=40, severidade="CRITICAL"),  # SLA atrasado
            _achado("novo", dias_atras=10),
            _achado("corrigido", dias_atras=30, fechado_em=(AGORA - timedelta(days=10)).isoformat()),
        ]
        importacoes = [{"data": "2026-02-01T08:00:00+00:00", "novos": 3, "fechados": 1, "lidos": 4}]
        resumo = resumir_metricas(achados, importacoes, agora=AGORA)
        self.assertEqual(set(resumo), {"aging", "mttr", "tendencia", "sla"})
        self.assertEqual(resumo["aging"]["abertos"], 2)
        self.assertEqual(resumo["mttr"]["amostra"], 1)
        self.assertEqual(len(resumo["tendencia"]), 1)
        self.assertEqual(resumo["sla"]["aplicaveis"], 2)
        self.assertEqual(resumo["sla"]["atrasados"], 1)


class IntegracaoBancoTests(unittest.TestCase):
    def setUp(self):
        self.conn = elma_db.conectar(":memory:")
        self.agora = datetime.now(timezone.utc)

    def tearDown(self):
        self.conn.close()

    def _inserir(self, fingerprint, status, dias_atras, fechado_dias_atras=None):
        primeira_vez = (self.agora - timedelta(days=dias_atras)).isoformat()
        fechado = (
            (self.agora - timedelta(days=fechado_dias_atras)).isoformat()
            if fechado_dias_atras is not None
            else None
        )
        self.conn.execute(
            """INSERT INTO findings
                 (fingerprint, regra, arquivo, linha, status, primeira_vez,
                  ultima_vez, severidade, tipo_scan, fechado_automaticamente_em)
               VALUES (?, 'regra', 'app.py', 1, ?, ?, ?, 'HIGH', 'sast', ?)""",
            (fingerprint, status, primeira_vez, primeira_vez, fechado),
        )
        self.conn.commit()

    def test_resumir_metricas_combina_findings_e_historico(self):
        self._inserir("a" * 64, "novo", 10)
        self._inserir("b" * 64, "confirmado", 45)
        self._inserir("c" * 64, "corrigido", 30, fechado_dias_atras=10)
        self._inserir("d" * 64, "corrigido", 30)  # corrigido manualmente, sem timestamp
        elma_db.registrar_importacao(
            self.conn, "org/repo", "semgrep", "sast",
            lidos=4, novos=3, reabertos=0, fechados=1,
            data="2026-02-01T08:00:00+00:00",
        )
        elma_db.registrar_importacao(
            self.conn, "org/repo", "trivy", "sca",
            lidos=2, novos=1, reabertos=0, fechados=0,
            data="2026-02-01T20:00:00+00:00",
        )

        metricas = elma_db.resumir_metricas(self.conn)

        self.assertEqual(metricas["aging"]["abertos"], 2)
        self.assertEqual(metricas["aging"]["idade_maxima_dias"], 45)
        self.assertEqual(metricas["mttr"], {"corrigidos": 2, "amostra": 1, "mttr_dias": 20, "mttr_mediano_dias": 20})
        self.assertEqual(
            metricas["tendencia"],
            [{"data": "2026-02-01", "novos": 4, "fechados": 1, "lidos": 6}],
        )
        self.assertEqual(metricas["sla"]["aplicaveis"], 2)
        self.assertEqual(metricas["sla"]["atrasados"], 1)  # HIGH 45d > 30d

    def test_banco_vazio(self):
        metricas = elma_db.resumir_metricas(self.conn)
        self.assertEqual(metricas["aging"]["abertos"], 0)
        self.assertEqual(metricas["mttr"]["amostra"], 0)
        self.assertEqual(metricas["tendencia"], [])
        self.assertEqual(metricas["sla"]["atrasados"], 0)


if __name__ == "__main__":
    unittest.main()
