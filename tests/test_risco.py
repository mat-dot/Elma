import unittest

from elma.risco import calcular_componentes_score, calcular_score


class RiskScoreTests(unittest.TestCase):
    def test_high_internet_critical_asset_outranks_critical_internal_low_asset(self):
        high_internet_critical = calcular_score(
            {"severidade": "HIGH", "status": "novo"},
            {"exposicao": "internet", "criticidade": 5},
        )
        critical_internal_low = calcular_score(
            {"severidade": "CRITICAL", "status": "novo"},
            {"exposicao": "interna", "criticidade": 1},
        )

        self.assertGreater(high_internet_critical, critical_internal_low)

    def test_false_positive_and_corrected_findings_score_zero(self):
        for status in ("falso_positivo", "corrigido"):
            with self.subTest(status=status):
                self.assertEqual(
                    calcular_score(
                        {"severidade": "CRITICAL", "status": status},
                        {"exposicao": "internet", "criticidade": 5},
                    ),
                    0.0,
                )

    def test_high_confidence_false_positive_suggestion_reduces_only_score(self):
        finding = {"severidade": "HIGH", "status": "novo"}
        ordinary = calcular_score(finding, {"exposicao": "internet", "criticidade": 4})
        suggested = calcular_score(
            {
                **finding,
                "sugestao_ia": "provavel_falso_positivo",
                "confianca_ia": 8,
            },
            {"exposicao": "internet", "criticidade": 4},
        )

        self.assertEqual(suggested, ordinary * 0.5)
        self.assertEqual(finding["status"], "novo")

    def test_score_components_include_fail_closed_unknown_weight(self):
        components = calcular_componentes_score(
            {"severidade": "UNKNOWN", "status": "novo"},
            {"exposicao": "interna", "criticidade": 1},
        )

        self.assertEqual(components["peso_severidade"], 7)
        self.assertEqual(components["fator_criticidade"], 0.6)
        self.assertEqual(components["score"], 4.2)


if __name__ == "__main__":
    unittest.main()