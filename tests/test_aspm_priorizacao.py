# Elma ASPM - Challenge FIAP x PRIDE 2026
# Copyright (C) 2026 Equipe Abutres
# SPDX-License-Identifier: BSD-3-Clause
# Licenciado sob BSD 3-Clause. Veja o arquivo LICENSE.md.

import unittest
from unittest.mock import patch

from elma.priorizacao import (
    _validar_lote,
    gerar_remediacoes_estruturadas,
    gerar_sugestoes_estruturadas,
)


class PrioritizationMarkdownTests(unittest.TestCase):
    def test_parses_json_wrapped_in_markdown_fence(self):
        resposta = '''```json
[
  {
    "fingerprint": "fp-1",
    "sugestao": "provavel_real",
    "confianca": 8,
    "justificativa": "Evidência consistente."
  }
]
```'''

        resultado = _validar_lote(resposta, ["fp-1"])

        self.assertEqual(
            resultado,
            [
                {
                    "fingerprint": "fp-1",
                    "sugestao": "provavel_real",
                    "confianca": 8,
                    "justificativa": "Evidência consistente.",
                }
            ],
        )

    def test_provider_failure_is_indeterminate_by_default_and_raises_in_strict_mode(self):
        finding = {"fingerprint": "fp-1", "arquivo": "src/app.py"}
        with patch(
            "elma.priorizacao._consultar_modelo_ia",
            side_effect=RuntimeError("provider indisponível"),
        ):
            result = gerar_sugestoes_estruturadas(
                [finding], provider="ollama", strict=False
            )
        self.assertEqual(result[0]["sugestao"], "indeterminado")

        with patch(
            "elma.priorizacao._consultar_modelo_ia",
            side_effect=RuntimeError("provider indisponível"),
        ), self.assertRaisesRegex(RuntimeError, "provider indisponível"):
            gerar_sugestoes_estruturadas(
                [finding], provider="ollama", strict=True
            )

    def test_remediation_provider_failure_raises_in_strict_mode(self):
        finding = {"fingerprint": "fp-rem-1", "arquivo": "src/app.py"}
        with patch(
            "elma.priorizacao._consultar_modelo_ia",
            side_effect=RuntimeError("provider indisponível"),
        ), self.assertRaisesRegex(RuntimeError, "provider indisponível"):
            gerar_remediacoes_estruturadas(
                [finding], provider="ollama", strict=True
            )


if __name__ == "__main__":
    unittest.main()
