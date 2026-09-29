# Elma ASPM

Elma ingere relatórios SARIF 2.1.0 em um repositório local de findings em
SQLite. Oferece triagem determinística de achados, relatórios de postura e
códigos de saída para CI. O Semgrep ou o Trivy rodam separadamente e
fornecem o SARIF de entrada.

## Configuração

```powershell
python -m pip install -r requirements.txt
```

O banco padrão é `elma_findings.db`. Defina `ELMA_DB_PATH` no `.env` ou no
ambiente do processo para usar outro caminho. A triagem assistida por IA
(`findings suggest-ia`) e os relatórios consultivos (`report --advice`) são
opcionais; a importação, a triagem, os relatórios e o CI principais não
exigem nenhum modelo ou credencial de nuvem.

Os recursos de IA (`findings suggest-ia` e `report --advice`) usam Gemini
e exigem `ELMA_GOOGLE_API_KEY` (ou `GOOGLE_API_KEY`). O modelo padrão é
`gemini-2.5-flash`; use `ELMA_CLOUD_MODEL` para selecionar outro modelo
Gemini. O código atual não oferece suporte a Ollama nem a
`ELMA_LLM_PROVIDER`.

## Comandos

Importar um relatório SARIF:

```powershell
python elma_cap8.py import-sarif scan.sarif
```

Uma importação completa retorna código 0. Se o SARIF contiver runs ou
resultados descartados por estrutura inválida, os findings válidos ainda
são importados, a CLI informa as contagens e retorna código 2.

Informe opcionalmente o tipo do scan (`sast`, `sca`, `secrets`, `iac`,
`container`, `k8s` ou `dast`); esse metadado não altera o fingerprint:

```powershell
python elma_cap8.py import-sarif scan.sarif --tipo iac
```

Escopar o fingerprint a um repositório específico (recomendado sempre que
o mesmo banco de findings é compartilhado entre repositórios ou também é
alimentado pela API HTTP, para que ingestões via CLI e via API do mesmo
achado resolvam para o mesmo fingerprint):

```powershell
python elma_cap8.py import-sarif scan.sarif --repo org/repo
```

Revisar findings e inspecionar um pelo fingerprint:

```powershell
python elma_cap8.py findings list --status novo
python elma_cap8.py findings list --tipo iac
python elma_cap8.py findings show FINGERPRINT
```

Gerar sugestões consultivas e estruturadas de priorização com IA:

```powershell
python elma_cap8.py findings suggest-ia --severity HIGH --limit 20
```

As sugestões são só consultivas; elas nunca alteram o status de um finding
automaticamente. Use `--force` para reprocessar sugestões já existentes. Os
achados são processados do mais severo pro menos severo (`CRITICAL` →
`HIGH` → `MEDIUM` → `LOW` → `INFO`); omita `--severity` e use `--limit`
para triar primeiro os achados mais críticos.

Atualizar o status de triagem (`novo`, `confirmado`, `falso_positivo` ou
`corrigido`):

```powershell
python elma_cap8.py findings status FINGERPRINT falso_positivo
```

Gerar um relatório no terminal ou um PDF com selo SHA-256:

```powershell
python elma_cap8.py report
python elma_cap8.py report --format pdf --output posture.pdf
python elma_cap8.py report --advice
```

Avaliar um relatório SARIF no CI. O comando sai com código 1 quando um
achado ativo atinge ou ultrapassa o limite selecionado ou quando o SARIF
contém runs/resultados descartados; o limite padrão é `HIGH`. Achados
marcados como `falso_positivo` são excluídos. Achados com
severidade ausente ou não reconhecida são armazenados como `UNKNOWN` e
reprovam o gate independente de `--fail-on`, para que metadados
incompletos do scanner não passem silenciosamente pelo CI. A Elma
normaliza a severidade durante a importação do SARIF e armazena apenas
`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` ou `UNKNOWN`. Os níveis SARIF
`error`, `warning`, `note` e `none` mapeiam para `HIGH`, `MEDIUM`, `LOW` e
`INFO`; scores numéricos de security-severity mapeiam para a faixa
correspondente. Por isso, `warning` sozinho não atinge o limite padrão
`HIGH`. Bancos existentes são normalizados automaticamente na primeira
abertura após essa atualização.

```powershell
python elma_cap8.py ci scan.sarif
python elma_cap8.py ci scan.sarif --fail-on MEDIUM
python elma_cap8.py ci scan.sarif --repo org/repo
python elma_cap8.py ci scan.sarif --tipo container
```

O `ci` nunca chama um provedor de LLM; a decisão de pass/fail continua
determinística e não depende de acesso de rede ao Gemini.

Use `--db CAMINHO` em qualquer comando para selecionar um banco diferente
do padrão configurado. O parecer de IA é complementar e não afeta as
decisões do CI.

## API SARIF

A API HTTP opcional aceita SARIF em `POST /findings`. Defina `ELMA_API_KEY`
e, se necessário, `ELMA_DB_PATH` antes de subir o serviço:

```powershell
uvicorn elma_api:app --host 0.0.0.0 --port 8000
```

Envie `Authorization: Bearer <ELMA_API_KEY>` e um corpo JSON contendo
`sarif`; `fail_on` tem padrão `HIGH`. Uma avaliação concluída sempre
retorna HTTP 200; inspecione o campo `aprovado` do JSON pra decidir se o
gate de vulnerabilidades e SARIF deve passar. Um valor `false` inclui os
detalhes dos bloqueadores. Se `fechar_ausentes=true`, a resposta também
informa `fechamento_bloqueado` e `motivo_fechamento`; isso indica fechamento
pendente e requer ação do operador, sem alterar o significado de `aprovado`.
Para solicitar fechamento, informe `repositorio` e `tipo_scan`; a API retorna
422 se qualquer um estiver ausente. Um scan sem findings só fecha ausentes
quando a ferramenta atesta sucesso explicitamente em uma invocação SARIF.
O Trivy não inclui esse atestado na saída SARIF, então o workflow da Elma o
acrescenta somente se o step do scanner terminar com sucesso. A proteção de
fechamento em massa continua ativa para scans sem sucesso explícito; scans
sem findings e sem esse atestado não são elegíveis para fechamento.
Credenciais inválidas retornam 401, requisições malformadas retornam 400 ou
422, corpos grandes demais retornam 413, e conflitos de fingerprint retornam
409. O limite de tamanho do corpo é aplicado durante
a leitura da requisição, inclusive quando `Content-Length` está ausente. A
API usa o mesmo banco SQLite e as mesmas limitações de chave única
descritas em `elma_api.py`; não exponha esse serviço v1 publicamente sem
um limite de requisições e controle de acesso em nível de deployment.

O campo opcional `repositorio` no corpo da requisição escopa o
fingerprint da mesma forma que `--repo` faz na CLI; use o mesmo
identificador nos dois caminhos para um dado repositório, para que
ingestões via CLI e via API do mesmo achado resolvam para o mesmo
fingerprint.

O painel calcula `ultimo_scan` pelo histórico de importações, inclusive
quando um scan válido não encontra findings. Importações também registram
`descartados`, a soma de runs e resultados ignorados por estrutura inválida.
O campo `lidos` conta somente resultados SARIF válidos que foram analisados.

O campo opcional `tipo_scan` aceita `sast`, `sca`, `secrets`, `iac`,
`container`, `k8s` ou `dast`; por exemplo:
`{"sarif": {...}, "tipo_scan": "iac"}`.
Esse metadado também não altera o fingerprint.

O mascaramento de segredos e a filtragem de prompt injection oferecem
controles heurísticos mapeados para OWASP LLM02 (Sensitive Information
Disclosure) e LLM01 (Prompt Injection); a detecção por regex não é
garantia de que todo segredo ou toda injeção sejam detectados.

## Tickets GitHub

O módulo `elma_tickets.py` mantém a integração de issues isolada da API e
da CLI. A confirmação manual de um finding `CRITICAL` pela dashboard/API
ou pelo comando `findings status FINGERPRINT confirmado` tenta criar a
issue no repositório `owner/repo` correspondente. Findings de outras
severidades não criam issue. A ingestão SARIF não dispara criação.
O endpoint retorna o resultado no campo `ticket`; a CLI e a dashboard
mostram o resultado, inclusive dry-run, falha ou motivo de inelegibilidade.

Configure `ELMA_GITHUB_TOKEN` com permissão de escrita de issues apenas nos
repositórios necessários. `ELMA_TICKETS_ATIVO` é `false` por padrão e
`ELMA_TICKETS_DRY_RUN` é `true` por padrão; a ativação real exige habilitar
o interruptor e desligar o dry-run explicitamente. `ELMA_DASHBOARD_URL`
define a base do painel; se omitida, usa `ELMA_API_URL` ou
`http://localhost:8000`. Findings marcados como possível segredo recebem
corpo e título genéricos, sem mensagem, trecho, regra ou caminho do scanner.
Todo finding do tipo `secrets` recebe o mesmo tratamento, mesmo quando a
detecção heurística de segredo não é acionada. A criação usa uma reserva
atômica por finding; reservas abandonadas expiram após dez minutos e podem
ser retomadas com reconciliação pelo fingerprint.

Não coloque tokens em arquivos versionados. As credenciais locais devem
ficar apenas no `.env` ignorado pelo Git ou no gerenciador de secrets do
ambiente de execução.