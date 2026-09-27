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

Quando os recursos de IA são usados, a Elma suporta dois provedores de LLM,
selecionados por `ELMA_LLM_PROVIDER`:

- `gemini` (padrão): exige `ELMA_GOOGLE_API_KEY`. O modelo padrão é
  `gemini-3.8-flash`; substitua com `ELMA_CLOUD_MODEL`.
- `ollama`: roda contra um servidor Ollama local, então o conteúdo do
  achado (trechos de código, caminhos de arquivo, mensagens de
  vulnerabilidade) nunca sai da máquina. Não exige chave de API. O modelo
  padrão é `llama3.1`; substitua com `ELMA_CLOUD_MODEL`. A URL do servidor
  tem padrão `http://localhost:11434`; substitua com `ELMA_OLLAMA_URL`.
  Exige um servidor Ollama já rodando e acessível, com o modelo alvo já
  baixado localmente.

Os dois provedores respondem pela mesma interface de chat do LangChain,
então `suggest-ia` e `--advice` se comportam de forma idêntica
independente do provedor; só muda o destino do conteúdo do achado (e, no
caso do Ollama, a latência local).

## Comandos

Importar um relatório SARIF:

```powershell
python elma_cap8.py import-sarif scan.sarif
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
achado ativo atinge ou ultrapassa o limite selecionado; o limite padrão é
`HIGH`. Achados marcados como `falso_positivo` são excluídos. Achados com
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
```

O `ci` nunca chama nenhum provedor de LLM — a decisão de pass/fail
continua totalmente determinística e não depende de acesso de rede ao
Gemini ou ao Ollama.

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
workflow deve passar. Um valor `false` inclui os detalhes dos
bloqueadores. Credenciais inválidas retornam 401, requisições malformadas
retornam 400 ou 422, corpos grandes demais retornam 413, e conflitos de
fingerprint retornam 409. O limite de tamanho do corpo é aplicado durante
a leitura da requisição, inclusive quando `Content-Length` está ausente. A
API usa o mesmo banco SQLite e as mesmas limitações de chave única
descritas em `elma_api.py`; não exponha esse serviço v1 publicamente sem
um limite de requisições e controle de acesso em nível de deployment.

O campo opcional `repositorio` no corpo da requisição escopa o
fingerprint da mesma forma que `--repo` faz na CLI; use o mesmo
identificador nos dois caminhos para um dado repositório, para que
ingestões via CLI e via API do mesmo achado resolvam para o mesmo
fingerprint.

O mascaramento de segredos e a filtragem de prompt injection oferecem
controles heurísticos mapeados para OWASP LLM02 (Sensitive Information
Disclosure) e LLM01 (Prompt Injection); a detecção por regex não é
garantia de que todo segredo ou toda injeção sejam detectados.
