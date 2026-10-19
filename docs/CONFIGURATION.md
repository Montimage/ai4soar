# Configuration reference

AI4SOAR reads its settings from `.env` (copy `.env.example`; for the hackathon / demo
setup, append `docs/hackathon/.env.hackathon.example` as in [INSTALL.md](INSTALL.md), step 4). Only `SHUFFLE_API_TOKEN` and
an LLM key are required; everything below has a working default. With
`docker-compose.local.yml`, the service addresses (MongoDB, NATS, Kafka, Shuffle, Ollama)
are set by the compose file and the `.env` values for them are ignored.

## Server

| Variable | Default | Meaning |
|---|---|---|
| `SERVER_HOST` | `0.0.0.0` | Listen address. `127.0.0.1` behind a reverse proxy |
| `SERVER_PORT` | `5000` | Listen port |
| `SERVER_DEBUG` | `false` | Flask debug mode |
| `SERVER_INTERNAL_HOST` | unset | **Server deployment with host networking only** (`docker-compose.yml`). A second listen address (e.g. `172.17.0.1`, Docker's host address) where Shuffle's containers post incident tickets. Requests that do not come from the machine itself then get only the incidents and mail APIs. Leave unset with `docker-compose.local.yml` |
| `EXAMPLE_ALERTS` | `true` | Load the example alerts of `data/example_alerts.json` into MongoDB at startup (missing ones only) |

## Shuffle

| Variable | Default | Meaning |
|---|---|---|
| `SHUFFLE_API_TOKEN` | — | **Required.** Shuffle → Settings → API key |
| `SHUFFLE_API_BASE_URL` | `http://localhost:5001/api/v1` | Shuffle backend API |
| `SHUFFLE_UI_URL` | `http://localhost:3001` | Shuffle web UI, for the links AI4SOAR shows (e.g. `https://shuffle.example.com`) |
| `SHUFFLE_EXECUTION_MODE` | `shuffle` | How **Execute** builds the workflow: `shuffle` = nodes as built by hand (a step on a machine is a *Run ssh command* node, HTTP steps are *http* nodes); `dry_run` = every command becomes an echo, nothing is changed |
| `SHUFFLE_DEFAULT_WORKFLOW_ID` | unset | Workflow opened when a playbook cannot be converted |

## LLM

| Variable | Default | Meaning |
|---|---|---|
| `LLM_PROVIDER` | `openai` | `anthropic`, `openai` or `ollama` |
| `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` | —, `claude-opus-5-5` | Anthropic |
| `OPENAI_API_KEY`, `LLM_MODEL` | —, `gpt-4o-mini` | OpenAI |
| `OLLAMA_HOST`, `OLLAMA_PORT`, `OLLAMA_MODEL` | `localhost`, `11434`, `llama3.1` | Local Ollama (or `OLLAMA_BASE_URL`) |
| `LLM_TIMEOUT` | `180` | Seconds per LLM call |
| `LLM_PLAYBOOK_MAX_TOKENS` | `16000` | Output budget of Path D (playbook generation) |
| `LLM_VERIFY_MAX_TOKENS` | `8000` | Output budget of the LLM review (Verify) |

### Path B (LLM technique attribution)

| Variable | Default | Meaning |
|---|---|---|
| `LLM_CONFIDENCE_THRESHOLD` | `0.70` | Below this self-reported confidence, Path B's answer is not used (Path D takes over) |
| `LLM_ATTRIBUTION_VOCAB` | `all` | `all` (697 techniques, as benchmarked) or `parents` (222) |
| `LLM_ATTRIBUTION_TOP_K` | `5` | Ranked techniques asked for. 5 is the benchmarked prompt |
| `LLM_ATTRIBUTION_RANKED_K` | = TOP_K | Ranked techniques consulted for playbooks |
| `LLM_REASONING_EFFORT` | `medium` | OpenAI reasoning models only: `minimal`, `medium`, `high` |
| `LLM_ATTRIBUTION_MAX_TOKENS` | `512` | Output budget (raised for reasoning models) |
| `LLM_NUM_CTX` | `16384` | Ollama context window; must fit the ~9.3K-token prompt |

## Orchestration

| Variable | Default | Meaning |
|---|---|---|
| `ORCH_EARLY_EXIT_THRESHOLD` | `0.85` | Confidence of the HIGH tier (auto-executable); `1.0` makes only Path A auto-executable |
| `ORCH_LOW_CONF_THRESHOLD` | `0.50` | Below this, the alert goes to Path D |
| `ORCH_PATH_C_ENABLED` | `true` | Path C (ML similarity to past incidents) |
| `ORCH_PATH_C_DISCOUNT` | `0.85` | Applied when Path C answers alone |
| `ORCH_CONFIRMATION_BONUS` | `0.10` | Added when Paths B and C agree |
| `SIMILARITY_MODEL` | `mlp` | Path C model: `knn`, `lr`, `ovr_lr`, `ovr_svm`, `rf`, `mlp` |
| `PLAYBOOK_LIBRARY_PATH` | `playbooks` | Folder of the CACAO templates |
| `STIX_DATA_PATH` | `../attack-stix-data/…` | Optional full MITRE ATT&CK STIX bundle; without it the bundled `data/mitre_techniques.json` is used |

## Playbooks

Values the playbook templates take from the deployment rather than from the alert.

| Variable | Meaning |
|---|---|
| `INCIDENT_API_URL` | Ticketing API of the "create incident ticket" steps. AI4SOAR provides one (`POST /api/v1/incidents`, tickets pop up on every page): `http://172.17.0.1.nip.io:5000` makes Shuffle's containers reach AI4SOAR on Docker's host address. A host name is used because the CACAO schema accepts no bare IP in a URL; nip.io resolves `172.17.0.1.nip.io` to `172.17.0.1` |
| `MAIL_API_URL` | Mail gateway of the phishing playbook (`POST /api/v1/email/quarantine`); AI4SOAR too |
| `VIRUSTOTAL_API_KEY` | Reputation playbook. A secret: filled into the Shuffle workflow only, never into the CACAO AI4SOAR shows |
| `FIREWALL_SSH_HOST`, `FIREWALL_SSH_PORT`, `FIREWALL_SSH_USER`, `FIREWALL_SSH_PASSWORD` | Reputation playbook: the host it blocks malicious IPs on, over SSH (`sudo iptables`). The password is a secret like the key |

## SOARCA and demo lab

| Variable | Meaning |
|---|---|
| `LAB_HOST_IP` | Address the SOARCA and demo lab containers listen on (compose files). Default `172.17.0.1`: reachable from the machine and its containers, not from the network. Docker Desktop (macOS, Windows): `127.0.0.1` |
| `SOARCA_URL` | SOARCA API; set to enable the dry runs (`http://host.docker.internal:8082` with `docker-compose.local.yml`, `http://172.17.0.1:8082` with host networking) |
| `SOARCA_SANDBOX_PASSWORD` | Password of the dry-run sandbox (also used to build it) |
| `SOARCA_SANDBOX_HOST`, `SOARCA_SANDBOX_USER` | Sandbox address on SOARCA's network (`172.30.250.10`) and user (`ai4soar`) |
| `DEMO_VICTIM_HOST`, `DEMO_VICTIM_PORT`, `DEMO_VICTIM_USER`, `DEMO_VICTIM_PASSWORD` | **Demo lab only.** When set, every SSH step of the workflows AI4SOAR deploys runs on the demo victim web-01, and values the alert lacks are taken from the lab. Leave unset for real use |

## Brokers

| Variable | Default | Meaning |
|---|---|---|
| `NATS_HOST`, `NATS_PORT` | `localhost`, `4222` | NATS (Alerts → Live (NATS)) |
| `KAFKA_BROKERS` | empty | Comma-separated `host:port` list; empty = no Kafka |
| `KAFKA_TOPIC` | `ai4soar.alerts` | Default topic of Alerts → Live (Kafka) |
| `KAFKA_GROUP_ID` | — | Consumer group |
| `KAFKA_SECURITY_PROTOCOL` | `PLAINTEXT` | `PLAINTEXT`, `SSL`, `SASL_PLAINTEXT`, `SASL_SSL` |
| `KAFKA_SSL_CAFILE`, `KAFKA_SSL_CERTFILE`, `KAFKA_SSL_KEYFILE`, `KAFKA_SSL_PASSWORD` | — | TLS (paths as seen by AI4SOAR; mount the files with Docker) |
| `KAFKA_SASL_MECHANISM`, `KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD` | — | SASL: `PLAIN`, `SCRAM-SHA-256`, `SCRAM-SHA-512` |

## MongoDB

| Variable | Default |
|---|---|
| `MONGODB_HOST`, `MONGODB_PORT`, `MONGODB_DATABASE` | `localhost`, `27017`, `ai4soar` |
