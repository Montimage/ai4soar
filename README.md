# AI4SOAR

AI-driven Security Orchestration, Automation and Response, by [Montimage](https://www.montimage.eu).

AI4SOAR takes security alerts (Wazuh, MMT, Suricata, Snort, or live from Kafka / NATS),
works out which MITRE ATT&CK techniques they show, and recommends response playbooks in the
standard [CACAO 2.0](https://www.oasis-open.org/committees/cacao/) format, filled with the
alert's values. Playbooks are verified, can be edited, and run on
[Shuffle](https://shuffler.io) (for real) or [SOARCA](https://github.com/COSSAS/SOARCA)
(dry run).

| Path | When | How |
|---|---|---|
| **A** | the alert carries its MITRE technique | direct lookup in the playbook library (no AI), confidence 100% |
| **B** | no technique in the alert | an LLM ranks the most likely techniques; their templates are filled |
| **C** | historical incidents available | ML similarity to past alerts |
| **D** | no template covers the alert | an LLM writes a CACAO playbook for it, verified before use |

Also included:

- **18 CACAO playbook templates** (`playbooks/`), editable in the UI and published to
  Shuffle as reusable workflows
- **Verification**: official CACAO 2.0 schema, workflow structure, bash syntax, a safety
  policy, and an optional LLM review of every command
- **Incident tickets**: AI4SOAR is the ticketing API of the playbooks; tickets pop up in
  the UI
- **Demo lab**: a throwaway Linux server the playbooks really act on, and ten example
  alerts covering paths A, B and D

## Quick start

Everything runs in Docker. Full guide: **[docs/INSTALL.md](docs/INSTALL.md)**.

```bash
# 1. Shuffle, from its own repository (see docs/INSTALL.md for the OpenSearch preparation)
git clone https://github.com/Shuffle/Shuffle && cd Shuffle && docker compose up -d

# 2. AI4SOAR
git clone https://github.com/Montimage/ai4soar.git && cd ai4soar
cp .env.example .env          # set SHUFFLE_API_TOKEN and ANTHROPIC_API_KEY (or another LLM)
docker compose -f docker-compose.local.yml up -d --build
```

Open <http://localhost:5000>, then **Playbooks → Sync to Shuffle**. For the hackathon
setup (SOARCA dry runs, the demo lab), append `docs/hackathon/.env.hackathon.example` to `.env`: step 4 of
the install guide. Demo settings only; production settings are in `.env.example`.

| Document | Content |
|---|---|
| [docs/INSTALL.md](docs/INSTALL.md) | Installation, demo lab, troubleshooting |
| [docs/CONFIGURATION.md](docs/CONFIGURATION.md) | Every `.env` setting |
| [docs/hackathon/](docs/hackathon/README.md) | Four hands-on challenges: a Shuffle workflow, paths A, B and D, verification |

## Deployment files

| File | Use |
|---|---|
| `docker-compose.local.yml` | Your machine: AI4SOAR + MongoDB + NATS + Kafka; reaches Shuffle via `host.docker.internal` |
| `docker-compose.yml` | Server: AI4SOAR with host networking + localhost-only NATS and Kafka; uses the host's MongoDB and Shuffle. Set `SERVER_HOST=127.0.0.1` behind a reverse proxy |
| `docker-compose.soarca.yml` | Optional: SOARCA and its dry-run sandbox |
| `docker-compose.lab.yml` | Optional: the demo victim web-01 |

## Development

Python 3.10:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python3 server.py                    # web UI and API on http://localhost:5000 (/ui/)
python3 -m unittest discover tests
```

Run the orchestrator on one alert without the web server:

```bash
python3 -m core.intelligent_orchestration                                   # Path A example
python3 -m core.intelligent_orchestration --alert "data/example_alerts.json#lab-06"
python3 -m core.intelligent_orchestration --alert path/to/alert.json --k 5 --json
```

## Repository layout

| Path | Content |
|---|---|
| `api/` | REST API (alerts, recommendations, playbooks, verification, incidents) |
| `web/` | Web UI (templates, JS, CSS) |
| `core/intelligent_orchestration/` | Enrichment, paths A–D, the orchestrator |
| `core/playbook_generation/` | Path D generator, CACAO → Shuffle converter |
| `core/playbook_verification/` | Verifier, safety policy, official CACAO schema check |
| `core/orchestration_engine/` | Shuffle deployment and library sync, SOARCA dry runs |
| `core/playbook_library/` | Template loading and editing |
| `playbooks/` | CACAO templates (`tXXXX_*.yaml`), indexed by MITRE technique |
| `data/` | MITRE technique names, CACAO schemas, example alerts, Shuffle app catalog |
| `deploy/` | Images of the SOARCA sandbox and the demo victim |
| `scripts/` | Benchmark / example alert loaders, Shuffle library publishing, metrics |
| `tests/` | Unit tests |
| `docs/` | Installation, configuration, hackathon |
