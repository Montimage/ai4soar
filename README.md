# ai4soar

AI-driven Security Orchestration, Automation, and Response (SOAR) platform.

It ingests security alerts (e.g. Wazuh, MMT), attributes them to MITRE ATT&CK
techniques, and recommends parameterized [CACAO](https://www.oasis-open.org/committees/cacao/)
response playbooks through a multi-path orchestration engine (rule-based, ML
similarity, and LLM attribution).

## Requirements

- Python 3.10.12
- Docker + Docker Compose (for the Shuffle SOAR backend / OpenSearch)
- An LLM API key (OpenAI or Anthropic) for the LLM-based attribution path

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Montimage/ai4soar.git
cd ai4soar
```

### 2. Install Python dependencies

We recommend a virtual environment to keep dependencies isolated:

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure the environment

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

At minimum, set your LLM credentials in `.env`:

```bash
LLM_PROVIDER=openai        # openai | anthropic
LLM_MODEL=gpt-4o-mini
OPENAI_API_KEY=sk-...      # or ANTHROPIC_API_KEY=... when LLM_PROVIDER=anthropic
```

Other settings (MongoDB, NATS, Kafka, server host/port, ML model, orchestration
thresholds) have sensible defaults and are documented inline in `.env.example`.

### 4. Start the SOAR backend (Shuffle + OpenSearch)

Fix the OpenSearch prerequisites as described in
[Shuffle's install guide](https://github.com/shuffle/shuffle/blob/main/.github/install-guide.md):

```bash
mkdir -p shuffle-database                 # database folder
sudo chown -R 1000:1000 shuffle-database  # if 'chown' fails, run: sudo useradd opensearch
sudo swapoff -a                           # disable swap (OpenSearch requirement)
```

Then bring up the stack:

```bash
sudo docker compose up -d
```

The Shuffle UI is served at <http://localhost:3001> — open it to set up the admin
account, then sign in. See
[Shuffle: after installation](https://github.com/shuffle/shuffle/blob/main/.github/install-guide.md#after-installation).

## Running AI4SOAR

### Web server / API

```bash
python3 server.py
```

The AI4SOAR web UI and API are served at <http://localhost:5000> (configurable via
`SERVER_HOST` / `SERVER_PORT` in `.env`). The orchestration dashboard lives at
`/orchestration`.

### Orchestration CLI

Run the playbook orchestrator against a single alert without the web server:

```bash
python3 -m core.intelligent_orchestration --help
python3 -m core.intelligent_orchestration --alert path/to/alert.json --k 5
```

Useful flags: `--alert FILE` (alert JSON to process; a sample is used if omitted),
`--k N` (max playbooks, default 5), `--json` (raw JSON output), `--no-save`
(don't write the result file).

## Repository layout

| Path | Description |
|------|-------------|
| `core/intelligent_orchestration/` | Multi-path orchestration engine (normalizer, paths A–D, orchestrator) |
| `core/playbook_library/` | Loads T-code-indexed CACAO playbook templates from `playbooks/` |
| `playbooks/` | CACAO response playbook templates (`tXXXX_*.yaml`), indexed by MITRE technique |
| `data/` | Reference data, including `mitre_techniques.json` (ID → technique name) |
| `web/` | Flask blueprints for the web UI |
| `server.py` | Main Flask server entry point |
