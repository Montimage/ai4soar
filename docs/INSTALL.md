# Running AI4SOAR locally with Docker

This guide sets up AI4SOAR on your machine with everything needed to use all its features
and to follow the [hackathon challenges](hackathon/README.md):

| Stack | What it runs | Where it comes from | URL |
|---|---|---|---|
| **Shuffle** | SOAR engine that executes playbooks | [Shuffle's own repository](https://github.com/Shuffle/Shuffle) | <http://localhost:3001> |
| **AI4SOAR** | web UI/API, MongoDB, NATS, Kafka | this repository (`docker-compose.local.yml`) | <http://localhost:5000> |
| SOARCA *(optional)* | TNO's CACAO orchestrator, for dry runs | `docker-compose.soarca.yml` | — |
| Demo lab *(optional)* | **web-01**, a throwaway Linux server the playbooks act on | `docker-compose.lab.yml` | — |

Steps 1–3 give you AI4SOAR with Shuffle. Step 4 adds the dry runs and the demo lab of the
hackathon. The commands are written for Linux; see the note at the end for Docker
Desktop (macOS, Windows).

## Requirements

- Docker with Compose v2 (`docker compose version`)
- **8 GB RAM** or more (OpenSearch alone reserves 2 GB; on Docker Desktop give Docker at
  least 6 GB under *Settings → Resources*), ~10 GB free disk space
- Free ports: `3001`, `3443`, `5001`, `9200` (Shuffle), `5000`, `4222`, `9094` (AI4SOAR)
- An LLM: an Anthropic or OpenAI API key, or a local [Ollama](https://ollama.com)
- For the reputation playbook: a free [VirusTotal](https://www.virustotal.com) API key

## 1. Install Shuffle

```bash
git clone https://github.com/Shuffle/Shuffle
cd Shuffle
mkdir -p shuffle-database
sudo chown -R 1000:1000 shuffle-database   # if this fails: sudo useradd opensearch, then retry
sudo swapoff -a
sudo sysctl -w vm.max_map_count=262144
docker compose up -d
```

The first start takes a few minutes. Open <http://localhost:3001>, register the admin
account and sign in. If the page doesn't load, check `docker compose logs
shuffle-opensearch` (usually `vm.max_map_count` or the folder permissions above). More:
[Shuffle install guide](https://github.com/Shuffle/Shuffle/blob/main/.github/install-guide.md).

In Shuffle:

- **API key**: profile menu (top right) → **Settings** → copy the **API key**.
- **VirusTotal app**: **Apps** → search *VirusTotal* → activate **Virustotal v3**. The
  reputation playbook uses it (Shuffle Tools and http, the other apps AI4SOAR uses, are
  there by default).

## 2. Install AI4SOAR

```bash
git clone https://github.com/Montimage/ai4soar.git
cd ai4soar
cp .env.example .env
```

In `.env`, set the two required values:

```bash
SHUFFLE_API_TOKEN=<the API key from Shuffle>
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

(OpenAI or Ollama instead: see [CONFIGURATION.md](CONFIGURATION.md).) The service
addresses don't need changing: the compose file sets the in-container values.

```bash
docker compose -f docker-compose.local.yml up -d --build
```

This starts MongoDB, NATS, a single-node Kafka broker and AI4SOAR. A one-off `seed`
container loads the 37-alert benchmark (MMT, Snort, Suricata); AI4SOAR itself adds the ten
example alerts of `data/example_alerts.json`. Open <http://localhost:5000>.

### Check it works

```bash
docker compose -f docker-compose.local.yml ps -a        # ai4soar, mongodb, nats, kafka: Up · seed: Exited (0)
curl http://localhost:5000/api/benchmark_alerts/stats   # 37 alerts by tool and tactic
curl http://localhost:5000/api/playbooks                # your Shuffle workflows (401 = wrong SHUFFLE_API_TOKEN)
```

The **Dashboard** (Integration Status) shows each integration in green or, with the reason,
in red.

## 3. Publish the playbook library to Shuffle

**Playbooks** → **Sync to Shuffle**. Each of the 18 CACAO templates becomes a Shuffle
workflow named *AI4SOAR library · …*; the cards then show **In Shuffle**. Run it again
after changing a template or a playbook setting (step 4): changed workflows are updated,
credentials you entered in Shuffle are kept.

From here you can use AI4SOAR: open an alert on the **Alerts** page, **Run
Orchestration**, then **Workflow**, **Verify** and **Execute** on a recommended playbook.
Without the demo lab, the playbooks act on the hosts the alerts name: fill **Host** and
the credentials on their *Run ssh command* nodes in Shuffle before running them. Settings
for your ticketing system, mail gateway, firewall and VirusTotal: `.env.example` and
[CONFIGURATION.md](CONFIGURATION.md).

## 4. Optional: the hackathon setup (SOARCA dry runs and the demo lab)

Two stacks next to AI4SOAR, and the settings of
[`docs/hackathon/.env.hackathon.example`](hackathon/.env.hackathon.example):

- **SOARCA** ([COSSAS/SOARCA](https://github.com/COSSAS/SOARCA), `docker-compose.soarca.yml`)
  runs the CACAO playbooks natively: the Execute dialog then offers **SOARCA (dry run)**,
  each step printing on a sandbox what it would do.
- **web-01** (`docker-compose.lab.yml`) is an empty Debian server in a container that the
  playbooks really act on: users alice, bob and dev, a suspicious `/tmp/payload.sh`, a
  crypto-miner and its crontab, a hidden setuid file, Postfix, its own firewall. Firewall
  rules, locked accounts and killed processes all stay inside it. Every SSH step of the
  workflows AI4SOAR deploys runs on it (values an alert lacks are taken from the lab), so
  all templates complete with visible effects.
- AI4SOAR becomes the ticketing and mail API of the playbooks (their tickets pop up in the
  UI), and the reputation playbook blocks malicious IPs on the SOARCA sandbox.

```bash
sed "/^#/! s/CHANGE_ME/$(openssl rand -hex 16)/" docs/hackathon/.env.hackathon.example >> .env
# then edit .env: VIRUSTOTAL_API_KEY=<your VirusTotal API key>
docker compose -f docker-compose.soarca.yml --env-file .env up -d --build
docker compose -f docker-compose.lab.yml --env-file .env up -d --build
docker compose -f docker-compose.local.yml up -d ai4soar      # recreate: picks up .env
```

Then **Playbooks → Sync to Shuffle** again (the library workflows get the new settings).
The Dashboard shows SOARCA under *SOAR Platform*. SOARCA, its sandbox and web-01 listen on
`172.17.0.1` (Docker's host address, `LAB_HOST_IP`): reachable from your machine and its
containers, not from the network.

**These settings are for the demo only.** With `DEMO_VICTIM_*` set, playbooks act on
web-01 whatever host the alert names. For real use remove them: playbooks then act on the
hosts the alerts name, with the credentials operators fill in Shuffle, and the ticketing,
mail and firewall settings point at your own systems (`.env.example`).

**Reset web-01** to its starting state (before a demo, or after re-running an alert whose
playbook removed what it acts on):

```bash
docker compose -f docker-compose.lab.yml --env-file .env up -d --force-recreate
```

The example alerts on top of the Alerts page are about web-01 and cover paths A, B and D;
[the hackathon challenges](hackathon/README.md) walks through them. `docker compose -f
docker-compose.local.yml exec ai4soar python3 scripts/load_example_alerts.py --force`
restores them as shipped; `EXAMPLE_ALERTS=false` stops loading them.

## Live alerts (Kafka, NATS)

- **Kafka**: *Alerts → Live (Kafka)*, topic `ai4soar.alerts`, **Connect** (*from
  beginning* replays what the topic holds). Publish through AI4SOAR:

  ```bash
  curl -X POST 'http://localhost:5000/api/publish_alerts?topic=ai4soar.alerts' \
       -H 'Content-Type: application/json' \
       -d '{"rule":{"description":"SSH brute force","level":10},"data":{"srcip":"10.0.0.5"}}'
  ```

  or from your own producer at `localhost:9094`. Live alerts are stored in MongoDB too.
- **NATS**: same with subject `ai4soar.alerts` and the
  [NATS CLI](https://github.com/nats-io/natscli):
  `nats pub ai4soar.alerts '{"rule":{"description":"SSH brute force","level":10},"data":{"srcip":"10.0.0.5"}}'`

## Useful commands

```bash
docker compose -f docker-compose.local.yml logs -f ai4soar      # follow app logs
docker compose -f docker-compose.local.yml up -d ai4soar        # after editing .env (recreates it)
docker compose -f docker-compose.local.yml up -d --build        # after git pull
docker compose -f docker-compose.local.yml down                 # stop (keeps data)
docker compose -f docker-compose.local.yml down -v              # stop and delete MongoDB data
```

`restart` keeps the old environment: after editing `.env`, use `up -d`. Execution logs are
written to `./output`.

## Docker Desktop (macOS, Windows)

`172.17.0.1` is the Docker host address on Linux only. On Docker Desktop, after appending
`docs/hackathon/.env.hackathon.example`, add `LAB_HOST_IP=127.0.0.1` to `.env` and use
`host.docker.internal` instead of `172.17.0.1` in `DEMO_VICTIM_HOST`, `FIREWALL_SSH_HOST`
and `INCIDENT_API_URL` / `MAIL_API_URL`. For OpenSearch on Windows, run
`wsl -d docker-desktop sysctl -w vm.max_map_count=262144` in PowerShell. This variant has
not been tested end to end.