# ai4soar
AI-driven Security Orchestration, Automation, and Response (SOAR) platform

## Requirements
- Python 3.10.12

## Installation
- Download AI4SOAR
```bash
git clone https://github.com/Montimage/ai4soar.git
cd ai4soar
```

- Fix prerequisites for the Opensearch database (Elasticsearch) as suggested by [Shuffle's installation guide](https://github.com/shuffle/shuffle/blob/main/.github/install-guide.md).
```bash
mkdir shuffle-database                    # Create a database folder
sudo chown -R 1000:1000 shuffle-database  # IF you get an error using 'chown', add the user first with 'sudo useradd opensearch'
sudo swapoff -a                           # Disable swap
sudo docker compose 
```

- Run docker-compose
```bash
sudo docker-compose up -d
```

- Install dependencies
```bash
pip3 install -r requirements.txt
```

- Run server
```bash
python3 server.py
```

- After installation, go to http://localhost:3001 to set up admin account and sign in with the same credential. [https://github.com/shuffle/shuffle/blob/main/.github/install-guide.md#after-installation](https://github.com/shuffle/shuffle/blob/main/.github/install-guide.md#after-installation)
