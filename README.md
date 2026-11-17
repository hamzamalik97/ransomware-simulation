# Controlled Ransomware Simulation Lab

A Docker-based cybersecurity lab built with Python and Flask to demonstrate ransomware-related workflows in an isolated environment. The project combines network reconnaissance, controlled access demonstrations, file encryption, recovery, and a web-based monitoring dashboard.

> **Disclaimer:** This project is intended strictly for educational purposes and authorized cybersecurity testing in an isolated lab. Do not use it against systems, networks, or data without explicit permission.

## 1. Project Overview

The Controlled Ransomware Simulation Lab demonstrates selected stages of a ransomware attack lifecycle in a controlled Docker environment.

It provides a web dashboard through which users can interact with lab components, discover target files, execute encryption and recovery operations, and explore controlled network-access demonstrations.

The simulation is designed to help cybersecurity students understand attack workflows, defensive monitoring concepts, and the importance of secure recovery procedures.

## 2. Features

- Flask-based web dashboard.
- Docker-based victim environment.
- Network host discovery and service assessment.
- Controlled SSH connectivity demonstration using Paramiko.
- Controlled HTTP connectivity demonstration.
- AES-256-GCM file encryption.
- Recovery-key generation and file recovery.
- Simulated dictionary-based credential demonstration.
- API endpoints for lab operations.
- Sample dictionary data for demonstration.

## 3. Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic |
| Flask | Web dashboard and API |
| Docker | Isolated victim environment |
| Docker SDK | Container interaction |
| Cryptography | AES-256-GCM encryption |
| Paramiko | SSH connectivity demonstration |
| HTML | Dashboard structure |
| CSS | Dashboard styling |

## 4. Project Architecture

The application consists of four main Python modules:

- `app.py`: Main Flask application, dashboard routes, and API endpoints.
- `recon_engine.py`: Host discovery, service scanning, and service assessment.
- `lab_controller.py`: Controlled file discovery, reading, writing, and deletion inside the victim container.
- `ransomware_engine.py`: Encryption-key generation, key storage, encryption, and decryption.

The frontend consists of:

- `templates/dashboard.html`
- `static/style.css`

The demonstration dictionary is stored in:

- `dictionaries/demo_dictionary.txt`

## 5. Simulation Workflow

1. The Flask dashboard starts locally.
2. The application communicates with the designated Docker victim container.
3. The reconnaissance module discovers hosts and assesses available services.
4. Controlled access demonstrations test SSH and HTTP connectivity.
5. The lab controller discovers files in the victim's designated data directory.
6. The ransomware engine generates an AES-256 key and encrypts selected files using AES-GCM.
7. Encrypted files are represented using the `.locked` extension.
8. The recovery operation uses the stored key to decrypt files and restore their original contents.

The lock-screen operation creates a demonstration marker file. It does not lock the host operating system.

## 6. Encryption and Recovery

The project uses AES-256-GCM through Python's `cryptography` library.

- A 256-bit encryption key is generated.
- A 12-byte nonce is generated for each encryption operation.
- AES-GCM encrypts the file contents and provides authenticated encryption.
- The nonce is stored alongside the encrypted data.
- The recovery operation uses the original key and nonce to decrypt the data.

**Important:** The current implementation stores the recovery key locally in `recovery_key.json` in Base64-encoded form. Base64 is encoding, not encryption. This is a lab implementation, not production-grade key management.

Never upload the recovery key to GitHub.

## 7. Installation

### Prerequisites

- Linux system
- Python 3
- Docker Engine
- A running Docker victim container configured for this lab

### Clone the repository

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd ransomware-lab
```

### Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the application

```bash
python app.py
```

Open the dashboard in your browser:

```text
http://127.0.0.1:5000
```

The Docker daemon must be running, and the configured victim container must be available.

## 8. API Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Dashboard |
| `/api/status` | GET | Lab status |
| `/api/recon/hosts` | GET | Host discovery |
| `/api/recon/scan` | GET | Network scanning |
| `/api/recon` | GET | Reconnaissance |
| `/api/discover` | GET | File discovery |
| `/api/encrypt` | GET | File encryption |
| `/api/lock` | GET | Demonstration lock marker |
| `/api/recover` | GET | File recovery |
| `/api/reset` | GET | Reset lab data |
| `/api/recon/assess` | GET | Service assessment |
| `/api/ssh-auth-test` | POST | Controlled SSH test |
| `/api/dictionary-demo` | POST | Simulated dictionary demonstration |
| `/api/attack` | GET / POST | Controlled initial-access workflow |

## 9. Important Limitations

- The project is designed for an isolated lab environment.
- The victim container name is configured in the application as `locker-victim`.
- The target data directory is configured as `/locker_data`.
- The dictionary demonstration simulates candidate matching; it is not a real password-cracking or SSH brute-force operation.
- The lock operation creates a text marker; it does not lock the host operating system.
- Recovery depends on retaining the correct encryption key.
- The current application is an educational prototype, not a production ransomware or enterprise security platform.

## 10. Security and Ethical Use

Use this project only in a controlled environment that you own or have permission to test.

- Do not target public IP addresses or unauthorized systems.
- Do not use real personal or organizational files as test data.
- Keep recovery keys and credentials private.
- Do not expose the dashboard or Docker daemon to public networks.
- Review all configuration before running lab operations.

## 11. Future Improvements

Potential improvements include:

- Enhanced audit logging.
- Better recovery-key management.
- More comprehensive error handling.
- Additional defensive monitoring and detection demonstrations.
- Automated lab setup and validation.
- Improved reporting and event visualization.

## 12. Author and Educational Purpose

Developed as a cybersecurity educational project to explore ransomware workflows, network reconnaissance, controlled access, cryptographic operations, and file recovery using Python, Flask, and Docker.

---

**Project:** Controlled Ransomware Simulation Lab  
**Primary Language:** Python  
**Environment:** Docker-based isolated lab  
**Purpose:** Cybersecurity education and authorized testing
