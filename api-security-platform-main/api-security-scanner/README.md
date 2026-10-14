# API Security Platform

[![CI](https://github.com/rahimahkhan/api-security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/rahimahkhan/api-security-scanner/actions/workflows/ci.yml)

A standalone AI-powered API security testing, structure inspection, and anomaly detection platform built with **Python 3.11**, **Flask**, **scikit-learn (Isolation Forest)**, **PyTorch (LSTM + Autoencoder)**, and **SQLAlchemy**.

The platform analyzes live API target URLs without requiring OpenAPI specification documents.

---

## Detection Architecture

1. **Layer 1 — Signature Engine**: Evaluates HTTP request/response headers, parameters, and bodies against deterministic regex rules, missing security header patterns, stack trace error exposures, and PII leaks.
2. **Layer 2 — ML Anomaly Detection**: Extracts 15 response-differential features (`response-diff-14-v1`) — how each probe's response deviates from its baseline: status/size/time changes, error-keyword deltas, reflection checks, content-type changes — and scores them with a trained **Isolation Forest** plus a calibrated tabular ranker. Both models are trained on **686 real (baseline, probe) response pairs** in `ml_pipeline/datasets/response_diff_v1.csv` (live benign traffic + locally collected safe-echo responses); never on payload text.
3. **Layer 3 — Deep Learning**: A PyTorch **Autoencoder** trained on benign response-differential features flags responses that reconstruct poorly; a character-level **LSTM** trained on real response bodies (exploit-effect vs normal) classifies the target's response and contributes up to 15 points. Both models measure the target's behavior — no model in the scoring path is trained on payload text.

---

## Quick Start (Docker)

Launch the platform dashboard along with the local VAmPI target app in one command:

```bash
docker compose up --build
```

- **Web Dashboard**: Access at [http://localhost:5000](http://localhost:5000)
- **VAmPI Vulnerable API**: Running at [http://localhost:5001](http://localhost:5001)

---

## Manual Setup

1. **Clone & Virtual Environment**:
   ```bash
   git clone https://github.com/rahimahkhan/api-security-scanner.git
   cd api-security-scanner/api-security-platform-main/api-security-scanner
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Train Machine Learning & Deep Learning Models** (optional — trained artifacts already ship in `models/`):
   ```bash
   python ml_pipeline/train_csic.py
   ```
   This trains the Isolation Forest, tabular ranker, and autoencoder on `ml_pipeline/datasets/response_diff_v1.csv` (686 real baseline/probe response pairs), and the response-body LSTM on `ml_pipeline/datasets/response_bodies_v1.csv` (130 real captured response bodies from public test services, a ground-truth app, and VAmPI; see `ml_pipeline/build_response_body_dataset.py`). The legacy `training/` scripts target the older CSIC-2010 pipeline and are not used by the shipped models.

4. **Launch Application**:
   - **CLI Inspection Scan**:
     ```bash
     python main.py --url http://localhost:5001
     ```
   - **Web Dashboard**:
     ```bash
     python main.py --dashboard
     ```

---

## Dataset Instructions

- **Live model dataset**: `ml_pipeline/datasets/response_diff_v1.csv` — 686 (baseline, probe) response pairs (434 benign, 252 anomalous), built by `ml_pipeline/build_response_dataset.py` from live benign traffic (httpbin.org, example.com, postman-echo.com) plus locally collected safe-echo responses. This is what the shipped Isolation Forest, tabular ranker, and autoencoder are trained on.
- **Legacy**: the HTTP CSIC 2010 files under `datasets/raw/csic_2010/` belong to the older training pipeline and are **not** used by the shipped models.

---

## Test Target Applications

The scanner can be evaluated against these vulnerable targets:
- **VAmPI** (`erev0s/vampi`): Vulnerable REST API (OWASP API Top 10) running locally on port 5001.
- **DVWA** (`digininja/dvwa`): Damn Vulnerable Web Application.
- **WebGoat** (`webgoat/webgoat`): OWASP Java vulnerable application.

---

## License

No `LICENSE` file is currently included in this repository — add one before distributing.
