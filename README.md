# 🛡️ AI-Powered Network Intrusion & Cyber Threat Detection System

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Jupyter](https://img.shields.io/badge/Notebook-Jupyter-orange.svg)](https://jupyter.org/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.3%2B-F7931E.svg)](https://scikit-learn.org/)
[![Cybersecurity](https://img.shields.io/badge/Domain-Cybersecurity%20%26%20SOC-red.svg)]()

An end-to-end Machine Learning Intrusion Detection System (IDS) developed in a comprehensive **Jupyter Notebook**. Designed for Security Operations Centers (SOC) to detect, classify, and mitigate cyberattacks in real-time across both known threat vectors and unknown zero-day anomalies.

---

## 🎯 Threat Classification Taxonomy

The system classifies network connection telemetry across 5 critical categories:

| Threat Category | Description & Attack Vectors | Real-World Examples | SOC Action Level |
|---|---|---|---|
| 🟢 **Normal** | Legitimate user web, DNS, and application traffic | Standard HTTP/HTTPS browsing, routine DNS queries | Allow Connection |
| 🟡 **Probe** | Port scanning, host sweeps, and reconnaissance probing | Nmap scanning, Satan, IP Sweep | Medium (Log & Honeypot) |
| 🔴 **DoS** | Denial of Service flooding aiming to exhaust system resources | SYN Flood, Neptune, Smurf, Ping of Death | High (Drop & Rate-Limit) |
| 🚨 **R2L** | Remote-to-Local unauthorized access attempts | SSH/FTP password brute-forcing, dictionary attacks | Critical (Isolate Host & MFA) |
| 🔥 **U2R** | User-to-Root privilege escalation and local root exploits | Buffer overflow, local rootkits, loadmodule | Critical (Emergency Termination) |

---

## 🚀 Key Highlights & Workflow

1. **Exploratory Data Analysis (EDA):**
   - Class imbalance visualization across benign and malicious traffic.
   - Network transport protocol usage (TCP, UDP, ICMP) by attack vector.
   - Log-scale source vs. destination payload byte distributions.
   - TCP flag signatures (`SF` normal establishment vs. `S0` SYN floods vs. `REJ` port scans).
   - Telemetry correlation heatmap.

2. **Zero-Day Anomaly Detection (Unsupervised):**
   - Implements **Isolation Forest** to isolate anomalous network behavior *without* requiring historical training labels, catching zero-day threats out-of-the-box.

3. **Multi-Model Supervised Benchmarking:**
   - Evaluates **Logistic Regression**, **Decision Tree**, **Random Forest**, and **Gradient Boosting**.
   - Generates full confusion matrices, precision, recall, and weighted F1-scores.

4. **Explainable Cyber AI (XAI):**
   - Ranks the top 15 network telemetry features driving intrusion alerts (e.g. `diff_srv_rate`, `serror_rate`, `num_failed_logins`).

5. **Live Packet Threat Inspector (SOC Simulator):**
   - Interactive function that accepts simulated streaming network packets and outputs:
     - Predicted threat category
     - Confidence score (%)
     - Threat severity level (BENIGN, MEDIUM, HIGH, CRITICAL)
     - Automated SOC incident response playbook

---

## 📊 Benchmark Results

| Model Architecture | Accuracy | Precision | Recall | F1-Score |
|---|---|---|---|---|
| 🏆 **Random Forest** | **99.6%** | **99.6%** | **99.6%** | **0.996** |
| 🥈 **Gradient Boosting** | 99.4% | 99.4% | 99.4% | 0.994 |
| 🥉 **Decision Tree** | 98.9% | 98.9% | 98.9% | 0.989 |
| 📌 **Logistic Regression** | 95.8% | 95.7% | 95.8% | 0.957 |

---

## 📁 Repository Structure

```
network-intrusion-detection-ai/
├── data/
│   └── network_traffic.csv              # Benchmark network telemetry dataset (8,000+ records)
├── notebooks/
│   └── Network_Intrusion_Detection.ipynb # Complete master Jupyter Notebook with pre-rendered charts
├── src/
│   ├── __init__.py
│   ├── data_generator.py                # Statistical network traffic synthesizer
│   ├── preprocessor.py                  # Feature encoding, scaling & stratified split pipeline
│   └── threat_detector.py               # Model benchmarking & live packet inspection engine
├── models/
│   ├── best_intrusion_detector.joblib   # Serialized champion model weights
│   └── preprocessor.joblib              # Serialized column transformer
├── run_notebook.bat                     # 1-Click double-click launcher for Jupyter Notebook on Windows
├── push_to_github.bat                   # 1-Click script to push updates to GitHub
├── build_notebook.py                    # Notebook generator script
├── requirements.txt                     # Python package dependencies
├── .gitignore                           # Git configuration
└── README.md                            # Project documentation
```

---

## 💻 Quick Start & Running the Project

### 1. Launch Jupyter Notebook (1-Click)
Double-click:
```
run_notebook.bat
```
*(Or run in your terminal:)*
```bash
python -m notebook notebooks/Network_Intrusion_Detection.ipynb
```

### 2. Run Data Pipeline Independently
To generate fresh data or train models via scripts:
```bash
# Generate synthetic benchmark dataset
python src/data_generator.py

# Re-build and pre-render notebook
python build_notebook.py
python -m nbconvert --to notebook --execute --inplace notebooks/Network_Intrusion_Detection.ipynb
```

---

## 🌐 Publish to GitHub

1. Create a new empty repository named **`network-intrusion-detection-ai`** at:  
   👉 **[https://github.com/new](https://github.com/new)**  
   *(Leave "Initialize with README" unchecked)*

2. Double-click:  
   📁 `push_to_github.bat`  
   *(Or run `git push -u origin main`)*

---

## 👤 Author
**Salman Ali**  
- GitHub: [@Salmanali9675](https://github.com/Salmanali9675)
