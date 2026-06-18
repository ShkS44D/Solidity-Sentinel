# 🛡️ Solidity Sentinel | Web3 Smart Contract Security Scanner

![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)
![Flask](https://img.shields.io/badge/Framework-Flask-lightgrey.svg)
![Solidity](https://img.shields.io/badge/Solidity-%5E0.8.0-363636.svg)
![Security](https://img.shields.io/badge/Security-Slither-success.svg)

**Solidity Sentinel** is a next-generation smart contract security scanner built for Ethereum-based Solidity contracts.

Designed for Web3 developers, auditors, and DeFi protocols, it combines the static analysis power of **Slither** with a **custom threat detection engine** to identify vulnerabilities, centralization risks, and unsafe logic before deployment.

## 🚀 Key Features

* **Advanced Static Analysis:** Integrates seamlessly with Slither to catch common vulnerabilities (Reentrancy, Unchecked External Calls, etc.).
* **Custom Threat Engine:** Proprietary algorithms to detect malicious code patterns such as unauthorized minting, backdoors, blacklist functions, hidden fees, and unsafe `selfdestruct` calls.
* **Intelligent Security Scoring:** Automatically calculates a risk score based on the severity and frequency of detected vulnerabilities.
* **Professional UI/UX:** Clean, dark-mode web interface for easy file uploads and readable, actionable security reports.
* **SLOC Analysis:** Source Lines of Code analysis for complexity tracking.
* **Fast & Local:** Runs entirely on your local machine, ensuring your proprietary smart contract code never leaves your environment.

## 🧪 Tech Stack

* **Backend:** Python, Flask, Werkzeug
* **Security & Analysis:** Slither Analyzer, Solidity Compiler (`solc`)
* **Frontend:** HTML5, CSS3 (Dark Mode), JavaScript

## 📋 Prerequisites

Before installing Solidity Sentinel, ensure your system has the following installed:

1. **Python 3.8+** (Tested on 3.12)
2. **Solidity Compiler (`solc`)**: Required by Slither to parse `.sol` files.

## 🛠️ Installation & Setup

Follow these steps to get the scanner running securely in a dedicated local environment.

**1. Clone the Repository**

```bash
git clone https://github.com/ShkS44D/Solidity-Sentinel.git
cd Solidity-Sentinel
```

**2. Create a Virtual Environment**

Creating a virtual environment is highly recommended to isolate project dependencies and prevent version conflicts.

Windows:

```powershell
python -m venv venv
.\venv\Scripts\activate
```

Mac/Linux:

```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install Dependencies**

With your virtual environment activated, install the required Python packages:

```bash
pip install -r requirements.txt
```

**4. Install the Solidity Compiler (solc)**

If you do not already have `solc` installed globally, the easiest way to manage it for Slither is via `solc-select`:

```bash
pip install solc-select
solc-select install 0.8.20  # Install a standard version
solc-select use 0.8.20      # Set it as active
```

## 💻 Usage

**1. Start the Flask Server**

Ensure your virtual environment is active, then run:

```bash
python app.py
```

**2. Access the Dashboard**

Open your web browser and navigate to: `http://127.0.0.1:5000`

**3. Scan a Contract**

* Click "Upload" and select any `.sol` smart contract file.
* Wait for the analysis engine to process the code.
* Review the generated threat report, severity breakdown, and overall security score.

## 📂 Project Structure

```text
Solidity-Sentinel/
│
├── app.py                   # Main Flask application entry point
├── requirements.txt         # Project dependencies
├── uploads/                 # Temporary storage for scanned contracts
├── scanner/                 # Core security modules
│   ├── slither_scan.py      # Slither integration logic
│   └── parser.py            # Threat analysis and report parsing
├── static/                  # CSS, JS, and static assets
└── templates/               # HTML UI templates (index.html, report.html)
```

## 👨‍💻 Author

Developed by **Muhammad Saad Ahmed**

* **Role:** Cybersecurity & Web3 Security Researcher
* **Focus:** Offensive Security, Threat Detection, & Smart Contract Auditing
* **LinkedIn:** [S44D](https://www.linkedin.com/in/shsaadahmed/)


