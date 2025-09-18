# LoopSOAR

LoopSOAR is a security automation and response framework that ingests alerts, enriches them with threat intelligence, and exports incidents for further analysis.  

## 📦 Requirements

- Python **3.10+**  
- `pip` (Python package manager)  

## 🔧 Installation

1. Clone or download this repository:  
   ```bash
   git clone https://github.com/theycallmecharlie/loopsoar.git
   cd loopsoar
   ```

2. Create and activate a virtual environment (recommended):  
   ```bash
   python -m venv venv
   source venv/bin/activate   # Linux / macOS
   venv\Scripts\activate      # Windows
   ```

3. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```

## 📂 Project Structure

```
loopsoar/
├── main.py                  # Entry point
├── requirements.txt         # Python dependencies
├── src/                     # Core logic (actions, enrichment, triage, export)
├── configs/                 # Configuration files (allowlists, connectors, MITRE mapping)
├── template/                # Jinja2 templates for markdown export
├── alerts/                  # Example alerts from different sources
└── mocks/                   # Mock data for testing
```

## 🧪 Testing with Mock Data

You can simulate incidents using the JSON files provided in the `mocks/` and `alerts/` directories.  

Example:  
```bash
python main.py --alert alerts/sentinel.json
```

