# SmartGuard – AI-Powered Web Application Firewall (Academic Demo)

SmartGuard is a Flask-based academic project that demonstrates a **hybrid WAF**:
- ML classifier (Random Forest) for payload behavior patterns
- Rule-based signatures for deterministic blocking
- LIME explanations for interpretability

---

## 1) Clean setup (first-time user)

### Prerequisites
- Python 3.9+
- pip

### Install
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run
```bash
python app.py
```

App URL: `http://localhost:5000`

> Notes:
> - `smartguard.db` is auto-created/updated on first run.
> - Required model files must exist in `models/`:
>   - `attack_classifier.pkl`
>   - `feature_extractor.pkl`
>   - `lime_explainer.pkl`

---

## 2) Features to demo in college submission

1. **Home/About pages**
2. **Login/Register**
   - Register with username + email + password
   - Login with either username **or** email
3. **Try Now (Live Demo)**
   - Login/Search/Feedback attack simulation
   - Blocked requests and accepted requests
   - Threat analysis report toggle
4. **Dashboard**
   - Stats cards, charts, logs
   - Formatted UTC timestamps
   - CSV export
5. **Profile**
   - Displays stored email if available

---

## 3) Quick functional verification

Run these checks after starting app:

```bash
python -m py_compile app.py
node --check static/js/main.js static/js/dashboard.js
```

You can also run a lightweight API smoke-check:

```bash
python - <<'PY'
from app import app, init_db
init_db()
with app.test_client() as c:
    print('home', c.get('/').status_code)
    print('try_now', c.get('/try_now').status_code)
    print('analyze', c.post('/analyze', json={'payload':'hello','action_type':'Comment'}).status_code)
PY
```

---

## 4) Project structure

```text
app.py
models/
templates/
static/
datasets/        # research/training artifacts
demo_images/     # report/demo images
requirements.txt
```

---

## 5) Academic disclaimer

This project is for **educational demonstration** and **research presentation** only. It is not hardened for production security use.
