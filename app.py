import os
import sqlite3
import pickle
import numpy as np
import re
import joblib
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
import lime.lime_tabular
import warnings

# Suppress sklearn UserWarnings
warnings.filterwarnings("ignore", category=UserWarning)

app = Flask(__name__)
app.secret_key = 'smartguard_academic_demo_key_secret_123'
app.config['DATABASE'] = 'smartguard.db'

# --- 1. Database Setup ---
def get_db():
    # Increase timeout to 10 seconds to handle concurrent locks
    conn = sqlite3.connect(app.config['DATABASE'], timeout=10)
    conn.row_factory = sqlite3.Row
    # Enable Write-Ahead Logging for better concurrency
    conn.execute('PRAGMA journal_mode=WAL;')
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action_type TEXT,
                payload TEXT,
                result TEXT,
                confidence REAL,
                detected_type TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Lightweight migration for older DBs created before the email column existed.
        user_columns = [row['name'] for row in db.execute('PRAGMA table_info(users)').fetchall()]
        if 'email' not in user_columns:
            db.execute('ALTER TABLE users ADD COLUMN email TEXT')

        # # Demo reset requirement: start each run with a clean users/logs state.
        # db.execute('DELETE FROM logs')
        # db.execute('DELETE FROM users')

        db.commit()
        db.close() # Explicitly close the init connection


@app.template_filter('format_log_timestamp')
def format_log_timestamp(ts_value):
    """Format DB timestamps consistently for dashboard UI (UTC display)."""
    if not ts_value:
        return "-"

    ts_str = str(ts_value).strip()
    parse_formats = [
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
    ]

    parsed = None
    for fmt in parse_formats:
        try:
            parsed = datetime.strptime(ts_str, fmt)
            break
        except ValueError:
            continue

    if parsed is None:
        return ts_str

    parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.strftime('%d %b %Y, %H:%M:%S UTC')

# --- 2. ML Model Loading ---
MODEL_DIR = 'models'
try:
    clf = joblib.load(os.path.join(MODEL_DIR, 'attack_classifier.pkl'))
    scaler = joblib.load(os.path.join(MODEL_DIR, 'feature_extractor.pkl'))
    lime_params = joblib.load(os.path.join(MODEL_DIR, 'lime_explainer.pkl'))
    explainer = lime.lime_tabular.LimeTabularExplainer(
        training_data=lime_params['training_data'],
        feature_names=lime_params['feature_names'],
        class_names=lime_params['class_names'],
        mode=lime_params['mode']
    )
    print("✅ ML Models and Explainer loaded successfully.")
except Exception as e:
    print(f"⚠️ Error loading models: {e}")
    clf, scaler, explainer = None, None, None

def get_harm_explanation(detected_type):
    """
    Returns a manual academic explanation of the potential harm for the detected attack type.
    """
    kb = {
        "SQL Injection": "SQL Injection allows attackers to interfere with the queries an application makes to its database. HARM: Unauthorized viewing of data (passwords, emails), data modification (changing balances), or complete deletion of tables.",
        "XSS": "Cross-Site Scripting (XSS) enables attackers to inject malicious scripts into web pages viewed by other users. HARM: Session hijacking (stealing cookies), unauthorized redirects, defacing websites, or capturing keystrokes.",
        "Path Traversal": "Path Traversal involves manipulating file paths to access files stored outside the web root folder. HARM: Exposure of critical system files like /etc/passwd, configuration files, or source code.",
        "Command Injection": "Command Injection allows execution of arbitrary operating system commands on the server. HARM: Full server compromise, installation of malware/ransomware, and pivoting to internal networks.",
        "Normal": "The input follows standard structural patterns expected for this field. No malicious intent was detected in the payload syntax."
    }
    
    # Simple keyword matching for the KB
    d_type = detected_type.lower()
    if "sql" in d_type: return kb["SQL Injection"]
    if "xss" in d_type or "script" in d_type: return kb["XSS"]
    if "path" in d_type or "traversal" in d_type: return kb["Path Traversal"]
    if "command" in d_type or "cmd" in d_type: return kb["Command Injection"]
    
    return kb["Normal"]

def extract_features_from_payload(payload, action_type):
    payload_str = str(payload)
    
    # Feature extraction logic matches training notebook
    sql_pattern = re.compile(r'(union|select|insert|update|delete|drop|admin|or|and|1=1)', re.IGNORECASE)
    sql_keywords = len(sql_pattern.findall(payload_str))
    
    xss_pattern = re.compile(r'(<script|javascript:|onload|onerror|alert|img src)', re.IGNORECASE)
    xss_count = len(xss_pattern.findall(payload_str))
    
    special_chars = len(re.findall(r'[^a-zA-Z0-9\s]', payload_str))
    has_encoded = 1 if '%' in payload_str else 0

    # Simulation context
    # REVERTED TO REALISTIC VALUES (NOT ZERO) TO STABILIZE ML MODEL
    if action_type == 'Login':
        base_url_len, path_depth, num_params = 35, 2, 2
    elif action_type == 'Search':
        base_url_len, path_depth, num_params = 40, 2, 1
    elif action_type == 'Comment':
        base_url_len, path_depth, num_params = 45, 3, 1
    else:
        base_url_len, path_depth, num_params = 30, 1, 0

    features = {
        'url_length': base_url_len + len(payload_str),
        'num_parameters': num_params,
        'special_char_count': special_chars,
        'sql_keyword_count': sql_keywords,
        'xss_pattern_count': xss_count,
        'path_depth': path_depth,
        'has_encoded_chars': has_encoded,
        'request_rate': 0.5,           # Reverted to average
        'response_code': 200,          
        'user_agent_entropy': 3.5,     # Reverted to average (3.5 is typical)
        'payload_size': len(payload_str),
        'cookie_length': 120,          # Reverted to average
        'referer_present': 1,          # Reverted to typical browser behavior
        'time_gap': 0.5                # Reverted to average
    }
    
    feature_order = [
        'url_length', 'num_parameters', 'special_char_count', 'sql_keyword_count',
        'xss_pattern_count', 'path_depth', 'has_encoded_chars', 'request_rate',
        'response_code', 'user_agent_entropy', 'payload_size', 'cookie_length',
        'referer_present', 'time_gap'
    ]
    return [features[f] for f in feature_order]

def hybrid_decision_engine(ml_pred, ml_conf, payload, raw_features_dict):
    """
    Combines ML prediction with hard-coded safety rules.
    Includes a Safety Override for clean inputs to prevent False Positives.
    """
    payload_lower = payload.lower()
    
    # 1. Hard Rules (Attack Signatures)
    critical_sql = ["union select", "1=1", "waitfor delay", "' or '", "drop table", "select * from"]
    critical_xss = ["<script>", "javascript:", "onerror=", "<img src=x", "alert("]
    critical_cmd = ["cat /etc/passwd", "; ls", "| netstat", "system("]
    critical_path = ["../", "..\\", "/etc/passwd", "win.ini"]

    rule_verdict = "Normal"
    for p in critical_sql:
        if p in payload_lower: rule_verdict = "SQL Injection"; break
    for p in critical_xss:
        if p in payload_lower: rule_verdict = "XSS Attempt"; break
    for p in critical_cmd:
        if p in payload_lower: rule_verdict = "Command Injection"; break
    for p in critical_path:
        if p in payload_lower: rule_verdict = "Path Traversal"; break
            
    final_decision = "ACCEPTED"
    final_type = "Normal"
    
    # 2. SAFETY OVERRIDE (False Positive Prevention)
    
    # A. Structural Cleanliness (No suspicious tokens at all)
    is_clean_strict = (
        raw_features_dict['sql_keyword_count'] == 0 and 
        raw_features_dict['xss_pattern_count'] == 0 and 
        raw_features_dict['special_char_count'] < 4  
    )

    # B. Natural Language Safety (Suspicious keywords exist, but context is likely text)
    # Explanation: "select option A" has the keyword 'select', but lacks the code syntax 
    # (', ;, --, =, parens) required to make it executable SQL/Script.
    has_code_syntax = re.search(r"['\";\(\)\=\-\<\>]", payload) is not None
    
    is_clean_text = (
        not has_code_syntax and
        raw_features_dict['xss_pattern_count'] == 0 and
        # Slightly relax special chars for natural text punctuation (period, comma, exclamation)
        raw_features_dict['special_char_count'] < 6 
    )
    
    # Decision Tree:
    
    # A. If Rule Based says Attack -> BLOCK (Always trust specific signature if found)
    if rule_verdict != "Normal":
        final_decision = "BLOCKED"
        final_type = rule_verdict
        
    # B. Else If Clean (Strict or Textual) -> ACCEPT (Override ML paranoia)
    elif is_clean_strict or is_clean_text:
        final_decision = "ACCEPTED"
        final_type = "Normal"
    
    # C. Else -> Trust ML Prediction (with threshold)
    else:
        CONFIDENCE_THRESHOLD = 0.70
        if ml_pred == 1 and ml_conf > CONFIDENCE_THRESHOLD:
            final_decision = "BLOCKED"
            final_type = "Malicious Request"
        else:
            final_decision = "ACCEPTED"
            final_type = "Normal"
    
    return final_decision, final_type

# --- Routes ---
@app.route('/')
def home(): return render_template('home.html')

@app.route('/about')
def about(): return render_template('about.html')

@app.route('/try_now')
def try_now(): return render_template('try_now.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    # Defensive check: return structured JSON error instead of crashing if models missing
    if not clf or not scaler: 
        return jsonify({
            'error': 'Models not loaded. Ensure attack_classifier.pkl and feature_extractor.pkl are in the models/ directory.',
            'decision': 'ERROR',
            'detected_type': 'System Error',
            'confidence': '0.00%',
            'risk_level': 'Unknown',
            'explanation': [],
            'harm_text': 'Analysis unavailable. ML models failed to load.',
            'features': {'length': 0, 'special_chars': 0, 'sql_keywords': 0}
        }), 500

    data = request.get_json(silent=True) or {}
    payload = data.get('payload', '')
    action_type = data.get('action_type', 'Unknown')
    
    # Extract
    raw_features_list = extract_features_from_payload(payload, action_type)
    
    # Reconstruct dict for logic check (Mapping based on feature_order indices)
    # 2: special_char_count, 3: sql_keyword_count, 4: xss_pattern_count
    raw_features_dict = {
        'special_char_count': raw_features_list[2],
        'sql_keyword_count': raw_features_list[3],
        'xss_pattern_count': raw_features_list[4]
    }
    
    features_array = np.array(raw_features_list).reshape(1, -1)
    scaled_features = scaler.transform(features_array)
    
    prediction = clf.predict(scaled_features)[0]
    proba = clf.predict_proba(scaled_features)[0]
    attack_confidence = proba[1]
    
    try:
        exp = explainer.explain_instance(scaled_features[0], clf.predict_proba, num_features=3)
        explanation_list = exp.as_list()
    except:
        explanation_list = [("LIME Error", 0.0)]

    # Pass raw_features_dict to the decision engine
    decision, detected_type = hybrid_decision_engine(prediction, attack_confidence, payload, raw_features_dict)
    
    # Get Manual Explanation
    harm_text = get_harm_explanation(detected_type)

    # Adjust metrics based on Final Decision (Fix for UI consistency)
    if decision == 'ACCEPTED':
        risk_level = 'Low'
        # For Normal requests, show the confidence that it IS Normal (1 - attack_prob)
        # If attack_confidence > 0.5 but accepted, it means the Safety Override triggered.
        # In that case, we are 100% sure it's safe (rule-based).
        if attack_confidence > 0.5:
            display_confidence = 1.0
        else:
            display_confidence = 1.0 - attack_confidence
    else:
        # Granular Risk Levels
        if attack_confidence > 0.90:
            risk_level = 'Critical'
        elif attack_confidence > 0.75:
            risk_level = 'High'
        elif attack_confidence > 0.50:
            risk_level = 'Medium'
        else:
            risk_level = 'Low'
            
        display_confidence = attack_confidence

    if 'user_id' in session:
        try:
            db = get_db()
            db.execute(
                'INSERT INTO logs (user_id, action_type, payload, result, confidence, detected_type) VALUES (?, ?, ?, ?, ?, ?)',
                (session['user_id'], action_type, payload, decision, float(display_confidence), detected_type)
            )
            db.commit()
            db.close() # explicit close
        except Exception as e:
            print(f"Log Error: {e}")

    response = {
        'decision': decision,
        'detected_type': detected_type,
        'confidence': f"{display_confidence*100:.2f}%",
        'risk_level': risk_level,
        'explanation': explanation_list,
        'harm_text': harm_text, # Manual explanation
        'features': {
            'length': len(payload),
            'special_chars': raw_features_list[2],
            'sql_keywords': raw_features_list[3]
        }
    }
    return jsonify(response)

@app.route('/log_simulation', methods=['POST'])
def log_simulation():
    """Store demo-only synthetic events (e.g., rate-limit) in dashboard logs."""
    if 'user_id' not in session:
        return jsonify({'status': 'ignored', 'message': 'Login required for log persistence.'}), 200

    data = request.get_json(silent=True) or {}
    action_type = data.get('action_type', 'Extension Simulation')
    payload = data.get('payload', 'demo extension simulation')
    result = data.get('result', 'BLOCKED')
    confidence = float(data.get('confidence', 0.99))
    detected_type = data.get('detected_type', 'Rate Limit')

    try:
        db = get_db()
        db.execute(
            'INSERT INTO logs (user_id, action_type, payload, result, confidence, detected_type) VALUES (?, ?, ?, ?, ?, ?)',
            (session['user_id'], action_type, payload, result, confidence, detected_type)
        )
        db.commit()
        db.close()
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    db = get_db()
    logs = db.execute('SELECT * FROM logs WHERE user_id = ? ORDER BY timestamp DESC', (session['user_id'],)).fetchall()
    
    total = len(logs)
    blocked = sum(1 for log in logs if log['result'] == 'BLOCKED')
    safe = total - blocked
    chart_data = {'safe': safe, 'blocked': blocked, 'types': {}}
    for log in logs:
        if log['result'] == 'BLOCKED':
            d_type = log['detected_type']
            chart_data['types'][d_type] = chart_data['types'].get(d_type, 0) + 1
    
    db.close() # explicit close
    return render_template('dashboard.html', logs=logs, stats={'total': total, 'safe': safe, 'blocked': blocked}, chart_data=chart_data)

@app.route('/profile')
def profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    db = get_db()
    user = db.execute('SELECT username, email FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    db.close()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    return render_template('profile.html', username=user['username'], email=user['email'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        action = request.form['action']
        
        try:
            db = get_db()
            if action == 'register':
                email = request.form.get('email', '').strip().lower() or None
                try:
                    hashed_pw = generate_password_hash(password)
                    db.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', (username, email, hashed_pw))
                    db.commit()
                    flash('Registration successful! Please login.', 'success')
                except sqlite3.IntegrityError:
                    flash('Username or email already exists.', 'danger')
            elif action == 'login':
                user = db.execute(
                    'SELECT * FROM users WHERE username = ? OR lower(email) = lower(?)',
                    (username, username)
                ).fetchone()
                if user and check_password_hash(user['password'], password):
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['email'] = user['email'] if 'email' in user.keys() else None
                    db.close()
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid credentials.', 'danger')
            db.close()
        except sqlite3.OperationalError as e:
            flash(f'Database error: {e}. Please try again.', 'danger')
                
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5002)
