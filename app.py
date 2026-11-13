
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)

import sqlite3
import os
import re
import json
import traceback
import secrets
import time
import threading
from collections import deque
from datetime import timedelta

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.middleware.proxy_fix import ProxyFix

from flask_wtf.csrf import CSRFProtect, CSRFError

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None


# =====================================
# FLASK APPLICATION CONFIGURATION
# =====================================

app = Flask(__name__)

# Determine if running in a production environment (Render sets RENDER=true)
is_production = (
    os.environ.get("RENDER", "").lower() in ("true", "1") or
    os.environ.get("FLASK_ENV", "").lower() == "production" or
    os.environ.get("ENVIRONMENT", "").lower() == "production"
)

secret_key = os.environ.get("SECRET_KEY")
if secret_key:
    secret_key = secret_key.strip()

if is_production and not secret_key:
    raise RuntimeError(
        "CRITICAL SECURITY CONFIGURATION ERROR: The SECRET_KEY environment variable is not set. "
        "A secure secret key is required in production (Render) to encrypt and sign user sessions. "
        "Please configure SECRET_KEY in your Render dashboard environment variables."
    )

if not secret_key:
    secret_key = secrets.token_hex(32)
    print("\n" + "=" * 70)
    print("[SHAKTI AI SECURITY WARNING] SECRET_KEY is not set in environment.")
    print("A temporary cryptographic key was generated for this local session.")
    print("User sessions will reset whenever the Flask application restarts.")
    print("To keep persistent sessions locally, set SECRET_KEY in your environment.")
    print("=" * 70 + "\n")

app.secret_key = secret_key

# Enforce secure session cookie attributes and lifetime
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_DOMAIN=None,
)

if is_production:
    app.config.update(
        SESSION_COOKIE_NAME="__Host-shakti_session",
        SESSION_COOKIE_SECURE=True,
    )
    # Configure ProxyFix for Render reverse proxy (trusts X-Forwarded-For, Proto, Host from 1 proxy hop)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
else:
    app.config.update(
        SESSION_COOKIE_NAME="shakti_session",
        SESSION_COOKIE_SECURE=False,
    )

# =====================================
# CSRF PROTECTION INITIALIZATION
# =====================================

csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({
            "success": False,
            "error": f"CSRF validation failed: {e.description}"
        }), 400

    return f"Bad Request (400): CSRF validation failed - {e.description}", 400

DATABASE = os.path.join(app.root_path, "shakti.db")


# =====================================
# DATABASE CONNECTION
# =====================================

def get_db_connection():

    conn = sqlite3.connect(DATABASE)

    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA foreign_keys = ON")

    return conn


# =====================================
# CREATE DATABASE TABLES
# =====================================

def create_table():

    conn = get_db_connection()

    # USERS TABLE

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # TRUSTED CONTACTS TABLE

    conn.execute("""
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            phone TEXT NOT NULL,
            relationship TEXT,
            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)

    # SOS HISTORY TABLE

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sos_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            accuracy REAL NOT NULL,
            total_contacts INTEGER DEFAULT 0,
            successful_count INTEGER DEFAULT 0,
            failed_count INTEGER DEFAULT 0,
            notification_status TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE CASCADE
        )
    """)

    conn.commit()

    conn.close()


# =====================================
# HOME PAGE
# =====================================

@app.route('/')
def home():

    return render_template('index.html')


# =====================================
# USER REGISTRATION
# =====================================

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        name = request.form.get('name', '').strip()

        email = request.form.get('email', '').strip().lower()

        password = request.form.get('password', '')

        if not name or not email or not password:

            flash("Please fill in all fields.")

            return redirect(url_for('register'))

        if len(name) > 100:

            flash("Name must not exceed 100 characters.")

            return redirect(url_for('register'))

        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):

            flash("Please enter a valid email address.")

            return redirect(url_for('register'))

        if len(password) < 8:

            flash("Password must contain at least 8 characters.")

            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        conn = get_db_connection()

        try:

            conn.execute(
                """
                INSERT INTO users (name, email, password)
                VALUES (?, ?, ?)
                """,
                (name, email, hashed_password)
            )

            conn.commit()

            flash("Registration successful! Please login.")

            return redirect(url_for('login'))

        except sqlite3.IntegrityError:

            flash("This email is already registered.")

            return redirect(url_for('register'))

        finally:

            conn.close()

    return render_template('register.html')


# =====================================
# LOGIN RATE LIMITER (THREAD-SAFE & IN-MEMORY)
# =====================================

class LoginRateLimiter:
    """
    Thread-safe in-memory sliding window rate limiter for failed login attempts.
    Tracks failed attempts by (client_ip, normalized_email) tuple.
    Automatically expires old timestamps and prunes stale keys.
    """
    def __init__(self, max_attempts=5, window_seconds=300):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._failures = {}
        self._last_cleanup = time.time()

    def _get_key(self, ip, email):
        clean_ip = (ip or '127.0.0.1').strip()
        clean_email = (email or '').strip().lower()
        return (clean_ip, clean_email)

    def _cleanup_expired(self, now):
        """Periodically cleans up empty or stale entries to prevent memory growth."""
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        expired_keys = [
            k for k, timestamps in self._failures.items()
            if not timestamps or (now - timestamps[-1] > self.window_seconds)
        ]
        for k in expired_keys:
            del self._failures[k]

    def is_rate_limited(self, ip, email, now=None):
        """
        Checks if the given (ip, email) has reached or exceeded max_attempts within window_seconds.
        Returns (is_limited: bool, seconds_remaining: int).
        """
        if now is None:
            now = time.time()

        key = self._get_key(ip, email)
        with self._lock:
            self._cleanup_expired(now)
            timestamps = self._failures.get(key)
            if not timestamps:
                return False, 0

            # Prune timestamps outside sliding window
            while timestamps and (now - timestamps[0] > self.window_seconds):
                timestamps.popleft()

            if len(timestamps) >= self.max_attempts:
                seconds_remaining = max(1, int(self.window_seconds - (now - timestamps[0])))
                return True, seconds_remaining

            return False, 0

    def record_failure(self, ip, email, now=None):
        """Records a failed login attempt for the given (ip, email)."""
        if now is None:
            now = time.time()

        key = self._get_key(ip, email)
        with self._lock:
            self._cleanup_expired(now)
            if key not in self._failures:
                self._failures[key] = deque()
            self._failures[key].append(now)

    def clear(self, ip, email):
        """Clears failed attempts upon successful authentication."""
        key = self._get_key(ip, email)
        with self._lock:
            self._failures.pop(key, None)


login_limiter = LoginRateLimiter(max_attempts=5, window_seconds=300)


# =====================================
# USER LOGIN
# =====================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        client_ip = request.remote_addr or '127.0.0.1'
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        # Check rate limit before performing authentication or db queries
        is_limited, seconds_remaining = login_limiter.is_rate_limited(client_ip, email)
        if is_limited:
            minutes_remaining = max(1, (seconds_remaining + 59) // 60)
            if minutes_remaining == 1:
                flash("Too many failed login attempts. Please wait 1 minute before trying again.")
            else:
                flash(f"Too many failed login attempts. Please wait {minutes_remaining} minutes before trying again.")
            return redirect(url_for('login'))

        if not email or not password:
            flash("Please enter both email and password.")
            return redirect(url_for('login'))

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user['password'], password):

            login_limiter.clear(client_ip, email)

            session.clear()

            session.permanent = True

            session['user_id'] = user['id']

            session['user_name'] = user['name']

            return redirect(url_for('dashboard'))

        else:

            login_limiter.record_failure(client_ip, email)

            flash("Invalid email or password.")

            return redirect(url_for('login'))

    return render_template('login.html')


# =====================================
# USER DASHBOARD
# =====================================

@app.route('/dashboard')
def dashboard():

    if 'user_id' not in session:

        return redirect(url_for('login'))

    return render_template(
        'dashboard.html',
        name=session['user_name']
    )

# =====================================
# VOICEGUARD PAGE
# =====================================

@app.route('/voiceguard')
def voiceguard():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('voiceguard.html')

# =====================================
# JOURNEY GUARDIAN PAGE
# =====================================

@app.route('/journey_guardian')
def journey_guardian():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('journey_guardian.html')


# =====================================
# AI SAFETY ASSISTANT PAGE
# =====================================

@app.route('/ai_safety_assistant')
def ai_safety_assistant():

    if 'user_id' not in session:
        return redirect(url_for('login'))

    return render_template('ai_safety_assistant.html')


# =====================================
# MY PROFILE - VIEW AND EDIT PROFILE
# =====================================

@app.route('/profile', methods=['GET', 'POST'])
def profile():

    if 'user_id' not in session:

        return redirect(url_for('login'))

    conn = get_db_connection()

    user = conn.execute(
        """
        SELECT id, name, email
        FROM users
        WHERE id = ?
        """,
        (session['user_id'],)
    ).fetchone()

    if user is None:

        conn.close()

        session.clear()

        flash("User account not found. Please login again.")

        return redirect(url_for('login'))

    if request.method == 'POST':

        name = request.form.get('name', '').strip()

        email = request.form.get('email', '').strip().lower()

        if not name or not email:

            conn.close()

            flash("Name and email are required.")

            return redirect(url_for('profile'))

        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):

            conn.close()

            flash("Please enter a valid email address.")

            return redirect(url_for('profile'))

        existing_user = conn.execute(
            """
            SELECT id FROM users
            WHERE email = ? AND id != ?
            """,
            (email, session['user_id'])
        ).fetchone()

        if existing_user:

            conn.close()

            flash("This email address is already registered.")

            return redirect(url_for('profile'))

        conn.execute(
            """
            UPDATE users
            SET name = ?, email = ?
            WHERE id = ?
            """,
            (name, email, session['user_id'])
        )

        conn.commit()

        conn.close()

        session['user_name'] = name

        flash("Profile updated successfully!")

        return redirect(url_for('profile'))

    conn.close()

    return render_template(
        'profile.html',
        user=user
    )


# =====================================
# CHANGE PASSWORD
# =====================================

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():

    if 'user_id' not in session:

        return redirect(url_for('login'))

    if request.method == 'POST':

        current_password = request.form.get('current_password', '')

        new_password = request.form.get('new_password', '')

        confirm_password = request.form.get('confirm_password', '')

        conn = get_db_connection()

        user = conn.execute(
            "SELECT password FROM users WHERE id = ?",
            (session['user_id'],)
        ).fetchone()

        if user is None:

            conn.close()

            session.clear()

            flash("User account not found. Please login again.")

            return redirect(url_for('login'))

        # VERIFY CURRENT PASSWORD

        if not check_password_hash(user['password'], current_password):

            conn.close()

            flash("Your current password is incorrect.")

            return redirect(url_for('change_password'))

        # CHECK NEW PASSWORD LENGTH

        if len(new_password) < 8:

            conn.close()

            flash("New password must contain at least 8 characters.")

            return redirect(url_for('change_password'))

        # CHECK PASSWORD CONFIRMATION

        if new_password != confirm_password:

            conn.close()

            flash("New passwords do not match.")

            return redirect(url_for('change_password'))

        # HASH NEW PASSWORD

        hashed_password = generate_password_hash(new_password)

        # UPDATE PASSWORD IN DATABASE

        conn.execute(
            """
            UPDATE users
            SET password = ?
            WHERE id = ?
            """,
            (hashed_password, session['user_id'])
        )

        conn.commit()

        conn.close()

        flash("Password changed successfully!")

        return redirect(url_for('change_password'))

    return render_template('change_password.html')


# =====================================
# SAFECIRCLE - VIEW CONTACTS
# =====================================

@app.route('/safecircle')
def safecircle():

    if 'user_id' not in session:

        return redirect(url_for('login'))

    conn = get_db_connection()

    contacts = conn.execute(
        """
        SELECT * FROM contacts
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session['user_id'],)
    ).fetchall()

    conn.close()

    return render_template(
        'safecircle.html',
        contacts=contacts
    )


# =====================================
# ADD TRUSTED CONTACT
# =====================================

@app.route('/add_contact', methods=['POST'])
def add_contact():

    if 'user_id' not in session:

        return redirect(url_for('login'))

    name = request.form['name'].strip()

    phone = request.form['phone'].strip()

    relationship = request.form.get('relationship', '').strip()

    if not name or not phone:

        flash("Name and phone number are required.")

        return redirect(url_for('safecircle'))

    if not re.fullmatch(r'\+?[0-9\s-]{7,20}', phone):

        flash("Please enter a valid phone number.")

        return redirect(url_for('safecircle'))

    conn = get_db_connection()

    conn.execute(
        """
        INSERT INTO contacts
        (user_id, name, phone, relationship)
        VALUES (?, ?, ?, ?)
        """,
        (
            session['user_id'],
            name,
            phone,
            relationship
        )
    )

    conn.commit()

    conn.close()

    flash("Trusted contact added successfully!")

    return redirect(url_for('safecircle'))


# =====================================
# EDIT TRUSTED CONTACT
# =====================================

@app.route('/edit_contact/<int:contact_id>', methods=['GET', 'POST'])
def edit_contact(contact_id):

    if 'user_id' not in session:

        return redirect(url_for('login'))

    conn = get_db_connection()

    contact = conn.execute(
        """
        SELECT * FROM contacts
        WHERE id = ? AND user_id = ?
        """,
        (contact_id, session['user_id'])
    ).fetchone()

    if contact is None:

        conn.close()

        flash("Contact not found.")

        return redirect(url_for('safecircle'))

    if request.method == 'POST':

        name = request.form['name'].strip()

        phone = request.form['phone'].strip()

        relationship = request.form.get('relationship', '').strip()

        if not name or not re.fullmatch(r'\+?[0-9\s-]{7,20}', phone):

            conn.close()

            flash("Please enter valid contact details.")

            return redirect(
                url_for('edit_contact', contact_id=contact_id)
            )

        conn.execute(
            """
            UPDATE contacts
            SET name = ?, phone = ?, relationship = ?
            WHERE id = ? AND user_id = ?
            """,
            (
                name,
                phone,
                relationship,
                contact_id,
                session['user_id']
            )
        )

        conn.commit()

        conn.close()

        flash("Contact updated successfully!")

        return redirect(url_for('safecircle'))

    conn.close()

    return render_template(
        'edit_contact.html',
        contact=contact
    )


# =====================================
# DELETE TRUSTED CONTACT
# =====================================

@app.route('/delete_contact/<int:contact_id>', methods=['POST'])
def delete_contact(contact_id):

    if 'user_id' not in session:

        return redirect(url_for('login'))

    conn = get_db_connection()

    conn.execute(
        """
        DELETE FROM contacts
        WHERE id = ? AND user_id = ?
        """,
        (contact_id, session['user_id'])
    )

    conn.commit()

    conn.close()

    flash("Contact deleted successfully!")

    return redirect(url_for('safecircle'))


# =====================================
# DEMO SMS NOTIFICATION FUNCTION
# =====================================

def send_demo_sms(contact, message):

    try:
        raw_phone = str(contact['phone']).strip() if contact and 'phone' in contact.keys() else ''
    except Exception:
        raw_phone = ''

    try:
        relationship = str(contact['relationship']).strip() if contact and 'relationship' in contact.keys() else 'Trusted Contact'
    except Exception:
        relationship = 'Trusted Contact'

    if len(raw_phone) >= 4:
        masked_phone = '*' * (len(raw_phone) - 4) + raw_phone[-4:]
    else:
        masked_phone = '[PROTECTED]'

    print("\n" + "=" * 50)

    print("SHAKTI AI - DEMO SMS NOTIFICATION")

    print("=" * 50)

    print("Recipient Type:", relationship)

    print("Recipient Phone:", masked_phone)

    print("Emergency Message: [SIMULATED ALERT - LOCATION & USER DATA REDACTED]")

    print("-" * 50)

    print("STATUS: SIMULATED SUCCESS")

    print("NOTE: NO ACTUAL SMS WAS SENT.")

    print("=" * 50 + "\n")

    return True


# =====================================
# GEMINI AI SAFETY ASSISTANT HELPER
# =====================================

def analyze_safety_situation(situation_text):
    """
    Analyzes a user-described safety situation using the Google GenAI SDK.
    Returns a structured assessment dictionary suitable for a women's safety assistant.
    Does NOT store any user situation or AI response in the database.
    Ensures the client is closed after use and sanitizes all user-facing errors.
    """
    # 1. Validate user input and enforce length boundaries
    if not situation_text or not isinstance(situation_text, str) or not situation_text.strip():
        return {
            "success": False,
            "error": "Please describe your safety situation."
        }

    cleaned_text = situation_text.strip()
    if len(cleaned_text) < 10:
        return {
            "success": False,
            "error": "Please provide more details (at least 10 characters) so the assistant can assess the situation."
        }

    if len(cleaned_text) > 2000:
        return {
            "success": False,
            "error": "Situation description is too long (maximum 2,000 characters). Please provide a more concise description."
        }

    # 2. Check SDK availability
    if genai is None:
        return {
            "success": False,
            "error": "The google-genai library is not available. Please ensure google-genai is installed."
        }

    # 3. Retrieve API key securely from environment
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        return {
            "success": False,
            "error": "Gemini API key is not configured. Please ensure GEMINI_API_KEY is set in your environment."
        }

    api_key = api_key.strip().strip('"').strip("'")

    # 4. Construct prompt and safety instructions
    system_instruction = """You are the AI Safety Assistant for SHAKTI AI, a women's safety platform. Your mission is to evaluate a user's safety situation and provide protective, actionable, and calm guidance.

MANDATORY SAFETY DIRECTIVE:
- Your response is purely advisory and based solely on unverified user input.
- It is NOT verified fact and must NEVER delay contacting emergency services when someone is in immediate danger.
- If there is imminent threat or danger, explicitly instruct the user to trigger emergency SOS or contact emergency authorities (such as Police 112) immediately.

Analyze the provided situation and return ONLY a valid JSON object with the following exact keys:
{
  "situation_summary": "Concise, objective summary of the reported situation.",
  "risk_level": "One of: Low, Medium, High, Critical",
  "important_details": ["Key detail or environmental risk factor 1", "Key detail 2"],
  "recommended_actions": ["Immediate prioritized action 1", "Action 2"],
  "missing_information": ["Critical unknown detail 1 that could clarify the risk", "Detail 2"],
  "limitations_and_uncertainty": "Advisory disclaimer emphasizing that this AI guidance is not a substitute for emergency services and cannot verify real-world conditions."
}"""

    user_prompt = f"""{system_instruction}

USER SAFETY SITUATION:
{cleaned_text}

Provide your structured JSON analysis now:"""

    model_name = os.environ.get("GEMINI_MODEL", "gemini-3.5-flash-lite")
    client = None

    try:
        client = genai.Client(
            api_key=api_key,
            http_options={"timeout": 30000.0}
        )

        config = types.GenerateContentConfig(
            response_mime_type="application/json",
            temperature=0.2,
        ) if types else {"response_mime_type": "application/json"}

        response = client.models.generate_content(
            model=model_name,
            contents=user_prompt,
            config=config
        )

        response_text = (response.text or "").strip()

        # Clean potential markdown wrapping if present
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        elif response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
        response_text = response_text.strip()

        try:
            parsed_data = json.loads(response_text)
        except json.JSONDecodeError as decode_err:
            print("\n[SHAKTI AI ASSISTANT WARNING] JSON decode failed:", type(decode_err).__name__)
            return {
                "success": False,
                "error": "The AI response could not be verified in the required structured safety format. Please try again."
            }

        if not isinstance(parsed_data, dict):
            print("\n[SHAKTI AI ASSISTANT WARNING] Model returned non-dictionary JSON root.")
            return {
                "success": False,
                "error": "Invalid response structure received from the safety assessment model."
            }

        # 5. Strict validation of required fields
        summary = str(parsed_data.get("situation_summary", "")).strip()
        if not summary:
            print("\n[SHAKTI AI ASSISTANT WARNING] Validation failure: missing or empty situation_summary.")
            return {
                "success": False,
                "error": "The AI analysis is incomplete (missing situation summary). Please try again."
            }

        raw_risk = str(parsed_data.get("risk_level", "")).strip().capitalize()
        # Normalize "Moderate" to "Medium" only if it is an exact risk-level value
        if raw_risk == "Moderate":
            raw_risk = "Medium"

        if raw_risk not in ["Low", "Medium", "High", "Critical"]:
            print(f"\n[SHAKTI AI ASSISTANT WARNING] Validation failure: unrecognized risk_level '{raw_risk}'.")
            return {
                "success": False,
                "error": "The AI analysis returned an unrecognized risk level. Please try again."
            }

        def to_clean_list(val):
            if isinstance(val, list):
                return [str(item).strip() for item in val if str(item).strip()]
            elif isinstance(val, str) and val.strip():
                return [val.strip()]
            return []

        actions = to_clean_list(parsed_data.get("recommended_actions"))
        if not actions:
            print("\n[SHAKTI AI ASSISTANT WARNING] Validation failure: empty recommended_actions list.")
            return {
                "success": False,
                "error": "The AI analysis is incomplete (no recommended safety actions provided). Please try again."
            }

        details = to_clean_list(parsed_data.get("important_details"))
        missing_info = to_clean_list(parsed_data.get("missing_information"))
        limitations = str(parsed_data.get("limitations_and_uncertainty", "")).strip()
        if not limitations:
            limitations = (
                "This AI safety analysis is purely advisory and based solely on unverified user input. "
                "It cannot replace professional emergency services. In any immediate danger, contact emergency authorities (112) or trigger SOS without delay."
            )

        structured_analysis = {
            "situation_summary": summary,
            "risk_level": raw_risk,
            "important_details": details,
            "recommended_actions": actions,
            "missing_information": missing_info,
            "limitations_and_uncertainty": limitations
        }

        return {
            "success": True,
            "analysis": structured_analysis
        }

    except Exception as error:
        error_str = str(error)
        tb_str = traceback.format_exc()

        # Redact the Gemini API key from error message and traceback
        if api_key:
            error_str = error_str.replace(api_key, "[REDACTED_API_KEY]")
            tb_str = tb_str.replace(api_key, "[REDACTED_API_KEY]")

        # Safe server-side terminal logging (never logs user situation text or credentials)
        print("\n" + "=" * 60)
        print("SHAKTI AI - GEMINI SAFETY ASSISTANT ERROR LOG")
        print("=" * 60)
        print("Error Type:", type(error).__name__)
        print("Error Message:", error_str)
        print("-" * 60)
        print(tb_str)
        print("=" * 60 + "\n")

        # Sanitize error output to prevent exposing technical details, URLs, or keys to user
        error_lower = error_str.lower()
        if any(kw in error_lower for kw in ["api_key", "unauthenticated", "permission", "403", "401"]):
            user_error = "AI service authentication error. Please verify the Gemini API key configuration."
        elif any(kw in error_lower for kw in ["quota", "rate limit", "429", "resource_exhausted"]):
            user_error = "The AI safety service is temporarily experiencing high traffic. Please wait a moment and try again."
        elif any(kw in error_lower for kw in ["not found", "404"]):
            user_error = f"The requested Gemini model ({model_name}) is currently unavailable. Please check the model configuration."
        elif any(kw in error_lower for kw in ["timeout", "deadline", "connection"]):
            user_error = "Network timeout while contacting the AI safety service. Please check your internet connection and try again."
        else:
            user_error = (
                "Unable to complete AI safety analysis at this moment. "
                "If you are in immediate danger, please activate the SOS Emergency button or call emergency services (112) immediately."
            )

        return {
            "success": False,
            "error": user_error
        }

    finally:
        # Ensure client is properly closed after use
        if client is not None and hasattr(client, "close") and callable(client.close):
            try:
                client.close()
            except Exception:
                pass


# =====================================
# AI SAFETY ASSISTANT - SITUATION ANALYSIS
# =====================================

@app.route('/api/safety_assistant/analyze', methods=['POST'])
def analyze_safety():

    # 1. Require authentication
    if 'user_id' not in session:
        return jsonify({
            "success": False,
            "error": "Please login to access the AI Safety Assistant.",
            "login_required": True
        }), 401

    # 2. Accept JSON input
    data = request.get_json(silent=True) or {}

    # 3. Read user situation with fallback
    situation = data.get('situation')
    if situation is None or not isinstance(situation, str) or not situation.strip():
        situation = data.get('situation_text')

    # 4. Validate input
    if not situation or not isinstance(situation, str) or not situation.strip():
        return jsonify({
            "success": False,
            "error": "Please describe your safety situation."
        }), 400

    cleaned_situation = situation.strip()

    if len(cleaned_situation) < 10:
        return jsonify({
            "success": False,
            "error": "Please provide more details (at least 10 characters) so the assistant can assess the situation."
        }), 400

    if len(cleaned_situation) > 2000:
        return jsonify({
            "success": False,
            "error": "Situation description is too long (maximum 2,000 characters). Please provide a more concise description."
        }), 400

    # 5. Call analyze_safety_situation helper safely
    try:
        result = analyze_safety_situation(cleaned_situation)

        if not result.get("success"):
            print(f"[SHAKTI AI API 500] Safety analysis returned error: {result.get('error')}")
            return jsonify(result), 500

        return jsonify(result), 200

    except Exception as route_err:
        route_err_str = str(route_err)
        route_tb_str = traceback.format_exc()
        api_k = os.environ.get("GEMINI_API_KEY")
        if api_k:
            route_err_str = route_err_str.replace(api_k, "[REDACTED_API_KEY]")
            route_tb_str = route_tb_str.replace(api_k, "[REDACTED_API_KEY]")

        print("\n" + "=" * 60)
        print("SHAKTI AI - API ROUTE UNEXPECTED EXCEPTION")
        print("=" * 60)
        print("Error Type:", type(route_err).__name__)
        print("Error Message:", route_err_str)
        print("-" * 60)
        print(route_tb_str)
        print("=" * 60 + "\n")

        return jsonify({
            "success": False,
            "error": "Unable to complete AI safety analysis at this moment. If you are in immediate danger, please dial 112 immediately."
        }), 500


# =====================================
# SOS EMERGENCY - PREPARE AND SIMULATE
# =====================================

@app.route('/api/sos/prepare', methods=['POST'])
def prepare_sos():

    if 'user_id' not in session:

        return jsonify({
            "success": False,
            "message": "Please login to access your SafeCircle contacts.",
            "login_required": True
        }), 401

    # RECEIVE GPS COORDINATES

    data = request.get_json(silent=True) or {}

    latitude = data.get('latitude')

    longitude = data.get('longitude')

    accuracy = data.get('accuracy')

    # VALIDATE COORDINATES

    try:

        latitude = float(latitude)

        longitude = float(longitude)

        accuracy = float(accuracy)

        if not (-90 <= latitude <= 90):

            raise ValueError()

        if not (-180 <= longitude <= 180):

            raise ValueError()

        if not (0 <= accuracy <= 100000):

            raise ValueError()

    except (TypeError, ValueError):

        return jsonify({
            "success": False,
            "message": "Invalid GPS coordinates."
        }), 400

    # RETRIEVE TRUSTED CONTACTS

    conn = get_db_connection()

    contacts = conn.execute(
        """
        SELECT name, phone, relationship
        FROM contacts
        WHERE user_id = ?
        """,
        (session['user_id'],)
    ).fetchall()

    conn.close()

    if not contacts:

        return jsonify({
            "success": False,
            "message": "No trusted contacts found. Please add contacts in SafeCircle."
        }), 404

    # GOOGLE MAPS LOCATION

    map_url = f"https://www.google.com/maps?q={latitude},{longitude}"

    # PREPARE EMERGENCY MESSAGE

    message = (
        f"EMERGENCY ALERT!\n"
        f"{session['user_name']} may need assistance.\n"
        f"Current location: {map_url}\n"
        f"GPS accuracy: approximately {round(accuracy)} metres."
    )

    # DEMO SMS PROCESSING

    successful_count = 0

    failed_count = 0

    notification_results = []

    print("\n" + "#" * 60)

    print("SHAKTI AI EMERGENCY SYSTEM ACTIVATED")

    print("GPS Status: Coordinates received and validated (coordinates redacted)")

    print(f"Target Recipients: {len(contacts)} trusted contact(s)")

    print("#" * 60)

    for contact in contacts:

        try:

            result = send_demo_sms(contact, message)

            if result:

                successful_count += 1

                notification_results.append({
                    "name": contact['name'],
                    "status": "SIMULATED SUCCESS"
                })

            else:

                failed_count += 1

                notification_results.append({
                    "name": contact['name'],
                    "status": "FAILED"
                })

        except Exception as error:

            failed_count += 1

            print("Demo notification error:", type(error).__name__)

            notification_results.append({
                "name": contact['name'],
                "status": "FAILED"
            })

    # SAVE SOS ACTIVATION TO DATABASE

    if failed_count == 0:

        notification_status = "DEMO - SIMULATED SUCCESS"

    elif successful_count > 0:

        notification_status = "DEMO - PARTIALLY PROCESSED"

    else:

        notification_status = "DEMO - FAILED"

    conn = get_db_connection()

    conn.execute(
        """
        INSERT INTO sos_history (
            user_id,
            latitude,
            longitude,
            accuracy,
            total_contacts,
            successful_count,
            failed_count,
            notification_status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session['user_id'],
            latitude,
            longitude,
            accuracy,
            len(contacts),
            successful_count,
            failed_count,
            notification_status
        )
    )

    conn.commit()

    conn.close()

    print("SOS HISTORY SAVED SUCCESSFULLY.")

    return jsonify({

        "success": True,

        "message": "Demo emergency notifications processed.",

        "user_name": session['user_name'],

        "latitude": latitude,

        "longitude": longitude,

        "accuracy": round(accuracy),

        "map_url": map_url,

        "emergency_message": message,

        "contact_count": len(contacts),

        "successful_count": successful_count,

        "failed_count": failed_count,

        "notification_results": notification_results,

        "notification_status": notification_status

    })


# =====================================
# SOS HISTORY WITH SUMMARY STATISTICS
# =====================================

@app.route('/sos_history')
def sos_history():

    if 'user_id' not in session:

        return redirect(url_for('login'))

    conn = get_db_connection()

    # GET ALL SOS HISTORY

    history = conn.execute(
        """
        SELECT *
        FROM sos_history
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session['user_id'],)
    ).fetchall()

    # CALCULATE SOS SUMMARY

    summary = conn.execute(
        """
        SELECT
            COUNT(*) AS total_activations,
            COALESCE(SUM(total_contacts), 0) AS total_contacts,
            COALESCE(SUM(successful_count), 0) AS successful_count,
            COALESCE(SUM(failed_count), 0) AS failed_count
        FROM sos_history
        WHERE user_id = ?
        """,
        (session['user_id'],)
    ).fetchone()

    conn.close()

    return render_template(
        'sos_history.html',
        history=history,
        name=session['user_name'],
        summary=summary
    )


# =====================================
# DELETE INDIVIDUAL SOS RECORD
# =====================================

@app.route('/delete_sos/<int:record_id>', methods=['POST'])
def delete_sos(record_id):

    if 'user_id' not in session:

        return redirect(url_for('login'))

    conn = get_db_connection()

    conn.execute(
        """
        DELETE FROM sos_history
        WHERE id = ? AND user_id = ?
        """,
        (record_id, session['user_id'])
    )

    conn.commit()

    conn.close()

    flash("SOS record deleted successfully!")

    return redirect(url_for('sos_history'))


# =====================================
# CLEAR ALL SOS HISTORY
# =====================================

@app.route('/clear_sos_history', methods=['POST'])
def clear_sos_history():

    if 'user_id' not in session:

        return redirect(url_for('login'))

    conn = get_db_connection()

    conn.execute(
        """
        DELETE FROM sos_history
        WHERE user_id = ?
        """,
        (session['user_id'],)
    )

    conn.commit()

    conn.close()

    flash("All SOS history records deleted successfully!")

    return redirect(url_for('sos_history'))


# =====================================
# USER LOGOUT
# =====================================

@app.route('/logout')
def logout():

    session.clear()

    return redirect(url_for('home'))


# =====================================
# RUN APPLICATION
# =====================================

create_table()

if __name__ == '__main__':
    app.run(debug=not is_production)
