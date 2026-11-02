
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)

import sqlite3
import os
import re

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# =====================================
# FLASK APPLICATION CONFIGURATION
# =====================================

app = Flask(__name__)

app.secret_key = "change_this_to_a_random_secret_before_deployment"

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

        name = request.form['name'].strip()

        email = request.form['email'].strip().lower()

        password = request.form['password']

        if not name or not email or not password:

            flash("Please fill in all fields.")

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
# USER LOGIN
# =====================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        email = request.form['email'].strip().lower()

        password = request.form['password']

        conn = get_db_connection()

        user = conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

        conn.close()

        if user and check_password_hash(user['password'], password):

            session.clear()

            session['user_id'] = user['id']

            session['user_name'] = user['name']

            return redirect(url_for('dashboard'))

        else:

            flash("Invalid email or password.")

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

    print("\n" + "=" * 50)

    print("SHAKTI AI - DEMO SMS NOTIFICATION")

    print("=" * 50)

    print("Recipient Name:", contact['name'])

    print("Recipient Phone:", contact['phone'])

    print("Emergency Message:")

    print(message)

    print("-" * 50)

    print("STATUS: SIMULATED SUCCESS")

    print("NOTE: NO ACTUAL SMS WAS SENT.")

    print("=" * 50 + "\n")

    return True


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

    print("\n")

    print("#" * 60)

    print("SHAKTI AI EMERGENCY SYSTEM ACTIVATED")

    print("User:", session['user_name'])

    print("GPS Location:", latitude, longitude)

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

            print("Demo notification error:", error)

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

if __name__ == '__main__':

    create_table()

    app.run(debug=True)

