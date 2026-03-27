from flask import Flask, request, jsonify, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
import json
from datetime import datetime

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "trainerhub.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ┌─────────────────────────────────────────────────────────┐
# │  STANDARD ADMIN CODE — only people who know this code   │
# │  can register as an admin. Change it to anything you    │
# │  want. Keep it secret!                                  │
# └─────────────────────────────────────────────────────────┘
ADMIN_CODE = "TRAINER@2026"


# ── Create tables on startup ──────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur  = conn.cursor()

    # Students table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            role       TEXT    NOT NULL DEFAULT 'student',
            created_at TEXT    NOT NULL
        )
    ''')

    # Admins table (separate from students)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL,
            email      TEXT    NOT NULL UNIQUE,
            password   TEXT    NOT NULL,
            admin_code TEXT    NOT NULL,
            created_at TEXT    NOT NULL
        )
    ''')

    # Login logs (tracks both student and admin logins)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            email      TEXT NOT NULL,
            role       TEXT NOT NULL DEFAULT 'student',
            created_at TEXT NOT NULL
        )
    ''')

    # Student registrations (enrollment form data)
    cur.execute('''
        CREATE TABLE IF NOT EXISTS student_registrations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id      INTEGER,
            student_email   TEXT,
            program         TEXT,
            program_type    TEXT,
            first_name      TEXT,
            last_name       TEXT,
            dob             TEXT,
            gender          TEXT,
            contact         TEXT,
            email           TEXT,
            street          TEXT,
            city            TEXT,
            pincode         TEXT,
            state           TEXT,
            profile_photo   TEXT,
            qualification   TEXT,
            department      TEXT,
            year_of_study   TEXT,
            college         TEXT,
            university      TEXT,
            acad_city       TEXT,
            acad_state      TEXT,
            technical_skills TEXT,
            languages       TEXT,
            has_internship  TEXT,
            intern_title    TEXT,
            intern_company  TEXT,
            intern_type     TEXT,
            intern_tech     TEXT,
            intern_start    TEXT,
            intern_end      TEXT,
            intern_role     TEXT,
            intern_desc     TEXT,
            intern_cert     TEXT,
            resume          TEXT,
            id_proof        TEXT,
            additional_docs TEXT,
            created_at      TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()
    print("  [OK] Database ready -> trainerhub.db")
    print(f"  [OK] Admin code   -> {ADMIN_CODE}")


# ── Helper: get DB connection ─────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ── Helper: save uploaded file ────────────────────────────────────
def save_upload(file_obj, sub_folder=""):
    if not file_obj or file_obj.filename == "":
        return None
    folder = os.path.join(UPLOAD_DIR, sub_folder) if sub_folder else UPLOAD_DIR
    os.makedirs(folder, exist_ok=True)
    filename = datetime.utcnow().strftime("%Y%m%d%H%M%S_") + secure_filename(file_obj.filename)
    path = os.path.join(folder, filename)
    file_obj.save(path)
    return filename


# ── Serve HTML page ───────────────────────────────────────────────
@app.route("/")
def home():
    for name in ["home.html", "index.html"]:
        if os.path.exists(os.path.join(BASE_DIR, name)):
            return send_from_directory(BASE_DIR, name)
    return "home.html not found in project folder", 404

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(BASE_DIR, filename)


# ── STUDENT SIGN UP ──────────────────────────────────────────────
@app.route("/signup", methods=["POST"])
def signup():
    data     = request.get_json()
    name     = data.get("name", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400

    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()

        if existing:
            return jsonify({"success": False, "message": "Email already registered."}), 409

        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO users (name, email, password, role, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, email, generate_password_hash(password), "student", now)
        )
        conn.commit()
        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        print(f"[SIGNUP] OK  id={user_id}  name={name}  email={email}  role=student")
        return jsonify({
            "success": True,
            "message": "Student account created successfully!",
            "data": {"id": user_id, "name": name, "email": email, "role": "student", "created_at": now}
        }), 201

    except Exception as e:
        print(f"[SIGNUP] FAIL  {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()


# ── ADMIN SIGN UP (requires admin code) ──────────────────────────
@app.route("/admin-signup", methods=["POST"])
def admin_signup():
    data       = request.get_json()
    name       = data.get("name", "").strip()
    email      = data.get("email", "").strip().lower()
    password   = data.get("password", "")
    admin_code = data.get("admin_code", "").strip()

    if not name or not email or not password or not admin_code:
        return jsonify({"success": False, "message": "All fields are required."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400

    # Verify admin code
    if admin_code != ADMIN_CODE:
        return jsonify({"success": False, "message": "Invalid admin code. Access denied."}), 403

    conn = get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM admins WHERE email = ?", (email,)
        ).fetchone()

        if existing:
            return jsonify({"success": False, "message": "Admin email already registered."}), 409

        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO admins (name, email, password, admin_code, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, email, generate_password_hash(password), admin_code, now)
        )
        conn.commit()
        admin_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        print(f"[ADMIN SIGNUP] OK  id={admin_id}  name={name}  email={email}")
        return jsonify({
            "success": True,
            "message": "Admin account created successfully!",
            "data": {"id": admin_id, "name": name, "email": email, "role": "admin", "created_at": now}
        }), 201

    except Exception as e:
        print(f"[ADMIN SIGNUP] FAIL  {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()


# ── LOGIN (student or admin — queries separate tables) ───────────
@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")
    role     = data.get("role", "student")

    if not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    conn = get_db()
    try:
        if role == "admin":
            # Query ADMINS table
            user = conn.execute(
                "SELECT * FROM admins WHERE email = ?", (email,)
            ).fetchone()
        else:
            # Query USERS (students) table
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?", (email,)
            ).fetchone()

        if not user or not check_password_hash(user["password"], password):
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        # Log the login
        now = datetime.utcnow().isoformat() + "Z"
        conn.execute(
            "INSERT INTO login_logs (email, role, created_at) VALUES (?, ?, ?)",
            (email, role, now)
        )
        conn.commit()
        log_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        print(f"[LOGIN]  OK  log_id={log_id}  role={role}  email={email}")
        return jsonify({
            "success": True,
            "message": f"Logged in successfully as {role.capitalize()}!",
            "data": {"id": user["id"], "name": user["name"], "email": email, "role": role}
        }), 200

    except Exception as e:
        print(f"[LOGIN]  FAIL  {e}")
        return jsonify({"success": False, "message": str(e)}), 500
    finally:
        conn.close()


# ── STUDENT REGISTRATION (enrollment form) ───────────────────────
@app.route("/register", methods=["POST"])
def register_enrollment():
    try:
        f = request.form
        now = datetime.utcnow().isoformat() + "Z"

        # Save uploaded files
        photo_name = save_upload(request.files.get("profile_photo"), "photos")
        resume_name = save_upload(request.files.get("resume"), "resumes")
        id_proof_name = save_upload(request.files.get("id_proof"), "id_proofs")
        intern_cert_name = save_upload(request.files.get("intern_cert"), "intern_certs")

        add_doc_names = []
        for doc in request.files.getlist("additional_docs"):
            name = save_upload(doc, "additional")
            if name:
                add_doc_names.append(name)

        conn = get_db()
        conn.execute('''
            INSERT INTO student_registrations (
                student_id, student_email, program, program_type,
                first_name, last_name, dob, gender, contact, email,
                street, city, pincode, state, profile_photo,
                qualification, department, year_of_study, college, university,
                acad_city, acad_state,
                technical_skills, languages, has_internship,
                intern_title, intern_company, intern_type, intern_tech,
                intern_start, intern_end, intern_role, intern_desc, intern_cert,
                resume, id_proof, additional_docs, created_at
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ''', (
            f.get("student_id"), f.get("student_email"),
            f.get("program"), f.get("program_type"),
            f.get("first_name"), f.get("last_name"),
            f.get("dob"), f.get("gender"),
            f.get("contact"), f.get("email"),
            f.get("street"), f.get("city"),
            f.get("pincode"), f.get("state"),
            photo_name,
            f.get("qualification"), f.get("department"),
            f.get("year_of_study"), f.get("college"), f.get("university"),
            f.get("acad_city"), f.get("acad_state"),
            f.get("technical_skills"), f.get("languages"),
            f.get("has_internship"),
            f.get("intern_title"), f.get("intern_company"),
            f.get("intern_type"), f.get("intern_tech"),
            f.get("intern_start"), f.get("intern_end"),
            f.get("intern_role"), f.get("intern_desc"),
            intern_cert_name,
            resume_name, id_proof_name,
            json.dumps(add_doc_names),
            now
        ))
        conn.commit()
        reg_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()

        print(f"[REGISTER] OK  id={reg_id}  program={f.get('program')}  email={f.get('email')}")
        return jsonify({"success": True, "message": "Registration successful!", "id": reg_id}), 201

    except Exception as e:
        print(f"[REGISTER] FAIL  {e}")
        return jsonify({"success": False, "message": str(e)}), 500


# ── View stored students ──────────────────────────────────────────
@app.route("/users", methods=["GET"])
def get_users():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, email, created_at FROM users"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── View stored admins ────────────────────────────────────────────
@app.route("/admins", methods=["GET"])
def get_admins():
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, email, created_at FROM admins"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── View login logs ───────────────────────────────────────────────
@app.route("/logs", methods=["GET"])
def get_logs():
    conn = get_db()
    rows = conn.execute("SELECT * FROM login_logs").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── View registrations ────────────────────────────────────────────
@app.route("/registrations", methods=["GET"])
def get_registrations():
    conn = get_db()
    rows = conn.execute("SELECT * FROM student_registrations ORDER BY id DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


# ── Run ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("=" * 50)
    print("  TrainerHub Flask Server")
    print("=" * 50)
    print("  Home          -> http://localhost:5000")
    print("  Users         -> http://localhost:5000/users")
    print("  Admins        -> http://localhost:5000/admins")
    print("  Logs          -> http://localhost:5000/logs")
    print("  Registrations -> http://localhost:5000/registrations")
    print("=" * 50)
    app.run(debug=True,host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
