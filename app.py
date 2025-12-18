# app.py - Smart Bus Pass (complete: registration, OTP, OCR, QR->URL, view, renew)
from dotenv import load_dotenv
import os
load_dotenv()

DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() in ("1", "true", "yes")

import json
import razorpay
import qrcode
import io
from razorpay.errors import SignatureVerificationError

from flask import Flask, render_template, request, redirect, session, url_for, jsonify, make_response, abort
from flask_sqlalchemy import SQLAlchemy
import random, smtplib, time, re, uuid, logging, socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import pytesseract
from PIL import Image, ImageOps, ImageFilter
from datetime import date, datetime, timedelta
from difflib import SequenceMatcher
from werkzeug.utils import secure_filename
from urllib.parse import urljoin

# ---------- CONFIG ----------
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("FLASK_SECRET", "supersecretkey")

basedir = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(basedir, "smartbus.db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Email config
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_EMAIL = os.getenv("FROM_EMAIL", SMTP_USER)

# Razorpay client (reads keys from env)
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
    rz_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
else:
    rz_client = None

# OTP settings
OTP_EXPIRY_SECONDS = 60   # 1 minute for quick testing
RESEND_COOLDOWN_SECONDS = 60
MAX_RESENDS = 3

# File settings
ALLOWED_EXT = {"jpg", "jpeg", "png"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------- DATABASE MODEL ----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120))
    dob = db.Column(db.String(20))
    aadhaar = db.Column(db.String(20))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    category = db.Column(db.String(20))
    pass_type = db.Column(db.String(20))
    id_proof = db.Column(db.String(200))
    photo = db.Column(db.String(200))
    address = db.Column(db.String(300))
    city = db.Column(db.String(120))
    district = db.Column(db.String(120))
    pincode = db.Column(db.String(20))
    starting_from = db.Column(db.String(200))
    destination = db.Column(db.String(200))
    issue_date = db.Column(db.String(20))
    verified = db.Column(db.Boolean, default=False)

class Pass(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pass_type = db.Column(db.String(20))
    start_hub = db.Column(db.String(300))
    dest_hub = db.Column(db.String(300))
    distance_km = db.Column(db.Float)
    price = db.Column(db.Float)
    paid = db.Column(db.Boolean, default=False)
    valid_from = db.Column(db.String(20))
    valid_to = db.Column(db.String(20))
    qr_token = db.Column(db.String(200))
    razorpay_order_id = db.Column(db.String(200))
    razorpay_payment_id = db.Column(db.String(200))
    revoked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------- PRICING & HUBS ----------
DIST_PATH = os.path.join(basedir, "data", "distances.json")
HUB_COORDS_PATH = os.path.join(basedir, "data", "hub_coords.json")

try:
    with open(DIST_PATH, 'r', encoding='utf-8') as f:
        DIST_FILE = json.load(f)
        DIST_DATA = DIST_FILE.get("distances_km", {}) if isinstance(DIST_FILE, dict) else {}
except Exception:
    DIST_DATA = {}

HUB_NAMES = []
if DIST_DATA:
    HUB_NAMES = sorted(list(DIST_DATA.keys()))
else:
    try:
        with open(HUB_COORDS_PATH, 'r', encoding='utf-8') as f:
            hub_coords = json.load(f)
            if isinstance(hub_coords, dict):
                HUB_NAMES = sorted(list(hub_coords.keys()))
    except Exception:
        HUB_NAMES = []

BASE_FARE = 10.0
PER_KM = 2.0
DISCOUNTS = {
    "Student": 0.7,
    "Senior Citizen": 0.8,
    "General": 0.9
}

def compute_pass_prices(start_hub, dest_hub, category, pass_type):
    dmap = DIST_DATA if DIST_DATA else {}
    dist = None
    if dmap.get(start_hub) and dmap[start_hub].get(dest_hub) is not None:
        dist = dmap[start_hub][dest_hub]
    elif dmap.get(dest_hub) and dmap[dest_hub].get(start_hub) is not None:
        dist = dmap[dest_hub][start_hub]
    if dist is None:
        dist = 5.0
    raw = BASE_FARE + (dist * PER_KM)
    daily = round(raw, 2)
    weekly = round(raw * 5 * 0.95, 2)
    monthly = round(raw * 22 * 0.85, 2)
    mult = DISCOUNTS.get(category, 1.0)
    prices = {
        "distance_km": dist,
        "daily": round(daily * mult, 2),
        "weekly": round(weekly * mult, 2),
        "monthly": round(monthly * mult, 2)
    }
    return prices

# ---------- HELPERS ----------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def save_file_with_uuid(uploaded_file):
    filename = secure_filename(uploaded_file.filename)
    ext = filename.rsplit(".", 1)[1].lower()
    new_name = f"{uuid.uuid4().hex}.{ext}"
    out_dir = os.path.join("static", "uploads")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, new_name)
    uploaded_file.save(path)
    return path

def send_email_otp(to_email, otp):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        return False, "SMTP not configured (set SMTP_HOST/SMTP_USER/SMTP_PASS)"
    try:
        msg = MIMEMultipart()
        msg["From"] = FROM_EMAIL
        msg["To"] = to_email
        msg["Subject"] = "Your Smart Bus Pass OTP"
        body = f"Your Smart Bus Pass OTP is: {otp}\n\nThis OTP is valid for {OTP_EXPIRY_SECONDS//60} minute(s)."
        msg.attach(MIMEText(body, "plain"))
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10)
        server.ehlo()
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(FROM_EMAIL, to_email, msg.as_string())
        server.quit()
        return True, None
    except Exception as e:
        logger.exception("send_email_otp failed")
        return False, str(e)

# QR base URL helper: prefer PUBLIC_BASE_URL env var, else try to detect LAN IP, else fallback to request.host_url
def get_base_url():
    # 1) explicit env var (useful for ngrok / public host)
    pub = os.getenv("PUBLIC_BASE_URL")
    if pub:
        # ensure trailing slash
        return pub.rstrip('/') + '/'
    # 2) try detect local LAN IP (so phone on same Wi-Fi can reach)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # connect to public DNS to determine outbound interface (no data sent)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        port = int(os.getenv("PORT", 5000))
        return f"http://{ip}:{port}/"
    except Exception:
        # 3) fallback (request context must be present)
        try:
            return request.host_url
        except Exception:
            return "http://127.0.0.1:5000/"

# OCR helpers
def preprocess_image_for_ocr(path):
    img = Image.open(path).convert('L')
    w, h = img.size
    if w < 1000:
        factor = max(1.5, 1000 / w)
        img = img.resize((int(w * factor), int(h * factor)), Image.LANCZOS)
    img = ImageOps.autocontrast(img)
    img = img.filter(ImageFilter.MedianFilter(size=3))
    try:
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        threshold = int(max(100, min(180, avg * 0.95)))
    except Exception:
        threshold = 140
    img = img.point(lambda p: 255 if p > threshold else 0)
    return img

def preprocess_image_variations(path):
    imgs = []
    try:
        orig = Image.open(path).convert('L')
        imgs.append(orig)
        imgs.append(ImageOps.autocontrast(orig))
        imgs.append(preprocess_image_for_ocr(path))
        try:
            imgs.append(orig.filter(ImageFilter.UnsharpMask(radius=1, percent=120, threshold=3)))
        except Exception:
            pass
    except Exception:
        pass
    return imgs

def extract_text_multi(path):
    candidates = preprocess_image_variations(path)
    all_text = []
    for img in candidates:
        try:
            txt = pytesseract.image_to_string(img, lang='eng')
            if txt and txt.strip():
                all_text.append(txt)
        except Exception:
            continue
    lines = []
    for block in all_text:
        for ln in block.splitlines():
            ln = ln.strip()
            if ln and ln not in lines:
                lines.append(ln)
    return "\n".join(lines)

def clean_text(s):
    s = (s or "").lower()
    s = re.sub(r'[^a-z0-9\s]', ' ', s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def seq_ratio(a, b):
    return SequenceMatcher(None, a, b).ratio()

def name_matches(extracted_text, user_name):
    ex = clean_text(extracted_text)
    name = clean_text(user_name)
    if not ex or not name:
        return False
    if name in ex:
        return True
    name_tokens = [t for t in name.split() if len(t) >= 2]
    ex_tokens = set(ex.split())
    matched = sum(1 for t in name_tokens if t in ex_tokens)
    if name_tokens:
        overlap_ratio = matched / max(len(name_tokens), 1)
        if overlap_ratio >= 0.6:
            return True
    r = seq_ratio(ex, name)
    if r >= 0.6:
        return True
    for t in name_tokens:
        for ex_t in ex_tokens:
            if seq_ratio(t, ex_t) >= 0.8:
                return True
    return False

def find_aadhaar_in_text(text):
    if not text:
        return None
    t = text.lower()
    m2 = re.search(r"(\d{12})", t)
    if m2:
        return m2.group(1)
    m = re.search(r"(\d{4}\s?\d{4}\s?\d{4})", t)
    if m:
        return re.sub(r"\s+", "", m.group(1))
    m_masked = re.search(r"([xX\*]{4}\s?[xX\*]{4}\s?(\d{4}))", text)
    if m_masked:
        last4 = m_masked.group(2)
        return "XXXXXXXX" + last4
    m_last4 = re.search(r"([xX\*]{2,}\s*\d{2,4}\s*\d{0,4})(\d{4})", text)
    if m_last4:
        return "XXXXXXXX" + m_last4.group(2)
    return None

def is_aadhaar_document(text):
    txt = (text or "").lower()
    aadnum = find_aadhaar_in_text(txt)
    if aadnum:
        return True
    keywords = ["aadhaar", "uidai", "unique identification", "government of india", "eaadhaar", "aadhar", "india"]
    for kw in keywords:
        if kw in txt:
            return True
    return False

DATE_PATTERNS = [r"(\d{2}[-/]\d{2}[-/]\d{4})", r"(\d{4}[-/]\d{2}[-/]\d{2})", r"(\d{2}\s\w{3}\s\d{4})", r"(\d{2}\.\d{2}\.\d{4})", r"(\d{2}[-/]\d{2}[-/]\d{2})"]

def parse_date_from_string(s):
    s = s.strip()
    formats = ["%d-%m-%Y", "%d/%m/%Y", "%Y-%m-%d", "%d %b %Y", "%d.%m.%Y", "%d-%m-%y", "%d/%m/%y"]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass
    try:
        parts = re.split(r"[\/\-\.\s]", s)
        parts = [p for p in parts if p]
        if len(parts) == 3:
            d = int(parts[0]); m = int(parts[1]); y = int(parts[2])
            return date(y, m, d)
    except Exception:
        pass
    return None

def check_id_not_expired(extracted_text):
    txt = (extracted_text or "").lower()
    today_dt = date.today()
    expiry_keywords = ['exp', 'expiry', 'valid', 'valid till', 'valid upto', 'valid until', 'expires', 'validity', 'valid thru']
    for kw in expiry_keywords:
        pattern = rf"{kw}[^0-9\w\.\-/\,]{{0,40}}([0-9\-\./\sA-Za-z,]{{5,30}})"
        m = re.search(pattern, txt)
        if m:
            nearby = m.group(1)
            for pat in DATE_PATTERNS:
                mm = re.search(pat, nearby)
                if mm:
                    dt = parse_date_from_string(mm.group(1))
                    if dt:
                        if dt < today_dt:
                            return (False, dt, "ID expiry found and expired")
                        else:
                            return (True, dt, "ID expiry found and valid")
    return (None, None, "No explicit expiry info found")

def find_dob_in_text(text):
    if not text:
        return None
    t = text
    patterns = [
        r"date of birth[:\s]*([0-9]{1,2}[\/\-\.\s][0-9]{1,2}[\/\-\.\s][0-9]{2,4})",
        r"dob[:\s]*([0-9]{1,2}[\/\-\.\s][0-9]{1,2}[\/\-\.\s][0-9]{2,4})",
        r"([0-9]{1,2}[\/\-\.\s][A-Za-z]{3,}[\/\-\.\s][0-9]{4})",
        r"([0-9]{2}[\/\-\.\s][0-9]{2}[\/\-\.\s][0-9]{4})",
        r"([0-9]{2}[\/\-\.\s][0-9]{2}[\/\-\.\s][0-9]{2})"
    ]
    for pat in patterns:
        m = re.search(pat, t, re.IGNORECASE)
        if m:
            dt = parse_date_from_string(m.group(1))
            if dt:
                return dt
    mm = re.search(r"(\d{2}[-/\.]\d{2}[-/\.]\d{4})", t)
    if mm:
        dt = parse_date_from_string(mm.group(1))
        return dt
    return None

def find_student_id_in_text(text):
    if not text:
        return None
    t = text
    patterns = [
        r"roll(?:\s*no|number)?[:\s]*([a-zA-Z0-9\-\/]{4,30})",
        r"regn(?:\s*no|istration)?[:\s]*([a-zA-Z0-9\-\/]{4,30})",
        r"enrol(?:ment|l)?(?:\s*no|number)?[:\s]*([a-zA-Z0-9\-\/]{4,30})",
        r"student\s*id[:\s]*([a-zA-Z0-9\-\/]{4,30})",
        r"stud id[:\s]*([a-zA-Z0-9\-\/]{4,30})",
        r"id\s*no[:\s]*([A-Z0-9\-\/]{4,30})"
    ]
    for pat in patterns:
        m = re.search(pat, t, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    m2 = re.search(r"\b(crn|urn|reg|roll)[\:\s\-]*([A-Z0-9\/\-]{3,30})\b", t, re.IGNORECASE)
    if m2:
        return m2.group(2).strip()
    m3 = re.search(r"\b([A-Z0-9]{2,}\d{2,}[A-Z0-9\-\/]{0,15})\b", t, re.IGNORECASE)
    if m3:
        token = m3.group(1)
        if not re.fullmatch(r"\d{4}", token):
            return token.strip()
    return None

def find_college_name_in_text(text, known_colleges=None, threshold=0.6):
    if not text:
        return None, 0.0
    txt = clean_text(text)
    default_colleges = [
        "guru nanak dev engineering college ludhiana",
        "guru nanak dev engineering college",
        "guru nanak dev college",
        "gndec ludhiana",
        "guru nanak dev"
    ]
    known = known_colleges or default_colleges
    best = (None, 0.0)
    for c in known:
        c_clean = clean_text(c)
        score = seq_ratio(txt, c_clean)
        if c_clean in txt:
            score = max(score, 0.95)
        if score > best[1]:
            best = (c, score)
    if best[1] >= threshold:
        return best
    return None, 0.0

def is_valid_name(name):
    if not name:
        return False
    name = name.strip()
    if not name:
        return False
    return bool(re.fullmatch(r"[A-Za-z]+(?:\s+[A-Za-z]+)*", name))

def is_valid_phone(phone):
    return bool(re.fullmatch(r"\d{10}", (phone or "").strip()))

def is_valid_pincode(pin):
    return bool(re.fullmatch(r"\d{6}", (pin or "").strip()))

def is_valid_email(email):
    return bool(re.fullmatch(r"[^@]+@[^@]+\.[^@]+", (email or "").strip()))

def is_valid_aadhaar(a):
    return bool(re.fullmatch(r"\d{12}", (a or "").strip()))

def calculate_age(dob_str):
    try:
        dob = datetime.strptime(dob_str, "%Y-%m-%d").date()
    except Exception:
        return -1
    today = date.today()
    return today.year - dob.year - ((today.month, today.day) < (dob.month, dob.day))

# ---------- ROUTES ----------
@app.after_request
def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route("/")
def home():
    return redirect("/register")

# --- register / OTP / OCR routes (restored) ---
@app.route("/register", methods=["GET", "POST"])
def register():
    hubs = HUB_NAMES or []

    if request.method == "GET":
        if session.get("otp_sent") and not session.get("registration_complete"):
            return redirect("/verify-otp")
        if session.get("registration_complete"):
            session.pop("registration_complete", None)
            return render_template("success.html", name=session.get("user", {}).get("name"))
        return render_template("register.html", today="", form={}, errors={}, hubs=hubs)

    form = {k: request.form.get(k, "").strip() for k in [
        "name","dob","aadhaar","phone","email","category","pass_type",
        "address","city","district","pincode","starting_from","destination","start_date"
    ]}

    errors = {}
    required = ["name","dob","aadhaar","email","address","city","district","pincode","starting_from","destination","category","pass_type"]
    for r in required:
        if not form.get(r):
            errors[r] = "This field is required."

    age = calculate_age(form["dob"])
    if age < 18:
        errors["dob"] = "You must be at least 18 years old to register."

    if not is_valid_name(form["name"]):
        errors["name"] = "Name should contain only letters and spaces (2-120 chars)."

    if not is_valid_email(form["email"]):
        errors["email"] = "Enter a valid email address."

    if not is_valid_phone(form["phone"]):
        errors["phone"] = "Phone must be 10 digits."

    if not is_valid_pincode(form["pincode"]):
        errors["pincode"] = "Pincode must be 6 digits."

    if not is_valid_aadhaar(form["aadhaar"]):
        errors["aadhaar"] = "Aadhaar must be 12 digits."

    if form.get("category") == "Senior Citizen" and age < 60:
        errors["dob"] = "Selected Senior Citizen but age < 60."

    if HUB_NAMES:
        if form.get("starting_from") not in HUB_NAMES:
            errors["starting_from"] = "Please select a Starting point from the allowed list."
        if form.get("destination") not in HUB_NAMES:
            errors["destination"] = "Please select a Destination from the allowed list."

    id_file = request.files.get("id_proof")
    photo_file = request.files.get("photo")

    if not id_file or id_file.filename == "":
        errors["id_proof"] = "ID proof image is required."
    if not photo_file or photo_file.filename == "":
        errors["photo"] = "Passport photo is required."

    for f_label, f in (("id_proof", id_file), ("photo", photo_file)):
        if f and f.filename:
            if not allowed_file(f.filename):
                errors[f_label] = "Only JPG/JPEG/PNG files allowed."
            else:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(0)
                if size > MAX_FILE_SIZE:
                    errors[f_label] = "Uploaded file too large (max 5MB)."

    if errors:
        return render_template("register.html", today="", form=form, errors=errors, hubs=hubs)

    id_path = save_file_with_uuid(id_file)
    photo_path = save_file_with_uuid(photo_file)
    session["user"] = dict(form, id_path=id_path, photo_path=photo_path)

    otp = str(random.randint(100000, 999999))
    session["otp"] = otp
    session["otp_time"] = time.time()
    session["otp_sent"] = True
    session["resend_count"] = 0
    session["last_resend_time"] = 0

    ok, err = send_email_otp(form["email"], otp)
    if not ok:
        return render_template("register.html", today="", form=form, errors={"_top": f"Error sending OTP: {err}"}, hubs=hubs)

    return redirect("/verify-otp")


@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "user" not in session:
        return redirect("/register")
    if request.method == "POST":
        entered = request.form.get("otp", "").strip()
        stored = session.get("otp")
        otp_time = session.get("otp_time")
        if not stored or not otp_time:
            return "No OTP found. Please register again."
        if time.time() - otp_time > OTP_EXPIRY_SECONDS:
            return "OTP expired. Please request resend."
        if entered == stored:
            session["otp_verified"] = True
            return redirect("/verify-ocr")
        else:
            expires_in = max(0, int(OTP_EXPIRY_SECONDS - (time.time() - otp_time)))
            return render_template("verify_otp.html", expires_in=expires_in, error="OTP invalid. Try again.")
    expires_in = None
    if session.get("otp_time"):
        expires_in = max(0, int(OTP_EXPIRY_SECONDS - (time.time() - session["otp_time"])) )
    return render_template("verify_otp.html", expires_in=expires_in, error=None)


@app.route("/resend-otp")
def resend_otp():
    if "user" not in session:
        return redirect("/register")
    now = time.time()
    last = session.get("last_resend_time", 0)
    count = session.get("resend_count", 0)
    if count >= MAX_RESENDS:
        return f"Max resends reached ({MAX_RESENDS}). Please try again later."
    if now - last < RESEND_COOLDOWN_SECONDS:
        wait = int(RESEND_COOLDOWN_SECONDS - (now - last))
        return f"Please wait {wait}s before resending OTP."
    otp = str(random.randint(100000, 999999))
    session["otp"] = otp
    session["otp_time"] = now
    session["resend_count"] = count + 1
    session["last_resend_time"] = now
    ok, err = send_email_otp(session["user"].get("email"), otp)
    if not ok:
        return f"Error sending OTP by email: {err}"
    return redirect("/verify-otp")


@app.route("/verify-ocr")
def verify_ocr():
    user = session.get("user")
    if not user:
        return redirect("/register")
    if not session.get("otp_verified"):
        return redirect("/verify-otp")

    id_path = user.get("id_path")
    if not id_path:
        return render_template("rejected.html", name=user.get("name"), primary="ID proof not uploaded", details="", debug="")

    try:
        extracted_text = extract_text_multi(id_path)
    except Exception as e:
        logger.exception("OCR error")
        return render_template("rejected.html", name=user.get("name"), primary=f"OCR error: {e}", details="", debug="")

    logger.info("OCR text:\n%s", extracted_text)

    reasons = []
    debug_lines = extracted_text or ""
    name_ok = name_matches(extracted_text, user["name"])
    if name_ok:
        reasons.append("Name matched with ID.")
    else:
        reasons.append("Name did NOT match with ID.")

    aadhaar_found = find_aadhaar_in_text(extracted_text)
    aadhaar_doc = is_aadhaar_document(extracted_text)
    aadhaar_ok = False
    if aadhaar_found:
        if aadhaar_found.startswith("XXXX") or aadhaar_found.startswith("XXXXXXXX"):
            last4 = aadhaar_found[-4:]
            if user.get("aadhaar", "").endswith(last4):
                aadhaar_ok = True
            reasons.append(f"Aadhaar-like found (masked): {aadhaar_found} — {'last-4 matches' if aadhaar_ok else 'last-4 DOES NOT match provided Aadhaar'}")
        else:
            if aadhaar_found == user.get("aadhaar"):
                aadhaar_ok = True
            reasons.append(f"Aadhaar-like found: {aadhaar_found} — {'matches' if aadhaar_ok else 'mismatch with provided Aadhaar'}")
    else:
        reasons.append("No Aadhaar-like number found in ID text.")

    dob_on_id = find_dob_in_text(extracted_text)
    dob_ok = False
    user_dob_obj = None
    try:
        user_dob_obj = datetime.strptime(user.get("dob", ""), "%Y-%m-%d").date()
    except Exception:
        user_dob_obj = None

    if dob_on_id:
        if user_dob_obj and dob_on_id == user_dob_obj:
            dob_ok = True
            reasons.append(f"DOB on ID matched ({dob_on_id.isoformat()}).")
        else:
            reasons.append(f"DOB on ID found ({dob_on_id.isoformat()}) — does NOT match provided DOB.")
    else:
        reasons.append("No DOB detected on ID.")

    expiry_status, expiry_dt, expiry_msg = check_id_not_expired(extracted_text)
    if expiry_status is False:
        primary = f"ID appears expired ({expiry_dt})."
        details = " ; ".join(reasons)
        return render_template("rejected.html", name=user.get("name"), primary=primary, details=details, debug=debug_lines)
    elif expiry_status is True:
        reasons.append(f"ID expiry detected and valid ({expiry_dt}).")
    else:
        reasons.append("No explicit expiry info found on ID (assume not expired unless expiry printed).")

    category = (user.get("category") or "").strip().lower()
    accepted = False
    primary = ""
    details = ""

    if category == "student":
        if aadhaar_doc:
            primary = "Student category requires Student ID — Aadhaar uploaded (not allowed)."
            details = "Aadhaar detected in uploaded document. Student verification requires a Student ID or college ID card."
            return render_template("rejected.html", name=user.get("name"), primary=primary, details=details, debug=debug_lines)

        student_id_found = find_student_id_in_text(extracted_text)
        matched_college, score = find_college_name_in_text(extracted_text)

        if (student_id_found or matched_college) and name_ok:
            accepted = True
            if student_id_found:
                reasons.append(f"Student ID number found on document: {student_id_found}.")
            else:
                reasons.append(f"College name detected: '{matched_college}' (score {score:.2f}).")
            reasons.append("Student accepted: name matched and student-ID/college present; ID not expired.")
        else:
            accepted = False
            if not (student_id_found or matched_college):
                primary = "Student verification failed: No student ID or college name detected on uploaded document."
            elif not name_ok:
                primary = "Student verification failed: Name on uploaded document does not match entered name."
            else:
                primary = "Student verification failed."
            details = " ; ".join(reasons)

    elif category in ("general", "senior citizen"):
        if not aadhaar_doc:
            primary = f"{category.title()} category requires Aadhaar document. Uploaded document does not look like Aadhaar."
            details = " ; ".join(reasons)
            return render_template("rejected.html", name=user.get("name"), primary=primary, details=details, debug=debug_lines)

        missing = []
        if not aadhaar_ok:
            missing.append("Aadhaar number on uploaded ID does NOT match the Aadhaar entered in the form.")
        if not name_ok:
            missing.append("Name on ID does NOT match the entered name.")
        if not dob_ok:
            missing.append("DOB on ID does NOT match the entered DOB.")
        if missing:
            accepted = False
            primary = missing[0]
            details = " ; ".join(reasons)
        else:
            accepted = True
            reasons.append(f"{category.title()} accepted: Aadhaar, Name and DOB all matched, ID not expired.")
            primary = ""

    else:
        if aadhaar_doc and (aadhaar_ok and name_ok and dob_ok):
            accepted = True
            reasons.append("Accepted via Aadhaar/Name/DOB strict match (fallback).")
        else:
            accepted = False
            primary = "Verification failed: Aadhaar/Name/DOB did not strictly match (fallback)."
            details = " ; ".join(reasons)

    # ---------- ACCEPTED BRANCH ----------
    if accepted:
        new_user = User(
            name=user.get("name"),
            dob=user.get("dob"),
            aadhaar=user.get("aadhaar"),
            phone=user.get("phone"),
            email=user.get("email"),
            category=user.get("category"),
            pass_type=user.get("pass_type"),
            id_proof=user.get("id_path"),
            photo=user.get("photo_path"),
            address=user.get("address"),
            city=user.get("city"),
            district=user.get("district"),
            pincode=user.get("pincode"),
            starting_from=user.get("starting_from"),
            destination=user.get("destination"),
            issue_date=user.get("start_date"),
            verified=True
        )
        db.session.add(new_user)
        db.session.commit()

        # Save the new user's id so we can redirect to buy-pass page
        session["registered_user_id"] = new_user.id

        # clear only OTP-related/session temp keys (keep registered_user_id)
        for k in ["otp","otp_time","otp_sent","otp_verified","resend_count","last_resend_time"]:
            session.pop(k, None)

        # Redirect straight to the payment / buy-pass page for this user
        return redirect(url_for("buy_pass", user_id=new_user.id))
    # ---------- END accepted branch ----------

    else:
        if not primary:
            primary = "Verification failed. See details for why."
            details = " ; ".join(reasons)
        return render_template("rejected.html", name=user.get("name"), primary=primary, details=details, debug=debug_lines)


@app.route("/cancel-registration")
def cancel_registration():
    for k in ["user", "otp", "otp_time", "otp_sent", "otp_verified", "registration_complete", "resend_count", "last_resend_time"]:
        session.pop(k, None)
    return redirect("/register")

# ---------- BUY PASS RENDER ROUTE ----------
@app.route("/buy-pass/<int:user_id>")
def buy_pass(user_id):
    if not user_id:
        user_id = session.get("registered_user_id")
        if not user_id:
            return redirect(url_for("home"))
    user = User.query.get(user_id)
    if not user:
        return redirect(url_for("home"))
    ctx = {
        "user_id": user_id,
        "user_name": user.name if user else "",
        "user_email": user.email if user else "",
        "user_phone": user.phone if user else "",
        "start_hub": user.starting_from if user else "",
        "dest_hub": user.destination if user else "",
        "user_category": user.category if user else "",
        "hubs": HUB_NAMES
    }
    return render_template("purchase.html", **ctx)

@app.route("/price", methods=["POST"])
def get_price():
    data = request.get_json() or {}
    start = data.get("start_hub", "") or ""
    dest = data.get("dest_hub", "") or ""
    category = data.get("category", "") or "General"
    pass_type = data.get("pass_type", "") or "Monthly"

    if not start or not dest:
        return jsonify({"status": "error", "msg": "start_hub and dest_hub required"}), 400

    if HUB_NAMES:
        if start not in HUB_NAMES or dest not in HUB_NAMES:
            return jsonify({"status": "error", "msg": "start or dest hub invalid"}), 400

    try:
        prices = compute_pass_prices(start, dest, category, pass_type)
    except Exception:
        logger.exception("price calc failed")
        return jsonify({"status": "error", "msg": "price calculation failed"}), 500

    keyname = pass_type.strip().lower()
    amount = prices.get(keyname, prices.get("monthly"))
    return jsonify({
        "status": "ok",
        "distance_km": prices.get("distance_km"),
        "daily": prices.get("daily"),
        "weekly": prices.get("weekly"),
        "monthly": prices.get("monthly"),
        "amount": amount
    })

@app.route("/create-order", methods=["POST"])
def create_order():
    data = None
    if request.is_json:
        data = request.get_json() or {}
    else:
        data = {k: v for k, v in request.form.items()}

    required = ["user_id","pass_type","start_hub","dest_hub","category"]
    for r in required:
        if r not in data or (isinstance(data.get(r), str) and data.get(r).strip() == ""):
            return jsonify({"status":"error","msg":f"missing {r}"}), 400

    if HUB_NAMES:
        if data["start_hub"] not in HUB_NAMES or data["dest_hub"] not in HUB_NAMES:
            return jsonify({"status":"error","msg":"start or dest hub invalid"}), 400

    try:
        prices = compute_pass_prices(data["start_hub"], data["dest_hub"], data["category"], data["pass_type"])
        keyname = (data.get("pass_type") or "monthly").strip().lower()
        amount = prices.get(keyname, prices["monthly"])
        amount_paise = int(round(amount * 100))
    except Exception:
        logger.exception("price calc error")
        return jsonify({"status":"error","msg":"price calculation failed"}), 500

    try:
        new_pass = Pass(
            user_id = int(data["user_id"]),
            pass_type = data["pass_type"],
            start_hub = data["start_hub"],
            dest_hub = data["dest_hub"],
            distance_km = prices["distance_km"],
            price = amount,
            valid_from = data.get("valid_from",""),
            valid_to = data.get("valid_to","")
        )
        db.session.add(new_pass)
        db.session.commit()
    except Exception:
        logger.exception("db save pass failed")
        return jsonify({"status":"error","msg":"db save failed"}), 500

    if DEMO_MODE:
        order = {"id": f"test_order_{new_pass.id}"}
        new_pass.razorpay_order_id = order["id"]
        db.session.commit()
        # For demo, provide a view_url if token available (handy for testing)
        base = get_base_url()
        demo_token = new_pass.qr_token or ""
        view_url = (base + f"view-pass/{new_pass.id}?token={demo_token}") if demo_token else None
        return jsonify({"order_id": order["id"], "amount": amount_paise, "pass_id": new_pass.id, "key": None, "view_url": view_url})

    if not rz_client:
        logger.error("Razorpay keys not configured but DEMO_MODE is false.")
        return jsonify({"status":"error","msg":"Razorpay keys missing in environment (set RAZORPAY_KEY_ID/RAZORPAY_KEY_SECRET)"}), 500

    try:
        order = rz_client.order.create({
            "amount": amount_paise,
            "currency": "INR",
            "receipt": f"pass_{new_pass.id}",
            "payment_capture": 1
        })
    except Exception:
        logger.exception("razorpay order create failed")
        return jsonify({"status":"error","msg":"razorpay order create failed"}), 500

    new_pass.razorpay_order_id = order["id"]
    db.session.commit()

    return jsonify({"order_id": order["id"], "amount": amount_paise, "pass_id": new_pass.id, "key": RAZORPAY_KEY_ID})

@app.route("/confirm-payment", methods=["POST"])
def confirm_payment():
    payload = request.get_json() or {}
    p_id = payload.get("razorpay_payment_id")
    o_id = payload.get("razorpay_order_id")
    signature = payload.get("razorpay_signature")
    pass_id = payload.get("pass_id")

    if not all([p_id, o_id, signature, pass_id]):
        return jsonify({"status":"error","msg":"missing fields"}), 400
    try:
        if rz_client:
            rz_client.utility.verify_payment_signature({
                "razorpay_order_id": o_id,
                "razorpay_payment_id": p_id,
                "razorpay_signature": signature
            })
    except SignatureVerificationError:
        return jsonify({"status":"error","msg":"Signature verification failed"}), 400
    except Exception:
        logger.exception("verify signature error")
        return jsonify({"status":"error","msg":"Signature verification failed"}), 400

    p = Pass.query.get(pass_id)
    if not p:
        return jsonify({"status":"error","msg":"pass not found"}), 404

    p.paid = True
    p.razorpay_payment_id = p_id
    token = uuid.uuid4().hex
    p.qr_token = token

    # If valid_from/to empty, set automatic valid_from = today, valid_to based on pass_type
    try:
        if not p.valid_from:
            vf = date.today()
            p.valid_from = vf.isoformat()
        if not p.valid_to:
            days = 30
            pt = (p.pass_type or "").lower()
            if pt == "daily":
                days = 1
            elif pt == "weekly":
                days = 7
            elif pt == "monthly":
                days = 30
            vt = datetime.strptime(p.valid_from, "%Y-%m-%d").date() + timedelta(days=days - 1)
            p.valid_to = vt.isoformat()
    except Exception:
        # fallback: set valid_to = today + 30
        p.valid_to = (date.today() + timedelta(days=30)).isoformat()

    db.session.commit()

    # Build a base URL reachable by phone: PUBLIC_BASE_URL env -> detect LAN IP -> fallback to request.host_url
    base = get_base_url().rstrip('/') + '/'
    view_url = urljoin(base, f"view-pass/{p.id}?token={token}")

    # Save QR image (encode view_url)
    img = qrcode.make(view_url)
    path = os.path.join("static","passes", f"pass_{p.id}.png")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)

    return jsonify({"status":"ok","pass_id":p.id,"qr_image": f"/static/passes/pass_{p.id}.png","view_url": view_url})

@app.route("/api/verify-pass", methods=["POST"])
def api_verify_pass():
    data = request.get_json() or {}
    token = data.get("token")
    if not token:
        return jsonify({"ok": False, "reason":"no token"}), 400
    p = Pass.query.filter_by(qr_token=token).first()
    if not p:
        return jsonify({"ok": False, "reason":"pass not found"}), 404
    if not p.paid:
        return jsonify({"ok": False, "reason":"payment not completed"}), 403
    if p.revoked:
        return jsonify({"ok": False, "reason":"revoked"}), 403

    try:
        if p.valid_from:
            vf = datetime.strptime(p.valid_from, "%Y-%m-%d").date()
            if date.today() < vf:
                return jsonify({"ok": False, "reason":"not yet valid"}), 403
        if p.valid_to:
            vt = datetime.strptime(p.valid_to, "%Y-%m-%d").date()
            if date.today() > vt:
                return jsonify({"ok": False, "reason":"expired"}), 403
    except Exception:
        pass

    user = User.query.get(p.user_id)
    return jsonify({"ok": True, "pass_id": p.id, "name": user.name if user else None, "valid_to": p.valid_to})

# ---------- View Pass page ----------
@app.route("/view-pass/<int:pass_id>")
def view_pass(pass_id):
    token = request.args.get("token", "")
    p = Pass.query.get(pass_id)
    if not p:
        return render_template("rejected.html", name="", primary="Pass not found", details=""), 404

    # require token to match p.qr_token
    if not token or token != p.qr_token:
        return render_template("rejected.html", name="", primary="Invalid or missing token", details=""), 403

    user = User.query.get(p.user_id)
    # compute status
    status = "valid"
    today_dt = date.today()
    try:
        if p.valid_from:
            vf = datetime.strptime(p.valid_from, "%Y-%m-%d").date()
            if today_dt < vf:
                status = "not_yet_valid"
        if p.valid_to:
            vt = datetime.strptime(p.valid_to, "%Y-%m-%d").date()
            if today_dt > vt:
                status = "expired"
    except Exception:
        pass

    view_qr_path = f"/static/passes/pass_{p.id}.png"
    return render_template("view_pass.html", pass_obj=p, user=user, qr_path=view_qr_path, status=status)

# ---------- Renew pass endpoint ----------
@app.route("/renew-pass/<int:pass_id>", methods=["POST"])
def renew_pass(pass_id):
    data = request.get_json() or {}
    token = data.get("token")
    p = Pass.query.get(pass_id)
    if not p:
        return jsonify({"status":"error","msg":"pass not found"}), 404
    if not token or token != p.qr_token:
        return jsonify({"status":"error","msg":"invalid token"}), 403
    if p.revoked:
        return jsonify({"status":"error","msg":"pass revoked"}), 403
    if not p.paid:
        return jsonify({"status":"error","msg":"pass not paid"}), 403

    pt = (p.pass_type or "").lower()
    days = 30
    if pt == "daily":
        days = 1
    elif pt == "weekly":
        days = 7
    elif pt == "monthly":
        days = 30

    try:
        cur_vt = datetime.strptime(p.valid_to, "%Y-%m-%d").date() if p.valid_to else None
    except Exception:
        cur_vt = None

    start_from = date.today()
    if cur_vt and cur_vt >= start_from:
        new_vt = cur_vt + timedelta(days=days)
    else:
        new_vt = start_from + timedelta(days=days - 1)
    p.valid_to = new_vt.isoformat()

    # regenerate a new token for security
    new_token = uuid.uuid4().hex
    p.qr_token = new_token

    # build view_url using reachable base
    base = get_base_url().rstrip('/') + '/'
    view_url = urljoin(base, f"view-pass/{p.id}?token={new_token}")
    img = qrcode.make(view_url)
    path = os.path.join("static","passes", f"pass_{p.id}.png")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    img.save(path)

    db.session.commit()
    return jsonify({"status":"ok","pass_id":p.id,"valid_to":p.valid_to,"view_url":view_url,"qr_image": f"/static/passes/pass_{p.id}.png"})

@app.route("/init-db")
def init_db():
    db.create_all()
    return "DB initialized! ✅"

if __name__ == "__main__":
    logger.info("Starting app (with QR->URL + renew). Listening on 0.0.0.0 so LAN devices can reach it.)")
    # host=0.0.0.0 so phone on same network can connect to your PC's LAN IP
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
