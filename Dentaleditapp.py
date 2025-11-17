import os
import random
import string
from datetime import datetime, date
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------
# CONFIGURATION
# ---------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_FILE = os.path.join(BASE_DIR, "dentalclinic.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = "supersecretkey"
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_FILE}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

db = SQLAlchemy(app)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "pdf"}


# -----------------------------
# Login & Role-Based Access Decorators
# -----------------------------
def login_required(f):
    """Ensure the user is logged in before accessing the route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def doctor_required(f):
    """Allow access only to doctors."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'doctor':
            flash('Access restricted to doctors only.', 'danger')
            return redirect(url_for('dashboard_main'))
        return f(*args, **kwargs)
    return decorated_function


def assistant_required(f):
    """Allow access only to assistants."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'assistant':
            flash('Access restricted to assistants only.', 'danger')
            return redirect(url_for('dashboard_main'))
        return f(*args, **kwargs)
    return decorated_function


def patient_required(f):
    """Allow access only to patients."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('role') != 'patient':
            flash('Access restricted to patients only.', 'danger')
            return redirect(url_for('dashboard_patient'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------------
# SYSTEMIC RISK PROTOCOLS (Decision Support)
# ---------------------------------
SYSTEMIC_PROTOCOLS = {
    "Cardiovascular": {
        "Ischemic Heart Disease / Post-MI": {
            "summary": "Stable angina / post-MI patients with controlled disease can be treated with precautions.",
            "red_flags": [
                "MI within last 30 days",
                "Unstable angina",
                "Severe shortness of breath at rest",
                "Ongoing chest pain"
            ],
            "safe_to_treat": "MI > 6 months ago, stable angina, no chest pain on exertion, vitals acceptable.",
            "vital_limits": {
                "bp": "Ideally <160/100 mmHg",
                "pulse": "<100 bpm at rest"
            },
            "investigations": [
                "Recent cardiology note if high risk",
                "List of cardiac medications"
            ],
            "local_anaesthesia": "Limit epinephrine to 0.04 mg per visit (≈ 2 carpules 1:100,000). Avoid vasoconstrictor if unstable.",
            "avoid_drugs": [
                "Avoid high doses of NSAIDs in patients on antiplatelets / ACE inhibitors",
                "Avoid adrenaline-impregnated retraction cords"
            ],
            "chairside_tips": [
                "Short, stress-free appointments",
                "Morning visits preferred",
                "Have nitroglycerin tablet/spray and oxygen in the room"
            ],
            "emergency": [
                "Stop procedure immediately for chest pain",
                "Sit patient upright",
                "Give Nitroglycerin 0.4 mg SL; repeat every 5 minutes up to 3 doses",
                "Give Oxygen 4–6 L/min",
                "If no relief in 10–15 minutes → activate emergency services"
            ]
        },
        "Hypertension": {
            "summary": "Most hypertensive patients can be treated with monitoring; very high BP requires deferral.",
            "red_flags": [
                "BP ≥ 180/110 mmHg at rest",
                "Headache, visual changes, chest pain, dyspnea"
            ],
            "vital_limits": {
                "treat": "BP <160/100 mmHg – elective care OK",
                "caution": "160–179 / 100–109 – urgent care with monitoring only",
                "defer": "≥180/110 – defer, refer to physician"
            },
            "local_anaesthesia": "Limit epinephrine to 0.04 mg per visit; inject slowly; aspirate.",
            "avoid_drugs": [
                "Avoid long-term NSAID use (can worsen BP control)",
                "Avoid sudden position changes in chair"
            ],
            "chairside_tips": [
                "Measure BP pre-op if history of hypertension",
                "Repeat BP if initially high; allow patient to rest"
            ]
        },
        "Valve Disease / IE Risk": {
            "summary": "Only a small subset of valve/CHD patients need infective endocarditis prophylaxis.",
            "ie_high_risk": [
                "Prosthetic heart valve",
                "Previous infective endocarditis",
                "Unrepaired cyanotic congenital heart disease",
                "Repaired CHD with residual defect or within 6 months",
                "Cardiac transplant with valve disease"
            ],
            "when_prophylaxis_needed": [
                "Dental procedures with manipulation of gingiva",
                "Periapical region manipulation",
                "Perforation of oral mucosa"
            ],
            "antibiotic_prophylaxis": {
                "standard_adult": "Amoxicillin 2 g PO 30–60 minutes before procedure",
                "pen_allergy_oral": "Azithromycin 500 mg PO or Cephalexin 2 g PO (avoid cephalosporins if anaphylactic penicillin allergy)",
                "no_oral_route": "Ampicillin 2 g IM/IV or Cefazolin/Ceftriaxone 1 g IM/IV"
            }
        }
    },

    "Bleeding / Antithrombotic": {
        "Warfarin (Vitamin K antagonist)": {
            "summary": "Most dental extractions and minor surgery are safe without stopping warfarin if INR ≤3.5.",
            "labs": [
                "Check INR within 24–72 hours of procedure, especially if multiple extractions or flaps planned"
            ],
            "safe_to_treat": "INR ≤3.5 for simple–moderate oral surgery with good local hemostasis.",
            "defer": "INR >3.5 – defer elective care; coordinate dose adjustment with physician.",
            "local_hemostasis": [
                "Atraumatic extraction technique",
                "Sutures (prefer horizontal mattress where possible)",
                "Local hemostatic agent (Surgicel, Gelfoam, collagen sponge)",
                "Tranexamic acid mouthwash 4.8%: 10 mL for 2 minutes, 4× daily for 2–5 days"
            ],
            "emergency": [
                "If persistent bleeding despite local measures → compress with gauze and refer to hospital",
                "Hospital options: Vitamin K, PCC, FFP as per physician"
            ]
        },
        "DOACs (Rivaroxaban, Apixaban, Dabigatran, Edoxaban)": {
            "summary": "Many minor dental procedures can be safely performed without stopping DOACs.",
            "timing": [
                "Schedule treatment 12–24 hours after last dose for minor work",
                "For higher-risk surgery, possible 24–48 hour interruption only with physician approval"
            ],
            "local_hemostasis": [
                "Same local measures as warfarin patients",
                "Avoid multiple surgical sites in one session if possible"
            ],
            "restart": "Usually restart DOAC 24 hours after hemostasis is secure (per physician advice)."
        },
        "Antiplatelets (Aspirin, Clopidogrel, DAPT)": {
            "summary": "Do NOT routinely stop antiplatelet drugs for dental procedures.",
            "principles": [
                "Single or dual antiplatelet therapy usually continued",
                "Only consider change after cardiologist approval, especially post-stent",
                "Rely on local hemostatic techniques"
            ]
        },
        "Inherited Bleeding Disorders (Hemophilia, vWD)": {
            "summary": "Always coordinate with a hematologist before invasive dental work.",
            "red_flags": [
                "Spontaneous joint or soft tissue bleeds",
                "History of excessive post-extraction bleeding"
            ],
            "pre_op": [
                "Factor VIII/IX replacement for Hemophilia as per hematologist",
                "DDAVP or factor for vWD where indicated",
                "Avoid IAN blocks in uncontrolled severe cases"
            ]
        }
    },

    "Diabetes": {
        "Type 1 / Type 2 Diabetes": {
            "summary": "Controlled diabetics can be treated normally with some precautions.",
            "vital_limits": {
                "rbs_safe": "80–200 mg/dL – routine care OK",
                "rbs_caution": "200–250 mg/dL – consider antibiotics for surgical procedures",
                "rbs_defer": ">250–300 mg/dL – defer elective care; coordinate with physician"
            },
            "chairside_tips": [
                "Prefer morning appointments after normal meal and medications",
                "Avoid long fasting",
                "Keep oral glucose (gel/juice) in clinic"
            ],
            "hypoglycemia_signs": [
                "Sweating, tremor, confusion, tachycardia, hunger"
            ],
            "hypoglycemia_management": [
                "Stop treatment",
                "Give oral glucose if conscious",
                "If unresponsive, place in recovery position and call emergency services"
            ],
            "post_op": [
                "Minimize traumatic surgery",
                "Consider prophylactic antibiotics for poorly controlled patients undergoing extractions/flaps",
                "Emphasize infection control and follow-up"
            ]
        }
    },

    "Respiratory": {
        "Asthma": {
            "summary": "Most asthmatic patients can be treated; keep inhaler accessible.",
            "red_flags": [
                "Frequent night-time symptoms",
                "Recent hospital admission / ICU",
                "Use of oral steroids"
            ],
            "chairside_tips": [
                "Ensure patient brings inhaler to each visit",
                "Avoid known triggers if history present",
                "Avoid sulfite-containing LA in severe steroid-dependent asthma"
            ],
            "avoid_drugs": [
                "Avoid aspirin and NSAIDs in aspirin-sensitive asthmatics"
            ],
            "emergency": [
                "At onset of bronchospasm: stop procedure, sit patient upright",
                "Give 2 puffs salbutamol inhaler, repeat as needed",
                "Give oxygen",
                "If no adequate response → refer urgently"
            ]
        },
        "COPD": {
            "summary": "Treat in semi-upright position; avoid oversedation and excessive oxygen in CO₂ retainers.",
            "tips": [
                "Avoid long, stressful procedures",
                "Use low-flow oxygen (2–3 L/min) if needed",
                "Avoid rubber dam if causes distress"
            ]
        }
    },

    "Liver / Kidney": {
        "Cirrhosis / Liver Failure": {
            "summary": "Bleeding risk and drug metabolism issues are the main concern.",
            "labs": [
                "INR/PT, LFTs, platelet count where indicated"
            ],
            "avoid_drugs": [
                "Avoid or limit NSAIDs",
                "Use paracetamol cautiously and within safe total daily dose",
                "Avoid hepatotoxic drugs"
            ]
        },
        "Chronic Kidney Disease / Dialysis": {
            "summary": "Schedule dental care the day after dialysis when possible.",
            "tips": [
                "Adjust dosages for renally excreted drugs (e.g. penicillins, acyclovir)",
                "Avoid NSAIDs where possible",
                "Check for heparin use on dialysis days"
            ]
        }
    },

    "Thyroid": {
        "Hyperthyroidism": {
            "summary": "Uncontrolled hyperthyroid patients are at risk of thyroid storm.",
            "red_flags": [
                "Tachycardia at rest",
                "Heat intolerance, tremor, weight loss"
            ],
            "local_anaesthesia": "Avoid epinephrine in uncontrolled hyperthyroidism; use plain LA.",
            "plan": "Defer elective care until thyroid status is controlled."
        },
        "Hypothyroidism": {
            "summary": "Over-sedation risk; slower metabolism of sedatives.",
            "tips": [
                "Short appointments in a warm environment",
                "Use sedatives with caution",
                "Monitor for excessive drowsiness"
            ]
        }
    },

    "Neurologic / Psychiatric": {
        "Epilepsy": {
            "summary": "Most controlled epileptic patients can be treated safely.",
            "tips": [
                "Ask about last seizure and triggers",
                "Schedule when patient is well-rested and medicated",
                "Keep mouth clear of instruments during potential seizure"
            ],
            "during_seizure": [
                "Stop procedure; remove instruments",
                "Do NOT put anything in the mouth",
                "Protect from injury, turn head to the side",
                "Call for medical help if seizure is prolonged (>5 minutes) or cluster occurs"
            ]
        },
        "Psychiatric Conditions": {
            "summary": "Many psych meds cause xerostomia and interact with epinephrine.",
            "avoid_drugs": [
                "Limit epinephrine in patients on tricyclic antidepressants",
                "Check for interactions if multiple psych medications"
            ],
            "tips": [
                "Provide clear explanations and reassurance",
                "Prefer short, structured appointments"
            ]
        }
    },

    "Gastrointestinal": {
        "Peptic Ulcer / GERD": {
            "summary": "Main concerns are NSAID use and reflux in supine position.",
            "avoid_drugs": [
                "Avoid aspirin and NSAIDs where possible",
                "Consider paracetamol-based analgesia"
            ],
            "tips": [
                "Treat in semi-upright position if reflux is significant",
                "Avoid heavy meals just before appointment"
            ]
        }
    }
}

# ---------------------------------
# DATABASE MODELS
# ---------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    temporary_password = db.Column(db.String(50))


# =========================================================
# 🧠 PATIENT MODEL (FULL — KEEPING ALL EXISTING FIELDS)
# =========================================================
class Patient(db.Model):
    __tablename__ = 'patients'

    id = db.Column(db.Integer, primary_key=True)
    file_no = db.Column(db.String(50), unique=True)
    full_name = db.Column(db.String(150))
    father_or_spouse_name = db.Column(db.String(150))
    gender = db.Column(db.String(20))
    dob_or_age = db.Column(db.String(50))
    marital_status = db.Column(db.String(50))
    occupation = db.Column(db.String(100))
    contact = db.Column(db.String(50))
    email = db.Column(db.String(100))
    cnic = db.Column(db.String(20))
    address = db.Column(db.Text)
    date = db.Column(db.String(20), default=date.today().strftime("%Y-%m-%d"))
    created_by = db.Column(db.String(100))

    # -----------------------
    # 🩺 MEDICAL HISTORY
    # -----------------------
    heart_disease = db.Column(db.String(10))
    blood_pressure = db.Column(db.String(10))
    diabetes = db.Column(db.String(10))
    asthma = db.Column(db.String(10))
    tuberculosis = db.Column(db.String(10))
    hepatitis = db.Column(db.String(10))
    bleeding_disorder = db.Column(db.String(10))
    epilepsy = db.Column(db.String(10))
    thyroid_disorder = db.Column(db.String(10))
    kidney_disease = db.Column(db.String(10))
    stomach_ulcers = db.Column(db.String(10))
    psychiatric_disorder = db.Column(db.String(10))

    medications = db.Column(db.Text)
    allergies = db.Column(db.Text)
    other_health = db.Column(db.Text)

    pregnant = db.Column(db.String(10))
    breastfeeding = db.Column(db.String(10))
    pregnancy_weeks = db.Column(db.String(20))

    surgery_history = db.Column(db.Text)

    # -----------------------
    # 🪥 DENTAL HISTORY
    # -----------------------
    last_dental_visit = db.Column(db.String(50))
    last_dental_reason = db.Column(db.String(50))

    # Previous Treatment
    treat_fillings = db.Column(db.String(10))
    treat_rct = db.Column(db.String(10))
    treat_crowns = db.Column(db.String(10))
    treat_extractions = db.Column(db.String(10))
    treat_scaling = db.Column(db.String(10))
    treat_denture = db.Column(db.String(10))
    treat_braces = db.Column(db.String(10))
    treat_implant = db.Column(db.String(10))
    treat_other = db.Column(db.String(100))

    # Bad experience
    bad_experience = db.Column(db.String(10))
    bad_experience_details = db.Column(db.Text)

    # Gum health
    gum_bleeding = db.Column(db.String(10))
    gum_loose = db.Column(db.String(10))
    gum_badbreath = db.Column(db.String(10))
    gum_none = db.Column(db.String(10))

    # Caries / sensitivity
    sensitive_teeth = db.Column(db.String(10))
    frequent_cavities = db.Column(db.String(10))
    caries_none = db.Column(db.String(10))

    # Trauma
    fractured_tooth = db.Column(db.String(10))
    jaw_accident = db.Column(db.String(10))
    trauma_none = db.Column(db.String(10))

    # Prosthesis
    prosthesis_crown = db.Column(db.String(10))
    prosthesis_denture = db.Column(db.String(10))
    prosthesis_implant = db.Column(db.String(10))
    prosthesis_braces = db.Column(db.String(10))
    prosthesis_none = db.Column(db.String(10))

    # Habits
    uses_tobacco = db.Column(db.String(10))
    uses_naswar = db.Column(db.String(10))
    uses_paan = db.Column(db.String(10))
    uses_smoke = db.Column(db.String(10))

    smoking_frequency = db.Column(db.String(100))

    # NEW — TMJ and Oral Hygiene fields
    tmj_issue = db.Column(db.Text)
    tmj_notes = db.Column(db.Text)
    oral_hygiene = db.Column(db.Text)
    caries_risk = db.Column(db.Text)
    soft_tissue_notes = db.Column(db.Text)
    dental_notes = db.Column(db.Text)

    # 🧾 RELATIONSHIPS
    cases = db.relationship('Case', backref='patient', cascade="all, delete-orphan", lazy='joined')
    treatments = db.relationship('Treatment', backref='patient', cascade="all, delete-orphan", lazy='joined')
    visits = db.relationship('Visit', backref='patient', cascade="all, delete-orphan", lazy=True)

    def __repr__(self):
        return f"<Patient {self.full_name}>"



# =========================================================
# 📂 CASE MODEL
# =========================================================
# =========================================================
# 📂 CASE MODEL (UPDATED WITH DYNAMIC MEDICAL INFO)
# =========================================================
class Case(db.Model):
    __tablename__ = "cases"

    id = db.Column(db.Integer, primary_key=True)

    # 🌟 Unified Case Identifier (required)
    case_id = db.Column(db.String(50), unique=True, nullable=False)

    title = db.Column(db.String(150))
    chief_complaint = db.Column(db.String(255))
    diagnosis = db.Column(db.String(255))
    treatment_plan = db.Column(db.Text)

    start_date = db.Column(db.Date, default=date.today)
    status = db.Column(db.String(20), default="Active")

    # 🌟 Dynamic per-case medical info
    pregnant = db.Column(db.String(10))
    pregnancy_weeks = db.Column(db.String(20))
    breastfeeding = db.Column(db.String(10))
    new_medications = db.Column(db.Text)
    recent_illness = db.Column(db.Text)
    new_conditions = db.Column(db.Text)
    change_in_allergy_or_medication = db.Column(db.Text)

    # 🔗 Foreign Key → Patient
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"))

    # 🔗 Linked Treatments
    treatments = db.relationship(
        "Treatment",
        backref="case",
        cascade="all, delete-orphan",
        lazy="dynamic"
    )

    # 🌟 AUTO-GENERATE CASE-ID: CASE-<pid>-YYYYMMDD-NN
    def generate_case_id(self):
        today = date.today().strftime("%Y%m%d")
        prefix = f"CASE-{self.patient_id}-{today}"

        # Count today's cases for this patient (NOT global)
        count_today = Case.query.filter(
            Case.patient_id == self.patient_id,
            Case.case_id.like(f"{prefix}%")
        ).count()

        next_number = count_today + 1
        self.case_id = f"{prefix}-{next_number:02d}"

# =========================================================
# 🟦 VISIT MODEL (NEW — Each Appointment = 1 Visit)
# =========================================================
class Visit(db.Model):
    __tablename__ = 'visits'

    id = db.Column(db.Integer, primary_key=True)

    # Visit Date
    visit_date = db.Column(
        db.String(20),
        default=datetime.now().strftime("%Y-%m-%d")
    )

    # 🔗 Foreign Keys
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    doctor_id = db.Column(db.Integer, db.ForeignKey('dentists.id'))

    # 🩺 Dynamic per-visit health info
    chief_complaint = db.Column(db.String(255))
    acute_issue = db.Column(db.String(255))
    bp = db.Column(db.String(50))

    # 🟣 Pregnancy ONLY if female
    pregnant = db.Column(db.String(10))        # Yes / No
    pregnancy_weeks = db.Column(db.String(20))
    breastfeeding = db.Column(db.String(10))

    # Visit Notes
    notes = db.Column(db.Text)

    # Files per-visit
    attachment = db.Column(db.String(200))

    # ---------------------------------------------------------
    # 🔁 Relationship: Visit → Treatments
    # ---------------------------------------------------------
    treatments = db.relationship(
        'Treatment',
        backref='visit',
        cascade="all, delete-orphan",
        lazy='dynamic'
    )

    # ---------------------------------------------------------
    # 💊 NEW: Visit-Level Prescription (ONE PER VISIT)
    # ---------------------------------------------------------
    prescription = db.relationship(
        'VisitPrescription',
        backref='visit',
        uselist=False,
        cascade="all, delete-orphan"
    )

# ---------------------------------
# VISIT LEVEL PRESCRIPTION MODELS
# ---------------------------------

class VisitPrescription(db.Model):
    __tablename__ = "visit_prescriptions"

    id = db.Column(db.Integer, primary_key=True)
    visit_id = db.Column(db.Integer, db.ForeignKey("visits.id"), unique=True, nullable=False)

    # Optional general notes for whole prescription
    notes = db.Column(db.Text)

    # Relationship to items
    items = db.relationship(
        "PrescriptionItem",
        backref="prescription",
        cascade="all, delete-orphan",
        lazy=True
    )


class PrescriptionItem(db.Model):
    __tablename__ = "prescription_items"

    id = db.Column(db.Integer, primary_key=True)

    # Each prescription item MUST link to a visit-level prescription
    prescription_id = db.Column(
        db.Integer,
        db.ForeignKey("visit_prescriptions.id"),
        nullable=False
    )

    # Drug details
    drug_name = db.Column(db.String(120), nullable=False)
    dosage_form = db.Column(db.String(120))
    strength = db.Column(db.String(120))
    quantity = db.Column(db.String(50))
    frequency = db.Column(db.String(120))
    duration = db.Column(db.String(120))
    notes = db.Column(db.String(255))

class MedicineMaster(db.Model):
    __tablename__ = "medicine_master"

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(120))
    drug_name = db.Column(db.String(120), nullable=False)
    dosage_form = db.Column(db.String(120))
    strength = db.Column(db.String(120))
    quantity = db.Column(db.String(50))
    frequency = db.Column(db.String(120))
    duration = db.Column(db.String(120))
    notes = db.Column(db.String(255))
# -----------------------------------------
# CONDITION-BASED PRESCRIPTION PROTOCOLS
# -----------------------------------------

CONDITION_PROTOCOLS = {
    # 1️⃣ RESTORATIVE / FILLINGS / DEEP CARIES

    "Simple Filling (no pulpal symptoms)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Paracetamol",
            "strength": "500 mg",
            "quantity": "10",
            "frequency": "1 tab q8h PRN",
            "duration": "As needed"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400 mg",
            "quantity": "6",
            "frequency": "1 tab q8h",
            "duration": "1–2 days"
        }
    ],

    "Deep Caries / Reversible Pulpitis": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400–600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Pantoprazole",
            "strength": "40 mg",
            "quantity": "5",
            "frequency": "1 tab daily",
            "duration": "5 days"
        }
    ],

    "Direct Pulp Cap / Very Deep Restoration": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400–600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Paracetamol",
            "strength": "500 mg",
            "quantity": "10",
            "frequency": "1 tab q8h PRN",
            "duration": "As needed"
        }
    ],

    # 2️⃣ ENDODONTICS (ROOT CANAL, PULPITIS, ABSCESS)

    "Acute Irreversible Pulpitis (before RCT; no swelling)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ketorolac",
            "strength": "10 mg",
            "quantity": "6",
            "frequency": "1 tab q6–8h",
            "duration": "2–3 days"
        }
    ],

    "Root Canal Treatment – Routine Visit (no acute infection)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400–600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Paracetamol",
            "strength": "500 mg",
            "quantity": "10",
            "frequency": "1 tab q8h PRN",
            "duration": "As needed"
        }
    ],

    "Acute Apical Periodontitis / RCT Flare-up (no large swelling)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Paracetamol",
            "strength": "500 mg",
            "quantity": "10",
            "frequency": "1 tab q8h PRN",
            "duration": "As needed"
        },
        {
            "dosage_form": "Capsule",
            "drug_name": "Amoxicillin",
            "strength": "500 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Capsule",
            "drug_name": "Clindamycin",
            "strength": "300 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        }
    ],

    "Acute Apical Abscess with Swelling – Adult": [
        {
            "dosage_form": "Capsule",
            "drug_name": "Amoxicillin",
            "strength": "500 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Amoxicillin + Clavulanic Acid",
            "strength": "625 mg",
            "quantity": "21",
            "frequency": "1 tab q8h",
            "duration": "5–7 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Metronidazole",
            "strength": "400 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        }
    ],

    "Acute Apical Abscess with Swelling – Child": [
        {
            "dosage_form": "Syrup",
            "drug_name": "Amoxicillin Syrup",
            "strength": "250 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "40–50 mg/kg/day ÷ 3",
            "duration": "5 days"
        },
        {
            "dosage_form": "Syrup",
            "drug_name": "Paracetamol Syrup",
            "strength": "120 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "15 mg/kg q8h PRN",
            "duration": "PRN"
        }
    ],

    "Post-Obturation Pain": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400–600 mg",
            "quantity": "9",
            "frequency": "1 tab q8h",
            "duration": "3 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ketorolac",
            "strength": "10 mg",
            "quantity": "6",
            "frequency": "1 tab q6–8h",
            "duration": "2 days"
        }
    ],

    "Pulpotomy / Pulpectomy in Children": [
        {
            "dosage_form": "Syrup",
            "drug_name": "Ibuprofen Syrup",
            "strength": "100 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "10 mg/kg q8h",
            "duration": "1–3 days"
        },
        {
            "dosage_form": "Syrup",
            "drug_name": "Paracetamol Syrup",
            "strength": "120 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "15 mg/kg q8h PRN",
            "duration": "PRN"
        },
        {
            "dosage_form": "Syrup",
            "drug_name": "Amoxicillin Syrup",
            "strength": "250 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "40–50 mg/kg/day ÷ 3",
            "duration": "5 days"
        }
    ],

    # 3️⃣ PERIODONTICS

    "Routine Scaling / Polishing (Gingivitis)": [
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "7–14 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400 mg",
            "quantity": "6",
            "frequency": "1 tab q8h",
            "duration": "1–3 days"
        }
    ],

    "Scaling & Root Planing (Moderate–Severe Periodontitis)": [
        {
            "dosage_form": "Capsule",
            "drug_name": "Doxycycline",
            "strength": "100 mg",
            "quantity": "14",
            "frequency": "1 cap daily",
            "duration": "7–14 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "14 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Vitamin C",
            "strength": "500 mg",
            "quantity": "10",
            "frequency": "1 tab daily",
            "duration": "7–10 days"
        }
    ],

    "Acute Necrotizing Ulcerative Gingivitis (ANUG)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Metronidazole",
            "strength": "400 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "7–10 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        }
    ],

    "Periodontal Abscess": [
        {
            "dosage_form": "Capsule",
            "drug_name": "Amoxicillin",
            "strength": "500 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Amoxicillin + Clavulanic Acid",
            "strength": "625 mg",
            "quantity": "21",
            "frequency": "1 tab q8h",
            "duration": "5–7 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "7 days"
        }
    ],

    # 4️⃣ ORAL SURGERY & EXTRACTIONS

    "Simple Extraction (non-surgical)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400–600 mg",
            "quantity": "9",
            "frequency": "1 tab q8h",
            "duration": "3 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "5–7 days"
        }
    ],

    "Surgical Extraction / Impacted Third Molar Surgery": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ketorolac",
            "strength": "10 mg",
            "quantity": "6",
            "frequency": "1 tab q6–8h",
            "duration": "2–3 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Amoxicillin + Clavulanic Acid",
            "strength": "625 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "7 days"
        }
    ],

    "Post-Extraction – Medically Compromised / High-Risk": [
        {
            "dosage_form": "Capsule",
            "drug_name": "Amoxicillin",
            "strength": "500 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Amoxicillin + Clavulanic Acid",
            "strength": "625 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Tranexamic Acid",
            "strength": "4.8%",
            "quantity": "1 bottle",
            "frequency": "Rinse QID",
            "duration": "2–5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400 mg",
            "quantity": "9",
            "frequency": "1 tab q8h",
            "duration": "3 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Pantoprazole",
            "strength": "40 mg",
            "quantity": "5",
            "frequency": "1 tab daily",
            "duration": "5 days"
        }
    ],

    "Dry Socket (Alveolar Osteitis)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "7 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Vitamin C",
            "strength": "500 mg",
            "quantity": "10",
            "frequency": "1 tab daily",
            "duration": "7–10 days"
        }
    ],

    "Post-Operative Bleeding Control": [
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Tranexamic Acid",
            "strength": "4.8%",
            "quantity": "1 bottle",
            "frequency": "Rinse QID",
            "duration": "2–5 days"
        }
    ],

    # 5️⃣ PROSTHODONTICS

    "Crown / Bridge Preparation (vital tooth)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400 mg",
            "quantity": "6",
            "frequency": "1 tab q8h",
            "duration": "1–2 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "5 days"
        }
    ],

    "Post-Implant Surgery (Uncomplicated, healthy patient)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Amoxicillin + Clavulanic Acid",
            "strength": "625 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Capsule",
            "drug_name": "Amoxicillin",
            "strength": "500 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "7–14 days"
        }
    ],

    "Denture Sore Mouth / Traumatic Ulcers from Denture": [
        {
            "dosage_form": "Gel",
            "drug_name": "Choline Salicylate Gel",
            "strength": "8.7%",
            "quantity": "1 tube",
            "frequency": "Apply QID",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Gel",
            "drug_name": "Hyaluronic Acid Gel",
            "strength": "0.2–0.8%",
            "quantity": "1 tube",
            "frequency": "Apply TID",
            "duration": "5–7 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Vitamin B Complex",
            "strength": "-",
            "quantity": "10",
            "frequency": "1 tab daily",
            "duration": "10–14 days"
        },
        {
            "dosage_form": "Liquid",
            "drug_name": "Nystatin Suspension",
            "strength": "100,000 IU/ml",
            "quantity": "1 bottle",
            "frequency": "1 ml q6h",
            "duration": "7–14 days"
        },
        {
            "dosage_form": "Oral Gel",
            "drug_name": "Miconazole",
            "strength": "2%",
            "quantity": "1 tube",
            "frequency": "Apply QID",
            "duration": "7–14 days"
        }
    ],

    # 6️⃣ ORTHODONTICS

    "Orthodontic Adjustment Pain": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Paracetamol",
            "strength": "500 mg",
            "quantity": "10",
            "frequency": "1 tab q8h PRN",
            "duration": "PRN / 1–3 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400 mg",
            "quantity": "9",
            "frequency": "1 tab q8h",
            "duration": "1–3 days"
        }
    ],

    "Ulcers from Brackets / Wires": [
        {
            "dosage_form": "Gel",
            "drug_name": "Choline Salicylate Gel",
            "strength": "8.7%",
            "quantity": "1 tube",
            "frequency": "Apply QID",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Benzydamine",
            "strength": "0.15%",
            "quantity": "1 bottle",
            "frequency": "Rinse TID",
            "duration": "5–7 days"
        },
        {
            "dosage_form": "Oral Paste",
            "drug_name": "Triamcinolone",
            "strength": "0.1%",
            "quantity": "1 tube",
            "frequency": "Apply 2–3× daily",
            "duration": "5 days"
        }
    ],

    # 7️⃣ ORAL MEDICINE / MUCOSAL CONDITIONS

    "Recurrent Aphthous Ulcers": [
        {
            "dosage_form": "Oral Paste",
            "drug_name": "Triamcinolone",
            "strength": "0.1%",
            "quantity": "1 tube",
            "frequency": "Apply 2–3× daily",
            "duration": "5 days"
        },
        {
            "dosage_form": "Gel",
            "drug_name": "Hyaluronic Acid Gel",
            "strength": "0.2–0.8%",
            "quantity": "1 tube",
            "frequency": "Apply TID",
            "duration": "5–7 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Vitamin B Complex",
            "strength": "-",
            "quantity": "10",
            "frequency": "1 tab daily",
            "duration": "10–14 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Vitamin C",
            "strength": "500 mg",
            "quantity": "10",
            "frequency": "1 tab daily",
            "duration": "7–10 days"
        }
    ],

    "Burning Mouth Syndrome / Neuropathic Pain": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Clonazepam",
            "strength": "0.5 mg",
            "quantity": "5",
            "frequency": "1 tab at bedtime",
            "duration": "3 days (short trial)"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Vitamin B Complex",
            "strength": "-",
            "quantity": "10",
            "frequency": "1 tab daily",
            "duration": "10–14 days"
        }
    ],

    "Oral Candidiasis": [
        {
            "dosage_form": "Liquid",
            "drug_name": "Nystatin Suspension",
            "strength": "100,000 IU/ml",
            "quantity": "1 bottle",
            "frequency": "1 ml q6h",
            "duration": "7–14 days"
        },
        {
            "dosage_form": "Oral Gel",
            "drug_name": "Miconazole",
            "strength": "2%",
            "quantity": "1 tube",
            "frequency": "Apply QID",
            "duration": "7–14 days"
        },
        {
            "dosage_form": "Tablet",
            "drug_name": "Fluconazole",
            "strength": "150 mg",
            "quantity": "1",
            "frequency": "Once",
            "duration": "1 day"
        }
    ],

    # 8️⃣ TRAUMA (DENTAL INJURIES)

    "Uncomplicated Crown Fracture (no pulp exposure)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "400–600 mg",
            "quantity": "9",
            "frequency": "1 tab q8h",
            "duration": "3 days"
        }
    ],

    "Complicated Crown Fracture (pulp exposure)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Capsule",
            "drug_name": "Amoxicillin",
            "strength": "500 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        },
        {
            "dosage_form": "Capsule",
            "drug_name": "Clindamycin",
            "strength": "300 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        }
    ],

    "Luxation Injuries (subluxation / extrusion / lateral)": [
        {
            "dosage_form": "Tablet",
            "drug_name": "Ibuprofen",
            "strength": "600 mg",
            "quantity": "15",
            "frequency": "1 tab q8h",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "7–10 days"
        },
        {
            "dosage_form": "Capsule",
            "drug_name": "Amoxicillin",
            "strength": "500 mg",
            "quantity": "15",
            "frequency": "1 cap q8h",
            "duration": "5 days"
        }
    ],

    "Avulsion (Permanent Tooth Replanted) – Adult": [
        {
            "dosage_form": "Capsule",
            "drug_name": "Amoxicillin",
            "strength": "500 mg",
            "quantity": "15–21",
            "frequency": "1 cap q8h",
            "duration": "5–7 days"
        },
        {
            "dosage_form": "Capsule",
            "drug_name": "Doxycycline",
            "strength": "100 mg",
            "quantity": "7",
            "frequency": "1 cap daily",
            "duration": "7 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse BID",
            "duration": "7–14 days"
        }
    ],

    "Avulsion (Permanent Tooth Replanted) – Child": [
        {
            "dosage_form": "Syrup",
            "drug_name": "Amoxicillin Syrup",
            "strength": "250 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "40–50 mg/kg/day ÷ 3",
            "duration": "5–7 days"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Rinse / dab BID",
            "duration": "7–14 days"
        }
    ],

    # 9️⃣ PEDIATRIC GENERAL DENTISTRY

    "Severe Dental Infection in Child (swelling, fever)": [
        {
            "dosage_form": "Syrup",
            "drug_name": "Amoxicillin Syrup",
            "strength": "250 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "40–50 mg/kg/day ÷ 3",
            "duration": "5 days"
        },
        {
            "dosage_form": "Syrup",
            "drug_name": "Metronidazole Syrup",
            "strength": "200 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "30 mg/kg/day ÷ 3",
            "duration": "3–5 days"
        },
        {
            "dosage_form": "Syrup",
            "drug_name": "Ibuprofen Syrup",
            "strength": "100 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "10 mg/kg q8h",
            "duration": "1–3 days"
        },
        {
            "dosage_form": "Syrup",
            "drug_name": "Paracetamol Syrup",
            "strength": "120 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "15 mg/kg q8h PRN",
            "duration": "PRN"
        }
    ],

    "Post-Extraction – Pediatric": [
        {
            "dosage_form": "Syrup",
            "drug_name": "Ibuprofen Syrup",
            "strength": "100 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "10 mg/kg q8h",
            "duration": "1–3 days"
        },
        {
            "dosage_form": "Syrup",
            "drug_name": "Paracetamol Syrup",
            "strength": "120 mg/5 ml",
            "quantity": "1 bottle",
            "frequency": "15 mg/kg q8h PRN",
            "duration": "PRN"
        },
        {
            "dosage_form": "Mouthwash",
            "drug_name": "Chlorhexidine",
            "strength": "0.12%",
            "quantity": "1 bottle",
            "frequency": "Dab / gentle rinse (age-appropriate)",
            "duration": "Few days"
        }
    ]
}

# Optional: to show dropdown with headings like "Restorative", "Endodontics", etc.
CONDITION_GROUPS = {
    "1️⃣ Restorative / Fillings / Deep Caries": [
        "Simple Filling (no pulpal symptoms)",
        "Deep Caries / Reversible Pulpitis",
        "Direct Pulp Cap / Very Deep Restoration"
    ],
    "2️⃣ Endodontics (RCT, Pulpitis, Abscess)": [
        "Acute Irreversible Pulpitis (before RCT; no swelling)",
        "Root Canal Treatment – Routine Visit (no acute infection)",
        "Acute Apical Periodontitis / RCT Flare-up (no large swelling)",
        "Acute Apical Abscess with Swelling – Adult",
        "Acute Apical Abscess with Swelling – Child",
        "Post-Obturation Pain",
        "Pulpotomy / Pulpectomy in Children"
    ],
    "3️⃣ Periodontics": [
        "Routine Scaling / Polishing (Gingivitis)",
        "Scaling & Root Planing (Moderate–Severe Periodontitis)",
        "Acute Necrotizing Ulcerative Gingivitis (ANUG)",
        "Periodontal Abscess"
    ],
    "4️⃣ Oral Surgery & Extractions": [
        "Simple Extraction (non-surgical)",
        "Surgical Extraction / Impacted Third Molar Surgery",
        "Post-Extraction – Medically Compromised / High-Risk",
        "Dry Socket (Alveolar Osteitis)",
        "Post-Operative Bleeding Control"
    ],
    "5️⃣ Prosthodontics": [
        "Crown / Bridge Preparation (vital tooth)",
        "Post-Implant Surgery (Uncomplicated, healthy patient)",
        "Denture Sore Mouth / Traumatic Ulcers from Denture"
    ],
    "6️⃣ Orthodontics": [
        "Orthodontic Adjustment Pain",
        "Ulcers from Brackets / Wires"
    ],
    "7️⃣ Oral Medicine / Mucosal Conditions": [
        "Recurrent Aphthous Ulcers",
        "Burning Mouth Syndrome / Neuropathic Pain",
        "Oral Candidiasis"
    ],
    "8️⃣ Trauma (Dental Injuries)": [
        "Uncomplicated Crown Fracture (no pulp exposure)",
        "Complicated Crown Fracture (pulp exposure)",
        "Luxation Injuries (subluxation / extrusion / lateral)",
        "Avulsion (Permanent Tooth Replanted) – Adult",
        "Avulsion (Permanent Tooth Replanted) – Child"
    ],
    "9️⃣ Pediatric General Dentistry": [
        "Severe Dental Infection in Child (swelling, fever)",
        "Post-Extraction – Pediatric"
    ]
}

# =======================
# ==================================
# 💊 TREATMENT MODEL
# =========================================================
class Treatment(db.Model):
    __tablename__ = 'treatments'

    id = db.Column(db.Integer, primary_key=True)

    # -------------------------------------------------
    # Parent–Child (Multi-step RCT / Ortho treatment)
    # -------------------------------------------------
    parent_treatment_id = db.Column(
        db.Integer,
        db.ForeignKey('treatments.id'),
        nullable=True
    )

    sub_treatments = db.relationship(
        'Treatment',
        backref=db.backref('parent_treatment', remote_side='Treatment.id'),
        cascade="all, delete-orphan",
        lazy=True
    )

    # -------------------------------------------------
    # Core Treatment Data
    # -------------------------------------------------
    treatment_category = db.Column(db.String(100))   # RCT / Extraction / Ortho / Cosmetic / etc.
    treatment_type = db.Column(db.String(150))       # Specific option selected from dropdown
    date = db.Column(db.String(20), default=datetime.now().strftime("%Y-%m-%d"))

    notes = db.Column(db.Text)                       # Auto + Manual clinical notes
    post_op = db.Column(db.Text)                     # Post-op instructions generated by script

    amount = db.Column(db.Float)                     # Treatment Fee
    next_appointment = db.Column(db.String(20))
    status = db.Column(db.String(20), default="Ongoing")

    # -------------------------------------------------
    # Tooth / Site
    # -------------------------------------------------
    tooth_number = db.Column(db.String(10))          # e.g. UR6, LL3, UL-A
    multi_tooth = db.Column(db.String(50))           # Bridges, Implants, Multi-site

    # -------------------------------------------------
    # RCT Fields (MUST match add_treatment.html)
    # -------------------------------------------------
    obturation_material = db.Column(db.String(100))

    # Stored as "MB1:21, DB:20, P:20"
    working_length = db.Column(db.Text)

    # Stored as "MB1:30, DB:30, P:35"
    maf = db.Column(db.Text)

    # -------------------------------------------------
    # Extraction / Surgical Procedure Fields
    # -------------------------------------------------
    extraction_type = db.Column(db.String(100))          # Simple / Surgical
    impaction_type = db.Column(db.String(100))
    extraction_difficulty = db.Column(db.String(50))
    flap_type = db.Column(db.String(100))
    bone_removal = db.Column(db.Boolean, default=False)
    suture_type = db.Column(db.String(100))

    # 🔥 MUST BE INCLUDED (You use it in JS & route)
    tooth_sectioning = db.Column(db.Boolean, default=False)
    sectioning_details = db.Column(db.String(200))

    # Minor surgical procedures (I&D, biopsy, frenectomy, etc.)
    surgical_details = db.Column(db.Text)

    # -------------------------------------------------
    # Optional Fields (Orthodontics / Pediatric / Cosmetic)
    # -------------------------------------------------
    ortho_details = db.Column(db.Text)
    pediatric_details = db.Column(db.Text)
    cosmetic_details = db.Column(db.Text)

    # -------------------------------------------------
    # File Attachment + Doctor
    # -------------------------------------------------
    attachment = db.Column(db.String(200))             # Legacy, keep for compatibility
    doctor = db.Column(db.String(100))                 # Saved clinician name

    # -------------------------------------------------
    # Foreign Keys
    # -------------------------------------------------
    dentist_id = db.Column(db.Integer, db.ForeignKey('dentists.id'))
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'))
    case_id = db.Column(db.Integer, db.ForeignKey('cases.id'))
    visit_id = db.Column(db.Integer, db.ForeignKey('visits.id'))

    # -------------------------------------------------
    # Related Data
    # -------------------------------------------------
    followups = db.relationship(
        'FollowUp',
        backref='treatment',
        cascade="all, delete-orphan",
        lazy='joined'
    )

    related_files = db.relationship(
        'Radiograph',
        backref='treatment',
        lazy=True
    )

# =========================================================

# =========================================================
# 🔁 FOLLOW-UP MODEL
# =========================================================
class FollowUp(db.Model):
    __tablename__ = 'followups'

    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(20), default=datetime.now().strftime("%Y-%m-%d"))
    notes = db.Column(db.Text)
    next_appointment = db.Column(db.String(20))
    status = db.Column(db.String(20), default='Ongoing')
    attachment = db.Column(db.String(200))  # optional per-visit file (X-ray, photo, etc.)

    treatment_id = db.Column(db.Integer, db.ForeignKey('treatments.id'))


# ---------------------------

class Dentist(db.Model):
    __tablename__ = 'dentists'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    specialization = db.Column(db.String(100))
    contact = db.Column(db.String(50))
    email = db.Column(db.String(100))
    joined_on = db.Column(db.String(50), default=datetime.utcnow().strftime("%Y-%m-%d %H:%M"))

    # 🔁 Treatments done by this dentist
    treatments = db.relationship('Treatment', backref='dentist', lazy=True)

    # 🔁 NEW: Visits handled by this dentist
    visits = db.relationship('Visit', backref='dentist_obj', lazy=True)

class Payment(db.Model):
    __tablename__ = 'payments'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"))
    treatment_id = db.Column(db.Integer, db.ForeignKey("treatments.id"), nullable=True)
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)
    date = db.Column(db.String(20))
    treatment_fee = db.Column(db.Float)
    amount_paid = db.Column(db.Float)
    remaining_balance = db.Column(db.Float)

    treatment = db.relationship('Treatment', backref='payments', lazy=True)


class Radiograph(db.Model):
    __tablename__ = 'radiographs'

    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"))
    treatment_id = db.Column(db.Integer, db.ForeignKey("treatments.id"), nullable=True)  # 🔗 Link to specific treatment
    case_id = db.Column(db.Integer, db.ForeignKey("cases.id"), nullable=True)
    filename = db.Column(db.String(200))
    uploaded_by = db.Column(db.String(50))
    uploaded_at = db.Column(db.String(50))


with app.app_context():
    db.create_all()


# ---------------------------------
# HELPERS
# ---------------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def require_role(roles):
    return session.get("role") in roles
# =====================================================
# 🦷 Accurate Canal Suggestion Logic Based on Tooth Anatomy
# =====================================================
def get_canals_for_tooth(tooth_number):
    """
    Returns recommended canal list based on correct endodontic anatomy.
    Input example: 'UR6', 'UL1', 'LL4', 'LR2', 'URC' (pediatric)
    """

    if not tooth_number or len(tooth_number) < 3:
        return ["M"]  # default single canal

    num = tooth_number[2:]  # number only

    # Pediatric teeth A–E
    if num in ["A", "B", "C", "D", "E"]:
        return ["M"]

    # Convert to integer if permanent tooth
    try:
        n = int(num)
    except:
        return ["M"]

    # ------------------------------
    # ANTERIORS 1–3 (Max & Mand)
    # ------------------------------
    if n in [1, 2, 3]:
        return ["C"]  # central canal

    # ------------------------------
    # PREMOLARS 4–5
    # ------------------------------
    if n == 4:   # Upper 1st premolar (2 or 3 canals)
        return ["B", "P"]
    if n == 5:   # Upper 2nd premolar (mostly 1 canal)
        return ["C"]

    # ------------------------------
    # MOLARS 6–8
    # ------------------------------
    if n == 6:
        return ["MB1", "MB2", "DB", "P"]
    if n == 7:
        return ["MB", "DB", "P"]
    if n == 8:
        return ["MB", "DB", "P"]  # simple default for wisdoms

    return ["M"]



# ---------------------------------
# AUTHENTICATION
# ---------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["username"] = user.username
            session["role"] = user.role
            if user.role in ["doctor", "assistant"]:
                return redirect(url_for("dashboard_main"))
            elif user.role == "patient":
                return redirect(url_for("dashboard_patient"))
        flash("Invalid username or password", "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/add_sample_users")
def add_sample_users():
    if User.query.first():
        return "Users already exist."
    doctor = User(username="doctor", password=generate_password_hash("doctor123"), role="doctor")
    assistant = User(username="assistant", password=generate_password_hash("assistant123"), role="assistant")
    db.session.add_all([doctor, assistant])
    db.session.commit()
    return "Sample users created."


# ---------------------------------
# DASHBOARD (Doctor/Assistant)
# ---------------------------------
@app.route("/dashboard_main")
def dashboard_main():
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    q = request.args.get("q", "")
    if q:
        patients = Patient.query.filter(Patient.full_name.ilike(f"%{q}%")).all()
    else:
        patients = Patient.query.order_by(Patient.id.desc()).all()

    total_revenue = sum(p.amount_paid for p in Payment.query.all())

    total_outstanding = 0.0
    for patient in Patient.query.all():
        total_treatments = sum(t.amount for t in Treatment.query.filter_by(patient_id=patient.id))
        total_paid = sum(pm.amount_paid for pm in Payment.query.filter_by(patient_id=patient.id))
        total_outstanding += max(0.0, total_treatments - total_paid)

    total_patients = Patient.query.count()

    return render_template(
        "dashboard_main.html",
        patients=patients,
        q=q,
        total_revenue=total_revenue,
        total_outstanding=total_outstanding,
        total_patients=total_patients
    )
# ---------------------------------
# -----------------------------
# Clinical Risk & Protocols Dashboard
# -----------------------------
# ================================
# CLINICAL RISK & PROTOCOLS
# ================================
@app.route("/medical_risk_dashboard")
def medical_risk_dashboard():
    # Only doctor / assistant should see this
    if not session.get("role") in ["doctor", "assistant"]:
        return redirect(url_for("login"))

    return render_template("medical_risk_dashboard.html")



@app.route('/doctor_dashboard')
@login_required
def doctor_dashboard():
    # Group treatments by doctor name
    doctors = db.session.query(
        Treatment.doctor,
        db.func.count(db.distinct(Treatment.patient_id)).label("patient_count")
    ).group_by(Treatment.doctor).all()

    return render_template("doctor_dashboard.html", doctors=doctors)


@app.route('/dentist/<dentist_name>')
@login_required
def view_dentist_patients(dentist_name):
    patient_ids = [t.patient_id for t in Treatment.query.filter_by(doctor=dentist_name).all()]
    patients = Patient.query.filter(Patient.id.in_(patient_ids)).all()

    return render_template("dentist_patients.html",
                           dentist_name=dentist_name,
                           patients=patients)


# ---------------------------------
@app.route("/patient_registration", methods=["GET", "POST"])
def patient_registration():
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    if request.method == "POST":
        last_patient = Patient.query.order_by(Patient.id.desc()).first()
        next_file_no = str(10000 + (last_patient.id + 1 if last_patient else 1))

        gender = request.form.get("gender")

        p = Patient(
            file_no=next_file_no,
            full_name=request.form.get("full_name"),
            father_or_spouse_name=request.form.get("father_or_spouse_name"),
            gender=gender,
            dob_or_age=request.form.get("dob_or_age"),
            marital_status=request.form.get("marital_status"),
            occupation=request.form.get("occupation"),
            contact=request.form.get("contact"),
            email=request.form.get("email"),
            cnic=request.form.get("cnic"),
            address=request.form.get("address"),
            created_by=session.get("username"),
            date=datetime.now().strftime("%Y-%m-%d"),
        )

        # Medical History
        for field in [
            "heart_disease", "blood_pressure", "diabetes", "asthma",
            "tuberculosis", "hepatitis", "bleeding_disorder", "epilepsy",
            "thyroid_disorder", "kidney_disease", "stomach_ulcers",
            "psychiatric_disorder"
        ]:
            setattr(p, field, "Yes" if request.form.get(field) else "No")

        # Pregnancy/Breastfeeding
        if gender == "Female":
            p.pregnant = "Yes" if request.form.get("pregnant") else "No"
            p.pregnancy_weeks = request.form.get("pregnancy_weeks")
            p.breastfeeding = "Yes" if request.form.get("breastfeeding") else "No"
        else:
            p.pregnant, p.pregnancy_weeks, p.breastfeeding = "No", None, "No"

        # Dental History
        for field in [
            "treat_fillings", "treat_rct", "treat_crowns", "treat_extractions",
            "treat_scaling", "treat_denture", "treat_braces", "treat_implant",
            "gum_bleeding", "gum_loose", "gum_badbreath", "gum_none",
            "sensitive_teeth", "frequent_cavities", "caries_none",
            "fractured_tooth", "jaw_accident", "trauma_none",
            "uses_tobacco", "uses_naswar", "uses_paan", "uses_smoke"
        ]:
            setattr(p, field, "Yes" if request.form.get(field) else "No")

        # New fields — TMJ & Oral Hygiene
        p.tmj_issue = "Yes" if request.form.get("tmj_issue") else "No"
        p.tmj_notes = request.form.get("tmj_notes")
        p.oral_hygiene = request.form.get("oral_hygiene")
        p.caries_risk = request.form.get("caries_risk")

        # Other text fields
        p.medications = request.form.get("medications")
        p.allergies = request.form.get("allergies")
        p.other_health = request.form.get("other_health")
        p.surgery_history = request.form.get("surgery_history")

        p.last_dental_visit = request.form.get("last_dental_visit")
        p.last_dental_reason = request.form.get("last_dental_reason")
        p.treat_other = request.form.get("treat_other")
        p.bad_experience = request.form.get("bad_experience")
        p.bad_experience_details = request.form.get("bad_experience_details")
        p.smoking_frequency = request.form.get("smoking_frequency")
        p.dental_notes = request.form.get("dental_notes")
        p.soft_tissue_notes = request.form.get("soft_tissue_notes")

        db.session.add(p)
        db.session.commit()

        # Create User login for patient
        temp_password = "".join(random.choices(string.ascii_letters + string.digits, k=6))
        user = User(
            username=p.file_no,
            password=generate_password_hash(temp_password),
            role="patient",
            temporary_password=temp_password
        )
        db.session.add(user)
        db.session.commit()

        flash(f"Patient registered successfully. File No: {p.file_no} | Temp Pwd: {temp_password}", "success")
        return render_template("patient_registered.html", file_no=p.file_no, temp_pwd=temp_password)

    return render_template("patient_registration.html")



@app.route('/register_dentist', methods=['GET', 'POST'])
def register_dentist():
    if request.method == 'POST':
        name = request.form['name']
        specialization = request.form['specialization']
        contact = request.form['contact']
        email = request.form['email']

        new_dentist = Dentist(
            name=name,
            specialization=specialization,
            contact=contact,
            email=email
        )
        db.session.add(new_dentist)
        db.session.commit()
        flash('New dentist added successfully.', 'success')
        return redirect(url_for('register_dentist'))

    dentists = Dentist.query.all()
    return render_template('register_dentist.html', dentists=dentists)


# ------------------------------
# Delete Dentist
# ------------------------------
@app.route("/delete_dentist/<int:dentist_id>", methods=["GET"])
def delete_dentist(dentist_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    dentist = Dentist.query.get_or_404(dentist_id)
    db.session.delete(dentist)
    db.session.commit()
    flash(f"{dentist.name} has been deleted.", "danger")
    return redirect(url_for("register_dentist"))


# ---------------------------------
# ADD TREATMENT (with next appointment + optional file + dentist selection)
# ---------------------------------
# ==========================================================
# ADD TREATMENT — FULL UPDATED ROUTE (PASTE REPLACING OLD ONE)
# ==========================================================
# ==========================================================
# ADD TREATMENT — NOW LINKS TO EXISTING VISIT (NO AUTO VISIT)
# ==========================================================
# ---------------------------------
# MEDICINE MASTER (LIST + ADD)
# ---------------------------------
@app.route("/medicine_master", methods=["GET", "POST"])
def medicine_master():
    # Only doctor/assistant should manage medicines
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    if request.method == "POST":
        category = (request.form.get("category") or "").strip() or None
        drug_name = (request.form.get("drug_name") or "").strip()
        dosage_form = (request.form.get("dosage_form") or "").strip() or None
        strength = (request.form.get("strength") or "").strip() or None
        quantity = (request.form.get("quantity") or "").strip() or None
        frequency = (request.form.get("frequency") or "").strip() or None
        duration = (request.form.get("duration") or "").strip() or None
        notes = (request.form.get("notes") or "").strip() or None

        if not drug_name:
            flash("Drug name is required.", "danger")
        else:
            med = MedicineMaster(
                category=category,
                drug_name=drug_name,
                dosage_form=dosage_form,
                strength=strength,
                quantity=quantity,
                frequency=frequency,
                duration=duration,
                notes=notes,
            )
            db.session.add(med)
            db.session.commit()
            flash("Medicine added to library.", "success")

        return redirect(url_for("medicine_master"))

    medicines = MedicineMaster.query.order_by(
        MedicineMaster.category, MedicineMaster.drug_name
    ).all()

    return render_template("medicine_master.html", medicines=medicines)

@app.route("/load_default_medicines")
def load_default_medicines():
    # Check if the table already has medicines
    existing = MedicineMaster.query.count()
    if existing > 0:
        return f"{existing} medicines already exist. No action taken."

    medicines = [
        # Painkillers
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Ibuprofen", "dosage_form": "Tablet",
         "strength": "400 mg", "quantity": 10, "frequency": "1 tab q8h", "duration": "3–5 days",
         "notes": "Take after food. Avoid if gastric issues."},
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Ibuprofen", "dosage_form": "Tablet",
         "strength": "600 mg", "quantity": 10, "frequency": "1 tab q8h", "duration": "3–5 days",
         "notes": "For severe pain."},
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Paracetamol", "dosage_form": "Tablet",
         "strength": "500 mg", "quantity": 10, "frequency": "1 tab q8h", "duration": "As needed",
         "notes": "Safe for stomach."},
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Aceclofenac + Paracetamol",
         "dosage_form": "Tablet", "strength": "100/500 mg", "quantity": 10, "frequency": "1 tab q12h",
         "duration": "3–5 days", "notes": "Pain + inflammation."},
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Diclofenac Potassium", "dosage_form": "Tablet",
         "strength": "50 mg", "quantity": 10, "frequency": "1 tab q8h", "duration": "3 days",
         "notes": "Fast-acting. Take with meals."},
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Diclofenac Sodium", "dosage_form": "Tablet",
         "strength": "50 mg", "quantity": 10, "frequency": "1 tab q12h", "duration": "3 days",
         "notes": "Longer-acting form."},
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Ketorolac", "dosage_form": "Tablet",
         "strength": "10 mg", "quantity": 10, "frequency": "1 tab q6–8h", "duration": "2–3 days",
         "notes": "Strong painkiller."},
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Naproxen", "dosage_form": "Tablet",
         "strength": "250 mg", "quantity": 10, "frequency": "1 tab q12h", "duration": "3–5 days",
         "notes": "Take with meals."},
        {"category": "Painkillers & Anti-Inflammatories", "drug_name": "Paracetamol + Orphenadrine",
         "dosage_form": "Tablet", "strength": "450 mg + 35 mg", "quantity": 10, "frequency": "1 tab q12h",
         "duration": "3–5 days", "notes": "Helps with TMJ pain and muscle spasm."},

        # Antibiotics (Adults)
        {"category": "Antibiotics (Adults)", "drug_name": "Amoxicillin", "dosage_form": "Capsule", "strength": "500 mg",
         "quantity": 15, "frequency": "1 cap q8h", "duration": "5 days", "notes": "Complete the course."},
        {"category": "Antibiotics (Adults)", "drug_name": "Amoxicillin + Clavulanic Acid", "dosage_form": "Tablet",
         "strength": "625 mg", "quantity": 15, "frequency": "1 tab q8h", "duration": "5–7 days",
         "notes": "Take after meals."},
        {"category": "Antibiotics (Adults)", "drug_name": "Metronidazole", "dosage_form": "Tablet",
         "strength": "400 mg", "quantity": 15, "frequency": "1 tab q8h", "duration": "3–5 days",
         "notes": "Avoid alcohol."},
        {"category": "Antibiotics (Adults)", "drug_name": "Clindamycin", "dosage_form": "Capsule", "strength": "300 mg",
         "quantity": 15, "frequency": "1 cap q8h", "duration": "5 days", "notes": "For penicillin allergy."},
        {"category": "Antibiotics (Adults)", "drug_name": "Azithromycin", "dosage_form": "Tablet", "strength": "500 mg",
         "quantity": 3, "frequency": "1 tab daily", "duration": "3 days", "notes": "Take 1 hr before meals."},
        {"category": "Antibiotics (Adults)", "drug_name": "Ciprofloxacin", "dosage_form": "Tablet",
         "strength": "500 mg", "quantity": 10, "frequency": "1 tab q12h", "duration": "3–5 days",
         "notes": "Not for children."},
        {"category": "Antibiotics (Adults)", "drug_name": "Doxycycline", "dosage_form": "Capsule", "strength": "100 mg",
         "quantity": 7, "frequency": "1 cap daily", "duration": "7–14 days", "notes": "Good for gum infections."},

        # Pediatric Antibiotics
        {"category": "Pediatric Antibiotics", "drug_name": "Amoxicillin Syrup", "dosage_form": "Syrup",
         "strength": "250 mg/5 ml", "quantity": 1, "frequency": "40–50 mg/kg/day ÷ 3", "duration": "5 days",
         "notes": "Shake well."},
        {"category": "Pediatric Antibiotics", "drug_name": "Augmentin ES Suspension", "dosage_form": "Syrup",
         "strength": "600 mg/5 ml", "quantity": 1, "frequency": "45 mg/kg/day ÷ 2", "duration": "5 days",
         "notes": "Refrigerate after opening."},
        {"category": "Pediatric Antibiotics", "drug_name": "Metronidazole Syrup", "dosage_form": "Syrup",
         "strength": "200 mg/5 ml", "quantity": 1, "frequency": "30 mg/kg/day ÷ 3", "duration": "3–5 days",
         "notes": "Metallic taste possible."},
        {"category": "Pediatric Antibiotics", "drug_name": "Azithromycin Syrup", "dosage_form": "Syrup",
         "strength": "200 mg/5 ml", "quantity": 1, "frequency": "10 mg/kg OD", "duration": "3 days",
         "notes": "Give 1 hr before food."},

        # Mouthwashes & Antiseptics
        {"category": "Mouthwashes & Antiseptics", "drug_name": "Chlorhexidine", "dosage_form": "Mouthwash",
         "strength": "0.12%", "quantity": 1, "frequency": "Rinse BID", "duration": "7–14 days",
         "notes": "Spit after rinsing."},
        {"category": "Mouthwashes & Antiseptics", "drug_name": "Povidone-Iodine", "dosage_form": "Mouthwash",
         "strength": "1%", "quantity": 1, "frequency": "Rinse BID", "duration": "5 days", "notes": "Do not swallow."},
        {"category": "Mouthwashes & Antiseptics", "drug_name": "Hydrogen Peroxide", "dosage_form": "Mouthwash",
         "strength": "1.5%", "quantity": 1, "frequency": "Rinse BID", "duration": "3–5 days",
         "notes": "Dilute before use."},

        # Ulcer / Soft Tissue Agents
        {"category": "Ulcer / Soft Tissue Agents", "drug_name": "Triamcinolone", "dosage_form": "Oral Paste",
         "strength": "0.1%", "quantity": 1, "frequency": "Apply 2–3× daily", "duration": "5 days",
         "notes": "No eating for 20 min after use."},
        {"category": "Ulcer / Soft Tissue Agents", "drug_name": "Benzydamine", "dosage_form": "Mouthwash",
         "strength": "0.15%", "quantity": 1, "frequency": "Rinse TID", "duration": "5–7 days",
         "notes": "Helps numb pain."},
        {"category": "Ulcer / Soft Tissue Agents", "drug_name": "Choline Salicylate Gel", "dosage_form": "Gel",
         "strength": "8.7%", "quantity": 1, "frequency": "Apply QID", "duration": "3–5 days",
         "notes": "Good for ulcers & teething."},
        {"category": "Ulcer / Soft Tissue Agents", "drug_name": "Hyaluronic Acid Gel", "dosage_form": "Gel",
         "strength": "0.2–0.8%", "quantity": 1, "frequency": "Apply TID", "duration": "5–7 days",
         "notes": "Promotes healing."},
        {"category": "Ulcer / Soft Tissue Agents", "drug_name": "Silver Nitrate Stick", "dosage_form": "Applicator",
         "strength": "75%", "quantity": 1, "frequency": "Single use", "duration": "",
         "notes": "Applied by dentist for ulcer cautery."},

        # Antifungals
        {"category": "Antifungals", "drug_name": "Miconazole", "dosage_form": "Oral Gel", "strength": "2%",
         "quantity": 1, "frequency": "Apply QID", "duration": "7–14 days", "notes": "For mouth fungus."},
        {"category": "Antifungals", "drug_name": "Nystatin Suspension", "dosage_form": "Liquid",
         "strength": "100,000 IU/ml", "quantity": 1, "frequency": "1 ml q6h", "duration": "7–14 days",
         "notes": "Swish & swallow."},
        {"category": "Antifungals", "drug_name": "Fluconazole", "dosage_form": "Tablet", "strength": "150 mg",
         "quantity": 1, "frequency": "Once", "duration": "1 day", "notes": "For severe thrush."},

        # Antivirals
        {"category": "Antivirals", "drug_name": "Acyclovir", "dosage_form": "Tablet", "strength": "400 mg",
         "quantity": 15, "frequency": "1 tab 5× daily", "duration": "3–5 days",
         "notes": "For cold sores/herpetic lesions."},

        # Dry Mouth Treatments
        {"category": "Dry Mouth Treatments", "drug_name": "Pilocarpine", "dosage_form": "Tablet", "strength": "5 mg",
         "quantity": 15, "frequency": "1 tab TID", "duration": "5–10 days", "notes": "For dry mouth."},
        {"category": "Dry Mouth Treatments", "drug_name": "Artificial Saliva Spray", "dosage_form": "Spray",
         "strength": "", "quantity": 1, "frequency": "Use PRN", "duration": "", "notes": "Oral dryness relief."},
        {"category": "Dry Mouth Treatments", "drug_name": "Xylitol Gum", "dosage_form": "Chewable", "strength": "",
         "quantity": 1, "frequency": "Chew TID", "duration": "2 weeks", "notes": "Prevents tooth decay."},

        # Topical Anesthetics
        {"category": "Topical Anesthetics", "drug_name": "Lidocaine Gel", "dosage_form": "Gel", "strength": "2%",
         "quantity": 1, "frequency": "Apply PRN", "duration": "", "notes": "Numbs gums temporarily."},
        {"category": "Topical Anesthetics", "drug_name": "Benzocaine Gel", "dosage_form": "Gel", "strength": "20%",
         "quantity": 1, "frequency": "Apply PRN", "duration": "", "notes": "For localized oral discomfort."},

        # Antihistamines & GI Protection
        {"category": "Antihistamines & GI Protection", "drug_name": "Cetirizine", "dosage_form": "Tablet",
         "strength": "10 mg", "quantity": 10, "frequency": "1 tab at night", "duration": "3–5 days",
         "notes": "For swelling/allergy."},
        {"category": "Antihistamines & GI Protection", "drug_name": "Pantoprazole", "dosage_form": "Tablet",
         "strength": "40 mg", "quantity": 10, "frequency": "1 tab daily", "duration": "5 days",
         "notes": "Prevents acidity due to NSAIDs."},
        {"category": "Antihistamines & GI Protection", "drug_name": "Ranitidine / Famotidine", "dosage_form": "Tablet",
         "strength": "150 mg", "quantity": 10, "frequency": "1 tab BID", "duration": "3–5 days",
         "notes": "Stomach protection."},

        # Neuromuscular Agents
        {"category": "Neuromuscular Agents", "drug_name": "Tizanidine", "dosage_form": "Tablet", "strength": "2 mg",
         "quantity": 10, "frequency": "1 tab at night", "duration": "5 days", "notes": "For TMJ muscle pain."},
        {"category": "Neuromuscular Agents", "drug_name": "Diazepam", "dosage_form": "Tablet", "strength": "5 mg",
         "quantity": 5, "frequency": "1 tab at bedtime", "duration": "3 days",
         "notes": "Relaxes muscles and helps sleep."},
        {"category": "Neuromuscular Agents", "drug_name": "Clonazepam", "dosage_form": "Tablet", "strength": "0.5 mg",
         "quantity": 5, "frequency": "1 tab at bedtime", "duration": "3 days",
         "notes": "For burning mouth or neuralgia."},

        # Vitamins & Probiotics
        {"category": "Vitamins & Probiotics", "drug_name": "Vitamin C", "dosage_form": "Tablet", "strength": "500 mg",
         "quantity": 10, "frequency": "1 tab daily", "duration": "7–10 days", "notes": "Helps gum healing."},
        {"category": "Vitamins & Probiotics", "drug_name": "Vitamin B Complex", "dosage_form": "Tablet", "strength": "",
         "quantity": 10, "frequency": "1 tab daily", "duration": "10–14 days", "notes": "Speeds up ulcer recovery."},
        {"category": "Vitamins & Probiotics", "drug_name": "Probiotic Sachet", "dosage_form": "Powder",
         "strength": "2–5 Billion CFU", "quantity": 10, "frequency": "1 sachet daily", "duration": "5–10 days",
         "notes": "Supports gut during antibiotics."},

        # Pediatric Pain / Teething
        {"category": "Pediatric Pain / Teething", "drug_name": "Paracetamol Syrup", "dosage_form": "Syrup",
         "strength": "120 mg/5 ml", "quantity": 1, "frequency": "15 mg/kg q8h", "duration": "PRN",
         "notes": "Use measuring syringe."},
        {"category": "Pediatric Pain / Teething", "drug_name": "Ibuprofen Syrup", "dosage_form": "Syrup",
         "strength": "100 mg/5 ml", "quantity": 1, "frequency": "10 mg/kg q8h", "duration": "1–3 days",
         "notes": "Give after food."},
        {"category": "Pediatric Pain / Teething", "drug_name": "Choline Salicylate Gel", "dosage_form": "Gel",
         "strength": "8.7%", "quantity": 1, "frequency": "Apply QID", "duration": "3–5 days",
         "notes": "Soothes teething pain."},

        # Bleeding Control
        {"category": "Bleeding Control", "drug_name": "Tranexamic Acid", "dosage_form": "Mouthwash", "strength": "4.8%",
         "quantity": 1, "frequency": "Rinse QID", "duration": "2–5 days",
         "notes": "Do not swallow; controls bleeding."},
    ]

    # Add each to DB
    for med in medicines:
        new_med = MedicineMaster(
            category=med["category"],
            drug_name=med["drug_name"],
            dosage_form=med["dosage_form"],
            strength=med["strength"],
            quantity=med["quantity"],
            frequency=med["frequency"],
            duration=med["duration"],
            notes=med["notes"],
        )
        db.session.add(new_med)

    db.session.commit()
    return f"{len(medicines)} default medicines loaded!"

# ---------------------------------
# EDIT MEDICINE
# ---------------------------------
@app.route("/medicine_master/<int:med_id>/edit", methods=["GET", "POST"])
def edit_medicine(med_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    med = MedicineMaster.query.get_or_404(med_id)

    if request.method == "POST":
        med.category = (request.form.get("category") or "").strip() or None
        med.drug_name = (request.form.get("drug_name") or "").strip()
        med.dosage_form = (request.form.get("dosage_form") or "").strip() or None
        med.strength = (request.form.get("strength") or "").strip() or None
        med.quantity = (request.form.get("quantity") or "").strip() or None
        med.frequency = (request.form.get("frequency") or "").strip() or None
        med.duration = (request.form.get("duration") or "").strip() or None
        med.notes = (request.form.get("notes") or "").strip() or None

        if not med.drug_name:
            flash("Drug name cannot be empty.", "danger")
        else:
            db.session.commit()
            flash("Medicine updated.", "success")
            return redirect(url_for("medicine_master"))

    return render_template("edit_medicine.html", med=med)


# ---------------------------------
# DELETE MEDICINE
# ---------------------------------
@app.route("/medicine_master/<int:med_id>/delete")
def delete_medicine(med_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    med = MedicineMaster.query.get_or_404(med_id)
    db.session.delete(med)
    db.session.commit()
    flash("Medicine deleted from library.", "info")
    return redirect(url_for("medicine_master"))

@app.route("/add_treatment/<int:patient_id>", methods=["GET", "POST"])
def add_treatment(patient_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    patient = Patient.query.get_or_404(patient_id)
    dentists = Dentist.query.all()
    cases = Case.query.filter_by(patient_id=patient.id).order_by(Case.id.desc()).all()

    # -----------------------------
    # VISIT VALIDATION
    # -----------------------------
    raw_post_visit = request.form.get("visit_id", "")
    raw_query_visit = request.args.get("visit_id", "")

    visit_id = raw_post_visit if raw_post_visit.isdigit() else raw_query_visit if raw_query_visit.isdigit() else None
    visit = db.session.get(Visit, int(visit_id)) if visit_id else None

    if not visit or visit.patient_id != patient.id:
        flash("Please select a valid visit first.", "danger")
        return redirect(url_for("view_patient", patient_id=patient.id) + "#visits")

    # -----------------------------
    # POST → ADD TREATMENT
    # -----------------------------
    if request.method == "POST":

        # BASIC FIELDS
        treatment_category = request.form.get("treatment_category")
        treatment_type = request.form.get("treatment_type")
        tooth_number = request.form.get("tooth_number") or request.form.get("multi_tooth")
        notes = request.form.get("treatment")
        obt_material = request.form.get("obturation_material")

        fee = float(request.form.get("treatment_fee") or 0)
        paid = float(request.form.get("amount_received") or 0)
        next_appt = request.form.get("next_appointment")

        # -----------------------------
        # CASE ID SELECTION
        # -----------------------------
        selected_case = request.form.get("case_id", "").strip()
        manual_case = request.form.get("case_id_manual", "").strip()

        if manual_case:
            case_id = manual_case
        elif selected_case:
            case_id = selected_case
        else:
            today = datetime.now().strftime("%Y%m%d")
            prefix = f"CASE-{patient.id}-{today}"
            count = Case.query.filter(
                Case.case_id.like(f"{prefix}%"),
                Case.patient_id == patient.id
            ).count()
            case_id = f"{prefix}-{count + 1:02d}"

        # Create case if new
        existing_case = Case.query.filter_by(case_id=case_id, patient_id=patient.id).first()
        if not existing_case:
            new_case = Case(case_id=case_id, title=f"Case {case_id}", patient_id=patient.id, status="Active")
            db.session.add(new_case)
            db.session.commit()

        # -----------------------------
        # DENTIST
        # -----------------------------
        dentist_id = request.form.get("dentist_id")
        dentist_id = int(dentist_id) if dentist_id and dentist_id.isdigit() else None
        dentist_name = db.session.get(Dentist, dentist_id).name if dentist_id else session.get("username")

        today_str = datetime.now().strftime("%Y-%m-%d")

        # -----------------------------
        # RCT — COLLECT WL + MAF
        # -----------------------------
        wl_pairs = []
        maf_pairs = []

        canal_list = ["MB","MB1","MB2","DB","DL","P","M","D","A","B","C","ML","Li","L","D"]

        for canal in canal_list:
            wl_val = request.form.get(f"wl_{canal}")
            maf_val = request.form.get(f"maf_{canal}")

            if wl_val: wl_pairs.append(f"{canal}:{wl_val}")
            if maf_val: maf_pairs.append(f"{canal}:{maf_val}")

        final_wl = ",".join(wl_pairs) if wl_pairs else None
        final_maf = ",".join(maf_pairs) if maf_pairs else None

        # -----------------------------
        # EXTRACTION FIELDS
        # -----------------------------
        extraction_type = request.form.get("extraction_type")
        impaction_type = request.form.get("impaction_type")
        extraction_difficulty = request.form.get("extraction_difficulty")
        flap_type = request.form.get("flap_type")
        suture_type = request.form.get("suture_type")
        bone_removal = True if request.form.get("bone_removal") else False
        sectioning = True if request.form.get("tooth_sectioning") else False
        sectioning_details = request.form.get("sectioning_details")

        # -----------------------------
        # POST OP INSTRUCTIONS
        # -----------------------------
        post_op = request.form.get("post_op")  # if you choose to save them

        # -----------------------------
        # CREATE TREATMENT OBJECT
        # -----------------------------
        treatment = Treatment(
            patient_id=patient.id,
            case_id=case_id,
            dentist_id=dentist_id,
            doctor=dentist_name,
            visit_id=visit.id,

            # CORE INFO
            date=today_str,
            treatment_category=treatment_category,
            treatment_type=treatment_type,
            tooth_number=tooth_number,
            notes=notes,
            post_op=post_op,

            # RCT
            obturation_material=obt_material,
            working_length=final_wl,
            maf=final_maf,

            # EXTRACTION
            extraction_type=extraction_type,
            impaction_type=impaction_type,
            extraction_difficulty=extraction_difficulty,
            flap_type=flap_type,
            suture_type=suture_type,
            bone_removal=bone_removal,
            tooth_sectioning=sectioning,
            sectioning_details=sectioning_details,

            # PAYMENT
            amount=fee,
            next_appointment=next_appt,
            status="Completed" if not next_appt else "Ongoing"
        )

        db.session.add(treatment)
        db.session.commit()

        # -----------------------------
        # PAYMENT RECORD
        # -----------------------------
        prev_paid = sum(p.amount_paid or 0 for p in Payment.query.filter_by(patient_id=patient.id))
        prev_fee = sum(t.amount or 0 for t in Treatment.query.filter_by(patient_id=patient.id))
        balance = prev_fee - prev_paid

        payment = Payment(
            patient_id=patient.id,
            treatment_id=treatment.id,
            case_id=case_id,
            date=today_str,
            treatment_fee=fee,
            amount_paid=paid,
            remaining_balance=balance
        )
        db.session.add(payment)
        db.session.commit()

        # -----------------------------
        # FILE UPLOAD
        # -----------------------------
        file = request.files.get("attachment")
        if file and file.filename and allowed_file(file.filename):
            fn = secure_filename(file.filename)
            unique = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{random.randint(1000,9999)}_{fn}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], unique))

            db.session.add(Radiograph(
                patient_id=patient.id,
                treatment_id=treatment.id,
                case_id=case_id,
                filename=unique,
                uploaded_by=session.get("username"),
                uploaded_at=datetime.now().strftime("%Y-%m-%d %H:%M")
            ))
            db.session.commit()

        flash("Treatment added successfully!", "success")
        return redirect(url_for("view_patient", patient_id=patient.id) + "#visits")

    # -----------------------------
    # RENDER FORM
    # -----------------------------
    prev_paid = sum(p.amount_paid or 0 for p in Payment.query.filter_by(patient_id=patient.id))
    prev_fee = sum(t.amount or 0 for t in Treatment.query.filter_by(patient_id=patient.id))
    balance = prev_fee - prev_paid

    return render_template("add_treatment.html", patient=patient, dentists=dentists, cases=cases, visit=visit, previous_balance=balance)




# ---------------------------------
@app.route('/view_patient/<int:patient_id>')
@login_required
def view_patient(patient_id):
    # 🔹 Load patient and related info
    patient = Patient.query.get_or_404(patient_id)

    # 🔹 All cases
    cases = (
        Case.query.filter_by(patient_id=patient.id)
        .order_by(Case.id.desc())
        .all()
    )

    # 🔹 All visits (each visit has treatments)
    visits = (
        Visit.query.filter_by(patient_id=patient.id)
        .order_by(Visit.visit_date.desc(), Visit.id.desc())
        .all()
    )

    # 🔹 Preload all treatments linked to this patient (for totals)
    treatments = (
        Treatment.query.filter_by(patient_id=patient.id)
        .order_by(Treatment.date.desc())
        .all()
    )

    # 🔹 Fetch all payments and radiographs
    payments = (
        Payment.query.filter_by(patient_id=patient.id)
        .order_by(Payment.date.desc())
        .all()
    )
    radiographs = (
        Radiograph.query.filter_by(patient_id=patient.id)
        .order_by(Radiograph.uploaded_at.desc())
        .all()
    )

    # 🔹 Totals
    total_fee = sum(t.amount or 0 for t in treatments)
    total_paid = sum(p.amount_paid or 0 for p in payments)
    remaining = total_fee - total_paid

    # 🔹 Dynamic field list for medical history table
    patient_fields = {
        'Heart Disease': patient.heart_disease,
        'High Blood Pressure': patient.blood_pressure,
        'Diabetes': patient.diabetes,
        'Asthma': patient.asthma,
        'Tuberculosis': patient.tuberculosis,
        'Hepatitis / Jaundice': patient.hepatitis,
        'Bleeding Disorder': patient.bleeding_disorder,
        'Epilepsy': patient.epilepsy,
        'Thyroid Disorder': patient.thyroid_disorder,
        'Kidney Disease': patient.kidney_disease,
        'Stomach Ulcers': patient.stomach_ulcers,
        'Psychiatric Disorder': patient.psychiatric_disorder,
    }

    return render_template(
        'view_patient.html',
        patient=patient,
        cases=cases,
        visits=visits,          # 🔵 NEW
        treatments=treatments,
        payments=payments,
        radiographs=radiographs,
        patient_fields=patient_fields,
        total_fee=total_fee,
        total_paid=total_paid,
        remaining=remaining,
    )
@app.route("/edit_personal/<int:patient_id>", methods=["POST"])
def edit_personal(patient_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    patient = Patient.query.get_or_404(patient_id)

    patient.full_name = request.form.get("full_name") or patient.full_name
    patient.father_or_spouse_name = request.form.get("father_or_spouse_name")
    patient.gender = request.form.get("gender")
    patient.dob_or_age = request.form.get("dob_or_age")
    patient.marital_status = request.form.get("marital_status")
    patient.occupation = request.form.get("occupation")
    patient.contact = request.form.get("contact")
    patient.email = request.form.get("email")
    patient.cnic = request.form.get("cnic")
    patient.address = request.form.get("address")

    db.session.commit()
    flash("Personal information updated successfully.", "success")
    return redirect(url_for("view_patient", patient_id=patient.id) + "#info")
@app.route("/edit_medical/<int:patient_id>", methods=["POST"])
def edit_medical(patient_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    patient = Patient.query.get_or_404(patient_id)

    # Yes/No fields
    for field in [
        "heart_disease", "blood_pressure", "diabetes", "asthma",
        "tuberculosis", "hepatitis", "bleeding_disorder",
        "epilepsy", "thyroid_disorder", "kidney_disease",
        "stomach_ulcers", "psychiatric_disorder"
    ]:
        setattr(patient, field, "Yes" if request.form.get(field) else "No")

    patient.medications = request.form.get("medications")
    patient.allergies = request.form.get("allergies")
    patient.other_health = request.form.get("other_health")
    patient.surgery_history = request.form.get("surgery_history")

    db.session.commit()
    flash("Medical history updated successfully.", "success")
    return redirect(url_for("view_patient", patient_id=patient.id) + "#medical")
@app.route("/delete_visit/<int:visit_id>")
def delete_visit(visit_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    visit = Visit.query.get_or_404(visit_id)
    patient_id = visit.patient_id

    # Delete treatments under this visit
    for t in list(visit.treatments):
        # Delete payments linked to this treatment
        for pay in list(t.payments):
            db.session.delete(pay)

        # Delete radiographs linked to this treatment (and files)
        for f in Radiograph.query.filter_by(treatment_id=t.id).all():
            path = os.path.join(app.config["UPLOAD_FOLDER"], f.filename)
            if os.path.exists(path):
                os.remove(path)
            db.session.delete(f)

        # FollowUps & Prescriptions are already cascade="all, delete-orphan"
        db.session.delete(t)

    db.session.delete(visit)
    db.session.commit()

    flash("Visit and all related treatments, follow-ups, payments and files deleted.", "success")
    return redirect(url_for("view_patient", patient_id=patient_id) + "#visits")
@app.route("/edit_dental/<int:patient_id>", methods=["POST"])
def edit_dental(patient_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    patient = Patient.query.get_or_404(patient_id)

    # ---------------------------------------------
    # SIMPLE TEXT FIELDS
    # ---------------------------------------------
    patient.last_dental_visit = request.form.get("last_dental_visit")
    patient.last_dental_reason = request.form.get("last_dental_reason")
    patient.treat_other = request.form.get("treat_other")
    patient.bad_experience = request.form.get("bad_experience")
    patient.bad_experience_details = request.form.get("bad_experience_details")
    patient.smoking_frequency = request.form.get("smoking_frequency")
    patient.dental_notes = request.form.get("dental_notes")

    # NEW FIELDS ADDED
    patient.tmj_issue = "Yes" if request.form.get("tmj_issue") else "No"
    patient.tmj_notes = request.form.get("tmj_notes")
    patient.oral_hygiene = request.form.get("oral_hygiene")
    patient.caries_risk = request.form.get("caries_risk")
    patient.soft_tissue_notes = request.form.get("soft_tissue_notes")

    # ---------------------------------------------
    # YES/NO CHECKBOX GROUPS
    # ---------------------------------------------
    yes_no_fields = [
        # Previous Treatments
        "treat_fillings", "treat_rct", "treat_crowns", "treat_extractions",
        "treat_scaling", "treat_denture", "treat_braces", "treat_implant",

        # Gum
        "gum_bleeding", "gum_loose", "gum_badbreath", "gum_none",

        # Caries / sensitivity
        "sensitive_teeth", "frequent_cavities", "caries_none",

        # Trauma
        "fractured_tooth", "jaw_accident", "trauma_none",

        # Prosthesis
        "prosthesis_crown", "prosthesis_denture",
        "prosthesis_implant", "prosthesis_braces", "prosthesis_none",

        # Habits
        "uses_tobacco", "uses_naswar", "uses_paan", "uses_smoke",
    ]

    for field in yes_no_fields:
        setattr(patient, field, "Yes" if request.form.get(field) else "No")

    # ---------------------------------------------
    db.session.commit()
    flash("Dental history updated successfully.", "success")
    return redirect(url_for("view_patient", patient_id=patient.id) + "#dental")


# ---------------------------
# CASES & VISITS ROUTES
# ---------------------------

@app.route('/add_case/<int:patient_id>', methods=['GET', 'POST'])
def add_case(patient_id):
    if not require_role(['doctor', 'assistant']):
        return redirect(url_for('login'))

    patient = Patient.query.get_or_404(patient_id)

    if request.method == 'POST':
        case = Case(
            title=request.form.get('title') or '',
            chief_complaint=request.form.get('chief_complaint') or '',
            diagnosis=request.form.get('diagnosis') or '',
            treatment_plan=request.form.get('treatment_plan') or '',
            patient_id=patient.id,

            # 🧩 Dynamic health info
            pregnant='Yes' if request.form.get('pregnant') else 'No',
            pregnancy_weeks=request.form.get('pregnancy_weeks'),
            breastfeeding='Yes' if request.form.get('breastfeeding') else 'No',
            new_medications=request.form.get('new_medications'),
            recent_illness=request.form.get('recent_illness'),
            new_conditions=request.form.get('new_conditions'),
            change_in_allergy_or_medication=request.form.get('change_in_allergy_or_medication')
        )

        case.generate_case_no()
        db.session.add(case)
        db.session.commit()

        flash('Case created successfully.', 'success')
        return redirect(url_for('view_case', case_id=case.id))

    return render_template('add_case.html', patient=patient)
# Add Case
# ---------------------------------
# ADD VISIT (Manual Appointment)
# ---------------------------------
@app.route("/add_visit/<int:patient_id>", methods=["GET", "POST"])
def add_visit(patient_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    patient = Patient.query.get_or_404(patient_id)
    dentists = Dentist.query.all()

    if request.method == "POST":
        # Basic visit fields
        visit_date = request.form.get("visit_date") or datetime.now().strftime("%Y-%m-%d")
        dentist_id = request.form.get("dentist_id")
        dentist_id = int(dentist_id) if dentist_id and dentist_id.isdigit() else None

        v = Visit(
            patient_id=patient.id,
            doctor_id=dentist_id,
            visit_date=visit_date,
            chief_complaint=request.form.get("chief_complaint"),
            acute_issue=request.form.get("acute_issue"),
            bp=request.form.get("bp"),
            pregnant=request.form.get("pregnant"),
            pregnancy_weeks=request.form.get("pregnancy_weeks"),
            breastfeeding=request.form.get("breastfeeding"),
            notes=request.form.get("visit_notes")
        )

        # Optional attachment
        file = request.files.get("attachment")
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{random.randint(1000,9999)}_{filename}"
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], unique))
            v.attachment = unique

        db.session.add(v)
        db.session.commit()

        flash("Visit added successfully. Now add treatment(s) inside this visit.", "success")
        return redirect(url_for("view_patient", patient_id=patient.id) + "#visits")

    return render_template("add_visit.html", patient=patient, dentists=dentists)


# View Case (case detail + treatments)
@app.route('/view_case/<int:case_id>')
def view_case(case_id):
    case = Case.query.get_or_404(case_id)
    treatments = Treatment.query.filter_by(case_id=case.id).order_by(Treatment.id.desc()).all()
    return render_template('view_case.html', case=case, treatments=treatments)

# ---------------------------------
# VIEW TREATMENT DETAILS PAGE
# ---------------------------------
@app.route('/view_treatment/<int:treatment_id>')
@login_required
def view_treatment(treatment_id):
    treatment = Treatment.query.get_or_404(treatment_id)
    followups = FollowUp.query.filter_by(treatment_id=treatment.id).order_by(FollowUp.date.desc()).all()
    patient = Patient.query.get(treatment.patient_id)
    case = Case.query.get(treatment.case_id)
    payments = Payment.query.filter_by(treatment_id=treatment.id).all()
    radiographs = Radiograph.query.filter_by(treatment_id=treatment.id).all()

    total_paid = sum(p.amount_paid for p in payments)
    remaining = (treatment.amount or 0) - total_paid

    return render_template(
        "view_treatment.html",
        treatment=treatment,
        patient=patient,
        case=case,
        followups=followups,
        payments=payments,
        radiographs=radiographs,
        total_paid=total_paid,
        remaining=remaining
    )

# ---------------------------------

@app.route("/treatment/<int:treatment_id>/add_followup", methods=["GET", "POST"])
def add_followup(treatment_id):
    treatment = Treatment.query.get_or_404(treatment_id)

    if request.method == "POST":
        notes = request.form.get("notes", "").strip()
        status = request.form.get("status")
        next_appointment = request.form.get("next_appointment", "")
        update_flag = request.form.get("update_treatment_status")  # "1" or "0"

        # Basic validation
        if not notes:
            flash("Follow-up notes are required.", "danger")
            return redirect(request.url)

        # Save attachment if provided
        attachment_file = request.files.get("attachment")
        attachment_filename = None

        if attachment_file and attachment_file.filename:
            filename = secure_filename(attachment_file.filename)
            upload_path = os.path.join(UPLOAD_FOLDER, filename)
            attachment_file.save(upload_path)
            attachment_filename = filename

        # Create follow-up entry
        followup = FollowUp(
            treatment_id=treatment.id,
            notes=notes,
            status=status,
            next_appointment=next_appointment if status == "Ongoing" else None,
            attachment=attachment_filename
        )
        db.session.add(followup)

        # -------------------------------------------------------------
        # LOGIC TO UPDATE TREATMENT BASED ON FOLLOW-UP
        # -------------------------------------------------------------
        if update_flag == "1":
            # Mark parent treatment completed
            treatment.status = "Completed"
            treatment.next_appointment = None
        else:
            # If follow-up is ongoing and next appointment was given
            if status == "Ongoing" and next_appointment:
                treatment.next_appointment = next_appointment

        # Optional: update timestamp if your model has updated_at field
        if hasattr(treatment, "updated_at"):
            treatment.updated_at = datetime.utcnow()

        db.session.commit()

        flash("Follow-up added successfully.", "success")
        return redirect(url_for("view_treatment", treatment_id=treatment.id))

    return render_template("add_followup.html", treatment=treatment)

# Mark any Case / Treatment / Follow-up as Completed
@app.route('/mark_complete/<obj_type>/<int:obj_id>')
def mark_complete(obj_type, obj_id):
    if not require_role(['doctor', 'assistant']):
        return redirect(url_for('login'))

    if obj_type == 'case':
        o = Case.query.get_or_404(obj_id)
        o.status = 'Completed'
    elif obj_type == 'treatment':
        o = Treatment.query.get_or_404(obj_id)
        o.status = 'Completed'
    elif obj_type == 'followup':
        o = FollowUp.query.get_or_404(obj_id)
        o.status = 'Completed'
    else:
        flash('Invalid object type.', 'danger')
        return redirect(url_for('dashboard_main'))

    db.session.commit()
    flash('Marked as completed.', 'success')

    # Redirect appropriately
    if obj_type == 'case':
        return redirect(url_for('view_case', case_id=obj_id))
    elif obj_type == 'treatment':
        return redirect(url_for('view_treatment', treatment_id=obj_id))
    else:
        return redirect(url_for('view_treatment', treatment_id=o.treatment_id))


# Delete Case
@app.route('/delete_case/<int:case_id>')
def delete_case(case_id):
    if not require_role(['doctor', 'assistant']):
        return redirect(url_for('login'))

    c = Case.query.get_or_404(case_id)
    pid = c.patient_id
    db.session.delete(c)
    db.session.commit()

    flash('Case deleted.', 'success')
    return redirect(url_for('view_patient', patient_id=pid))


# Delete Treatment
@app.route('/delete_treatment/<int:treatment_id>')
def delete_treatment(treatment_id):
    if not require_role(['doctor', 'assistant']):
        return redirect(url_for('login'))

    t = Treatment.query.get_or_404(treatment_id)
    pid = t.patient_id
    db.session.delete(t)
    db.session.commit()

    flash('Treatment deleted.', 'success')
    return redirect(url_for('view_patient', patient_id=pid))


# Delete Follow-up
@app.route('/delete_followup/<int:followup_id>')
def delete_followup(followup_id):
    if not require_role(['doctor', 'assistant']):
        return redirect(url_for('login'))

    f = FollowUp.query.get_or_404(followup_id)
    tid = f.treatment_id
    db.session.delete(f)
    db.session.commit()

    flash('Follow-up deleted.', 'success')
    return redirect(url_for('view_treatment', treatment_id=tid))

# ---------------------------------
# ADD / EDIT VISIT-LEVEL PRESCRIPTION (ONE PER VISIT)
# ---------------------------------

# ---------------------------------
# VISIT-LEVEL PRESCRIPTION (ADD / EDIT)
# ---------------------------------
# ---------------------------------
# VISIT-LEVEL PRESCRIPTION (ADD / EDIT)
# ---------------------------------
@app.route("/visit/<int:visit_id>/prescription/print")
def print_visit_prescription(visit_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    visit = Visit.query.get_or_404(visit_id)

    # Same logic
    prescription = VisitPrescription.query.filter_by(visit_id=visit.id).first()

    if not prescription:
        flash("No prescription available to print for this visit.", "warning")
        return redirect(url_for("view_patient", patient_id=visit.patient_id) + "#visits")

    return render_template(
        "print_visit_prescription.html",
        visit=visit,
        patient=visit.patient,
        prescription=prescription,
        items=prescription.items,    # ← Items to print
        today=datetime.now().strftime("%d-%m-%Y")
    )



# ---------------------------------
# PRINT VISIT-LEVEL PRESCRIPTION
# ---------------------------------
@app.route("/print_patient/<int:patient_id>")
def print_patient(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    treatments = Treatment.query.filter_by(patient_id=patient.id).all()
    total_fee = sum(t.amount for t in treatments)
    payments = Payment.query.filter_by(patient_id=patient.id).all()
    total_paid = sum(p.amount_paid for p in payments)
    remaining = total_fee - total_paid

    return render_template(
        "print_patient.html",
        patient=patient,
        treatments=treatments,
        total_fee=total_fee,
        total_paid=total_paid,
        remaining=remaining,
        datetime=datetime  # ✅ pass datetime to Jinja
    )

# ---------------------------------
# PRINT / SUMMARY ROUTES
# ---------------------------------
@app.route("/print_payment_summary/<int:patient_id>")
def print_payment_summary(patient_id):
    patient = Patient.query.get_or_404(patient_id)
    payments = Payment.query.filter_by(patient_id=patient.id).all()
    treatments = Treatment.query.filter_by(patient_id=patient.id).all()
    total_fee = sum(t.amount for t in treatments)
    total_paid = sum(p.amount_paid for p in payments)
    remaining = total_fee - total_paid

    return render_template(
        "print_payment_summary.html",
        patient=patient,
        payments=payments,
        total_fee=total_fee,
        total_paid=total_paid,
        remaining=remaining,
        datetime=datetime
    )

# ---------------------------------
# PRINT: VISIT SUMMARY
# ---------------------------------
@app.route("/print_visit_summary/<int:visit_id>")
def print_visit_summary(visit_id):
    # Allow doctor, assistant, patient to print
    if session.get("role") not in ["doctor", "assistant", "patient"]:
        return redirect(url_for("login"))

    visit = Visit.query.get_or_404(visit_id)
    patient = visit.patient

    # All treatments under this visit
    visit_treatments = Treatment.query.filter_by(visit_id=visit.id).order_by(Treatment.date.asc()).all()

    # Visit-level prescription (one-to-one)
    rx = visit.prescription

    return render_template(
        "print_visit_summary.html",
        patient=patient,
        visit=visit,
        treatments=visit_treatments,
        rx=rx
    )


# ---------------------------------
# PRINT: VISIT INVOICE
# ---------------------------------
@app.route("/print_visit_invoice/<int:visit_id>")
def print_visit_invoice(visit_id):
    if session.get("role") not in ["doctor", "assistant", "patient"]:
        return redirect(url_for("login"))

    visit = Visit.query.get_or_404(visit_id)
    patient = visit.patient

    # All treatments under this visit
    visit_treatments = Treatment.query.filter_by(visit_id=visit.id).all()
    treatment_ids = [t.id for t in visit_treatments]

    # Payments linked to these treatments
    if treatment_ids:
        visit_payments = Payment.query.filter(Payment.treatment_id.in_(treatment_ids)) \
                                      .order_by(Payment.date.asc()).all()
    else:
        visit_payments = []

    visit_fee = sum(t.amount or 0 for t in visit_treatments)
    paid_for_visit = sum(p.amount_paid or 0 for p in visit_payments)
    remaining_for_visit = visit_fee - paid_for_visit

    return render_template(
        "print_visit_invoice.html",
        patient=patient,
        visit=visit,
        treatments=visit_treatments,
        payments=visit_payments,
        visit_fee=visit_fee,
        paid_for_visit=paid_for_visit,
        remaining_for_visit=remaining_for_visit
    )


# ---------------------------------
# PRINT: MEDICAL / DENTAL PROCEDURE CERTIFICATE
# ---------------------------------
@app.route("/print_medical_certificate/<int:visit_id>")
def print_medical_certificate(visit_id):
    if session.get("role") not in ["doctor", "assistant", "patient"]:
        return redirect(url_for("login"))

    visit = Visit.query.get_or_404(visit_id)
    patient = visit.patient

    # Treatments for wording (e.g. extractions, RCT etc.)
    visit_treatments = Treatment.query.filter_by(visit_id=visit.id).all()

    return render_template(
        "print_medical_certificate.html",
        patient=patient,
        visit=visit,
        treatments=visit_treatments
    )

@app.route("/upload_file/<int:patient_id>", methods=["GET", "POST"])
def upload_file(patient_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))
    patient = Patient.query.get_or_404(patient_id)

    if request.method == "POST":
        files = request.files.getlist("files")
        if not files or all(f.filename == "" for f in files):
            flash("No files selected.", "warning")
            return redirect(request.url)

        for f in files:
            if f and getattr(f, "filename", "") and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{random.randint(1000,9999)}_{filename}"
                f.save(os.path.join(app.config["UPLOAD_FOLDER"], unique_name))
                db.session.add(Radiograph(
                    patient_id=patient.id,
                    filename=unique_name,
                    uploaded_by=session.get("username"),
                    uploaded_at=datetime.now().strftime("%Y-%m-%d %H:%M")
                ))
        db.session.commit()
        flash("Files uploaded successfully.", "success")
        return redirect(url_for("view_patient", patient_id=patient.id))

    return render_template("upload_file.html", patient=patient)



# VISIT-LEVEL PRESCRIPTION (ADD / EDIT)
# -------------------------------------
# ---------------------------------
# VISIT-LEVEL PRESCRIPTION (ADD / EDIT)
# -------------------------------------
@app.route("/visit/<int:visit_id>/prescription", methods=["GET", "POST"])
def visit_prescription(visit_id):
    # Only doctor / assistant can create or edit prescriptions
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    visit = db.session.get(Visit, visit_id)
    patient = visit.patient
    prescription = visit.prescription  # One-to-one relationship

    if request.method == "POST":
        rx_notes = request.form.get("rx_notes") or None

        # Create prescription if not exists
        if prescription is None:
            prescription = VisitPrescription(
                visit_id=visit.id,
                notes=rx_notes,
            )
            db.session.add(prescription)
            db.session.flush()  # Save and get prescription.id
        else:
            prescription.notes = rx_notes

        # Gather prescription item fields
        fields = ["drug_name[]", "dosage_form[]", "strength[]", "quantity[]",
                  "frequency[]", "duration[]", "item_notes[]"]
        drug_names, dosage_forms, strengths, quantities, frequencies, durations, item_notes = [
            request.form.getlist(field) for field in fields
        ]

        # Clear existing items and add new ones
        PrescriptionItem.query.filter_by(prescription_id=prescription.id).delete()
        for i, name in enumerate(drug_names):
            name = name.strip() if name else ""
            if name:
                item = PrescriptionItem(
                    prescription_id=prescription.id,
                    drug_name=name,
                    dosage_form=dosage_forms[i] if i < len(dosage_forms) else None,
                    strength=strengths[i] if i < len(strengths) else None,
                    quantity=quantities[i] if i < len(quantities) else None,
                    frequency=frequencies[i] if i < len(frequencies) else None,
                    duration=durations[i] if i < len(durations) else None,
                    notes=item_notes[i] if i < len(item_notes) else None,
                )
                db.session.add(item)

        db.session.commit()
        flash("Visit prescription saved successfully.", "success")
        return redirect(url_for("view_patient", patient_id=visit.patient_id) + "#visits")

    # GET request
    items = prescription.items if prescription else []
    medicine_list = MedicineMaster.query.order_by(
        MedicineMaster.category, MedicineMaster.drug_name
    ).all()

    # 🧠 Use global condition protocols (imported or defined above)
    return render_template(
        "visit_prescription.html",
        visit=visit,
        patient=patient,
        prescription=prescription,
        items=items,
        medicine_list=medicine_list,
        condition_protocols=CONDITION_PROTOCOLS,
        condition_groups=CONDITION_GROUPS,
    )

@app.route("/delete_file/<int:file_id>")
def delete_file(file_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))
    f = Radiograph.query.get_or_404(file_id)
    patient_id = f.patient_id
    path = os.path.join(app.config["UPLOAD_FOLDER"], f.filename)
    if os.path.exists(path):
        os.remove(path)
    db.session.delete(f)
    db.session.commit()
    flash("File deleted successfully.", "info")
    return redirect(url_for("view_patient", patient_id=patient_id))


@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ---------------------------------
# DELETE PAYMENT
# ---------------------------------
@app.route("/delete_payment/<int:payment_id>")
def delete_payment(payment_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))
    pay = Payment.query.get_or_404(payment_id)
    pid = pay.patient_id
    db.session.delete(pay)
    db.session.commit()
    flash("Payment record deleted.", "info")
    return redirect(url_for("view_patient", patient_id=pid))


# ---------------------------------
# DELETE PATIENT
# ---------------------------------
@app.route("/delete_patient/<int:patient_id>")
def delete_patient(patient_id):
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))
    patient = Patient.query.get_or_404(patient_id)
    Treatment.query.filter_by(patient_id=patient.id).delete()
    Payment.query.filter_by(patient_id=patient.id).delete()
    for f in Radiograph.query.filter_by(patient_id=patient.id):
        path = os.path.join(app.config["UPLOAD_FOLDER"], f.filename)
        if os.path.exists(path):
            os.remove(path)
        db.session.delete(f)
    user = User.query.filter_by(username=patient.file_no, role="patient").first()
    if user:
        db.session.delete(user)
    db.session.delete(patient)
    db.session.commit()
    flash("Patient and related data deleted.", "success")
    return redirect(url_for("dashboard_main"))


# ---------------------------------
# PATIENT LOGINS
# ---------------------------------
@app.route("/patient_logins")
def patient_logins():
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))
    q = request.args.get("q", "")
    users = User.query.filter_by(role="patient").all() if not q else \
        User.query.filter(User.role == "patient", User.username.ilike(f"%{q}%")).all()
    return render_template("patient_logins.html", users=users, query=q)


# ---------------------------------
# ---------------------------------
#
@app.route("/dashboard_patient")
def dashboard_patient():
    # Only patient role allowed
    if session.get("role") != "patient":
        return redirect(url_for("login"))

    # Patient is mapped to file_no = username
    patient = Patient.query.filter_by(file_no=session.get("username")).first()
    if not patient:
        flash("Patient record not found. Please contact the clinic.", "danger")
        return redirect(url_for("logout"))

    # Fetch visits (new EMR structure)
    visits = Visit.query.filter_by(patient_id=patient.id) \
                        .order_by(Visit.visit_date.desc()) \
                        .all()

    # Attach prescriptions (if exist) to each visit
    for visit in visits:
        prescription = VisitPrescription.query.filter_by(visit_id=visit.id).first()
        visit.prescriptions = (
            prescription.items if prescription and prescription.items else []
        )
        visit.rx_notes = prescription.notes if prescription else None

    # Fetch all treatments (for totals + any summaries if needed)
    treatments = Treatment.query.filter_by(patient_id=patient.id) \
                                .order_by(Treatment.date.desc()) \
                                .all()

    # Attach prescription-related treatment data
    for treatment in treatments:
        prescription = VisitPrescription.query.filter_by(visit_id=treatment.visit_id).first()
        treatment.prescriptions = (
            prescription.items if prescription and prescription.items else []
        )
        treatment.rx_notes = prescription.notes if prescription else None

    # Payments & radiographs
    payments = Payment.query.filter_by(patient_id=patient.id) \
                            .order_by(Payment.date.desc()) \
                            .all()

    radiographs = Radiograph.query.filter_by(patient_id=patient.id) \
                                  .order_by(Radiograph.uploaded_at.desc()) \
                                  .all()

    # Totals
    total_fee = sum(t.amount or 0 for t in treatments)
    total_paid = sum(p.amount_paid or 0 for p in payments)
    remaining = total_fee - total_paid

    # Render dedicated read-only patient dashboard with all data
    return render_template(
        "dashboard_patient.html",
        patient=patient,
        visits=visits,
        treatments=treatments,
        payments=payments,
        radiographs=radiographs,
        total_fee=total_fee,
        total_paid=total_paid,
        remaining=remaining
    )

# ---------------------------------
# NEW FEATURE: DUE / UPCOMING APPOINTMENTS
# ---------------------------------
@app.route("/due_appointments")
def due_appointments():
    if not require_role(["doctor", "assistant"]):
        return redirect(url_for("login"))

    today = datetime.now().strftime("%Y-%m-%d")
    appointments = Treatment.query.filter(
        Treatment.next_appointment != None,
        Treatment.next_appointment != "",
        Treatment.next_appointment >= today
    ).order_by(Treatment.next_appointment.asc()).all()

    return render_template("due_appointments.html", appointments=appointments)


# ---------------------------------
# HOME
# ---------------------------------
@app.route("/")
def home():
    if session.get("role") in ["doctor", "assistant"]:
        return redirect(url_for("dashboard_main"))
    elif session.get("role") == "patient":
        return redirect(url_for("dashboard_patient"))
    return redirect(url_for("login"))


# ---------------------------------
# RUN APP
# ---------------------------------
if __name__ == "__main__":
    if not os.path.exists(DB_FILE):
        with app.app_context():
            db.create_all()
        print(f"✅ Database created at: {DB_FILE}")
    else:
        print(f"ℹ️ Using existing database: {DB_FILE}")
    app.run(debug=True)
