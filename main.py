# app.py
import os
import json
from datetime import datetime, timedelta, timezone
import random
import string

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from functools import wraps
from werkzeug.utils import secure_filename

# --- Configuration ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///migrant_ecard.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# **CRITICAL**: Use a strong, random secret key from environment variables in production
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default_dev_secret_key_change_me')

db = SQLAlchemy(app)

# --- Database Model (User) - Updated with user type ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    user_type = db.Column(db.String(20), default='patient')  # 'patient' or 'worker'
    # The registration fields from the flowchart
    name = db.Column(db.String(100))
    phone = db.Column(db.String(20))
    dob = db.Column(db.String(10)) # Stored as string 'YYYY-MM-DD'
    place_address = db.Column(db.String(200))
    gender = db.Column(db.String(20))
    abha_no = db.Column(db.String(20), unique=True, nullable=True)
    
    # Stores the full health profile (Clinical, Vitals, Lifestyle) as a JSON string
    profile_data = db.Column(db.Text, default='{}')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Worker Model ---
class Worker(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    worker_type = db.Column(db.String(50), nullable=False)  # 'doctor', 'nurse', 'admin', etc.
    license_number = db.Column(db.String(50), unique=True, nullable=True)
    specialization = db.Column(db.String(100), nullable=True)
    hospital_clinic = db.Column(db.String(200), nullable=True)
    years_experience = db.Column(db.Integer, nullable=True)
    qualifications = db.Column(db.Text, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    verification_date = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref=db.backref('worker_profile', uselist=False))

# --- JWT Helper Function (Decorator) ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-auth-token')
        if not token:
            return jsonify({'message': 'Authorization token is missing!'}), 401

        try:
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user:
                 return jsonify({'message': 'Token is invalid or user not found!'}), 401
        except:
            return jsonify({'message': 'Token is invalid or expired!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# --- Worker-only decorator ---
def worker_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-auth-token')
        if not token:
            return jsonify({'message': 'Authorization token is missing!'}), 401

        try:
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
            if not current_user or current_user.user_type != 'worker':
                return jsonify({'message': 'Access denied. Worker account required.'}), 403
            
            # Check if worker is verified
            if not current_user.worker_profile or not current_user.worker_profile.is_verified:
                return jsonify({'message': 'Account pending verification. Please contact administrator.'}), 403
        except:
            return jsonify({'message': 'Token is invalid or expired!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# --- HealthRecord Model ---
class HealthRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Core Data
    allergies = db.Column(db.Text, default='')
    current_medications = db.Column(db.Text, default='')
    known_conditions = db.Column(db.Text, default='')
    immunization_history = db.Column(db.Text, default='')
    # Current Vitals
    height_cm = db.Column(db.Float, nullable=True)
    weight_kg = db.Column(db.Float, nullable=True)
    blood_group = db.Column(db.String(10), nullable=True)
    blood_pressure = db.Column(db.String(20), nullable=True)
    # Lifestyle & Habits
    smoking = db.Column(db.String(10), default='No')
    drinking = db.Column(db.String(10), default='No')
    physical_activity = db.Column(db.String(100), default='')
    dietary_habits = db.Column(db.String(100), default='')

    user = db.relationship('User', backref=db.backref('health_records', lazy=True))

# --- Diagnostic Report Model ---
class DiagnosticReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), nullable=True)
    code = db.Column(db.String(100), nullable=True)
    effective_date = db.Column(db.String(30), nullable=True)
    issued_date = db.Column(db.String(30), nullable=True)
    result = db.Column(db.Text, default='')  # Store as JSON string
    conclusion = db.Column(db.Text, default='')

    user = db.relationship('User', backref=db.backref('diagnostic_reports', lazy=True))

# --- Medication Request Model ---
class MedicationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=True)
    intent = db.Column(db.String(20), nullable=True)
    medication = db.Column(db.String(100), nullable=True)
    authored_on = db.Column(db.String(30), nullable=True)
    requester = db.Column(db.String(100), nullable=True)
    dosage_instruction = db.Column(db.Text, default='')  # Store as JSON string
    note = db.Column(db.Text, default='')

    user = db.relationship('User', backref=db.backref('medication_requests', lazy=True))

# --- Configure upload folder and allowed extensions ---
UPLOAD_FOLDER = 'uploaded_health_records'
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Health Document Model ---
class HealthDocument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    document_type = db.Column(db.String(50), nullable=False)
    document_date = db.Column(db.String(20), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.now)

    user = db.relationship('User', backref=db.backref('health_documents', lazy=True))

# Create database tables upon startup
with app.app_context():
    db.create_all()

# --- Worker Registration Route ---
@app.route('/api/register-worker', methods=['POST'])
def register_worker():
    data = request.get_json()
    
    # Check for required fields
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    phone = data.get('phone')
    worker_type = data.get('worker_type')
    license_number = data.get('license_number')

    if not all([email, password, name, phone, worker_type]):
        return jsonify({'message': 'Email, password, name, phone, and worker type are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists'}), 400

    # Check if license number already exists (if provided)
    if license_number and Worker.query.filter_by(license_number=license_number).first():
        return jsonify({'message': 'License number already registered'}), 400

    # Create user account
    new_user = User(
        email=email, 
        name=name,
        phone=phone,
        user_type='worker',
        dob=data.get('dob'),
        gender=data.get('gender'),
        place_address=data.get('place_address')
    )
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()

    # Create worker profile
    new_worker = Worker(
        user_id=new_user.id,
        worker_type=worker_type,
        license_number=license_number,
        specialization=data.get('specialization'),
        hospital_clinic=data.get('hospital_clinic'),
        years_experience=data.get('years_experience'),
        qualifications=data.get('qualifications')
    )
    
    db.session.add(new_worker)
    db.session.commit()

    return jsonify({'message': 'Worker registration successful. Account created and pending verification.'}), 201

# --- Worker Login Route ---
@app.route('/api/login-worker', methods=['POST'])
def login_worker():
    data = request.get_json()
    email = data.get('email')
    license_number = data.get('license_number')
    password = data.get('password')

    if not password or (not email and not license_number):
        return jsonify({'message': 'Email/License number and password are required'}), 400

    user = None
    if email:
        user = User.query.filter_by(email=email, user_type='worker').first()
    elif license_number:
        worker = Worker.query.filter_by(license_number=license_number).first()
        if worker:
            user = worker.user

    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Check if worker is verified
    if not user.worker_profile.is_verified:
        return jsonify({'message': 'Account pending verification. Please contact administrator.'}), 403

    # Create JWT
    token_payload = {
        'user_id': user.id,
        'user_type': 'worker',
        'worker_type': user.worker_profile.worker_type,
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }
    
    token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        'token': token,
        'user_id': user.id,
        'worker_type': user.worker_profile.worker_type,
        'message': 'Worker login successful',
        'is_verified': user.worker_profile.is_verified
    }), 200

# --- Updated Registration Route (for patients) ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Check for required fields based on the flowchart
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    dob = data.get('dob')
    gender = data.get('gender')
    phone = data.get('phone')
    place_address = data.get('place_address')

    if not all([email, password, name, dob, gender, place_address]):
        return jsonify({'message': 'All registration fields are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists'}), 400

    new_user = User(
        email=email, 
        name=name,
        phone=phone,
        dob=dob, 
        gender=gender,
        place_address=place_address,
        user_type='patient'
    )
    new_user.set_password(password)
    
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful. Account created.'}), 201

# --- Updated Login Route (for patients) ---
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    phone = data.get('phone')
    abha_no = data.get('abha_no') 
    password = data.get('password')

    # user will submit either abha or phone

    if not password or (not phone and not abha_no):
        return jsonify({'message': 'Phone/ABHA and password are required'}), 400
    
    user = None
    if phone:
        user = User.query.filter_by(phone=phone, user_type='patient').first()
    elif abha_no:
        user = User.query.filter_by(abha_no=abha_no, user_type='patient').first()

    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid Credentials'}), 401

    # Create JWT
    token_payload = {
        'user_id': user.id,
        'user_type': 'patient',
        'exp': datetime.now(timezone.utc) + timedelta(hours=24)
    }
    
    token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({
        'token': token,
        'user_id': user.id,
        'user_type': 'patient',
        'message': 'Login successful',
        'profile_complete': user.profile_data != '{}'
    }), 200

# --- Protected Profile Update Route (Flowchart Step J to N) ---
@app.route('/api/profile', methods=['PUT'])
@token_required
def update_profile(current_user):
    # This expects the complete, combined JSON object from the React wizard:
    # { "clinical": {..}, "vitals": {..}, "lifestyle": {..} }
    profile_data = request.get_json()

    # Basic check to ensure the data structure looks correct
    if not isinstance(profile_data, dict) or not ('clinical' in profile_data and 'vitals' in profile_data):
        return jsonify({'message': 'Invalid profile data structure'}), 400

    # Convert the Python dictionary into a JSON string and save it to the database
    current_user.profile_data = json.dumps(profile_data)
    db.session.commit()

    return jsonify({
        'message': 'Health profile updated successfully (Profile Active / Data Saved)', 
        'profile_data': profile_data
    }), 200

# --- Protected Profile GET Route ---
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile(current_user):
    # Only return non-confidential basic details
    basic_details = {
        'name': current_user.name,
        'phone': current_user.phone,
        'dob': current_user.dob,
        'place_address': current_user.place_address,
        'gender': current_user.gender,
        # Do NOT return: password_hash, abha_no, profile_data, email
    }
    return jsonify({
        'message': 'Basic profile fetched successfully',
        'basic_details': basic_details
    }), 200

# ----------------------------------------------------

# --- Add Health Record Route ---
@app.route('/api/health-records', methods=['POST'])
@token_required
def add_health_record(current_user):
    data = request.get_json()
    record = HealthRecord(
        user_id=current_user.id,
        allergies=data.get('allergies', ''),
        current_medications=data.get('current_medications', ''),
        known_conditions=data.get('known_conditions', ''),
        immunization_history=data.get('immunization_history', ''),
        height_cm=data.get('height_cm'),
        weight_kg=data.get('weight_kg'),
        blood_group=data.get('blood_group'),
        blood_pressure=data.get('blood_pressure'),
        smoking=data.get('smoking', 'No'),
        drinking=data.get('drinking', 'No'),
        physical_activity=data.get('physical_activity', ''),
        dietary_habits=data.get('dietary_habits', '')
    )
    db.session.add(record)
    db.session.commit()
    return jsonify({'message': 'Health record added successfully', 'record_id': record.id}), 201

# --- Update Health Record Route ---
@app.route('/api/health-records/<int:record_id>', methods=['PUT'])
@token_required
def update_health_record(current_user, record_id):
    record = HealthRecord.query.filter_by(id=record_id, user_id=current_user.id).first()
    if not record:
        return jsonify({'message': 'Health record not found'}), 404
    data = request.get_json()
    record.allergies = data.get('allergies', record.allergies)
    record.current_medications = data.get('current_medications', record.current_medications)
    record.known_conditions = data.get('known_conditions', record.known_conditions)
    record.immunization_history = data.get('immunization_history', record.immunization_history)
    record.height_cm = data.get('height_cm', record.height_cm)
    record.weight_kg = data.get('weight_kg', record.weight_kg)
    record.blood_group = data.get('blood_group', record.blood_group)
    record.blood_pressure = data.get('blood_pressure', record.blood_pressure)
    record.smoking = data.get('smoking', record.smoking)
    record.drinking = data.get('drinking', record.drinking)
    record.physical_activity = data.get('physical_activity', record.physical_activity)
    record.dietary_habits = data.get('dietary_habits', record.dietary_habits)
    db.session.commit()
    return jsonify({'message': 'Health record updated successfully'}), 200

# --- Delete Health Record Route ---
@app.route('/api/health-records/<int:record_id>', methods=['DELETE'])
@token_required
def delete_health_record(current_user, record_id):
    record = HealthRecord.query.filter_by(id=record_id, user_id=current_user.id).first()
    if not record:
        return jsonify({'message': 'Health record not found'}), 404
    db.session.delete(record)
    db.session.commit()
    return jsonify({'message': 'Health record deleted successfully'}), 200

# --- View Health Records Route ---
@app.route('/api/health-records', methods=['GET'])
@token_required
def view_health_records(current_user):
    records = HealthRecord.query.filter_by(user_id=current_user.id).all()
    records_list = []
    for r in records:
        records_list.append({
            'id': r.id,
            'allergies': r.allergies,
            'current_medications': r.current_medications,
            'known_conditions': r.known_conditions,
            'immunization_history': r.immunization_history,
            'height_cm': r.height_cm,
            'weight_kg': r.weight_kg,
            'blood_group': r.blood_group,
            'blood_pressure': r.blood_pressure,
            'smoking': r.smoking,
            'drinking': r.drinking,
            'physical_activity': r.physical_activity,
            'dietary_habits': r.dietary_habits
        })
    return jsonify({'health_records': records_list}), 200

# --- Add Diagnostic Report ---
@app.route('/api/diagnostic-reports', methods=['POST'])
@token_required
def add_diagnostic_report(current_user):
    data = request.get_json()
    report = DiagnosticReport(
        user_id=current_user.id,
        report_type=data.get('report_type'),
        status=data.get('status'),
        code=data.get('code'),
        effective_date=data.get('effective_date'),
        issued_date=data.get('issued_date'),
        result=json.dumps(data.get('result', {})),
        conclusion=data.get('conclusion', '')
    )
    db.session.add(report)
    db.session.commit()
    return jsonify({'message': 'Diagnostic report added', 'report_id': report.id}), 201

# --- Update Diagnostic Report ---
@app.route('/api/diagnostic-reports/<int:report_id>', methods=['PUT'])
@token_required
def update_diagnostic_report(current_user, report_id):
    report = DiagnosticReport.query.filter_by(id=report_id, user_id=current_user.id).first()
    if not report:
        return jsonify({'message': 'Report not found'}), 404
    data = request.get_json()
    report.report_type = data.get('report_type', report.report_type)
    report.status = data.get('status', report.status)
    report.code = data.get('code', report.code)
    report.effective_date = data.get('effective_date', report.effective_date)
    report.issued_date = data.get('issued_date', report.issued_date)
    report.result = json.dumps(data.get('result', json.loads(report.result)))
    report.conclusion = data.get('conclusion', report.conclusion)
    db.session.commit()
    return jsonify({'message': 'Diagnostic report updated'}), 200

# --- View Diagnostic Reports ---
@app.route('/api/diagnostic-reports', methods=['GET'])
@token_required
def view_diagnostic_reports(current_user):
    reports = DiagnosticReport.query.filter_by(user_id=current_user.id).all()
    reports_list = []
    for r in reports:
        reports_list.append({
            'id': r.id,
            'report_type': r.report_type,
            'status': r.status,
            'code': r.code,
            'effective_date': r.effective_date,
            'issued_date': r.issued_date,
            'result': json.loads(r.result) if r.result else {},
            'conclusion': r.conclusion
        })
    return jsonify({'diagnostic_reports': reports_list}), 200

# --- Delete Diagnostic Report ---
@app.route('/api/diagnostic-reports/<int:report_id>', methods=['DELETE'])
@token_required
def delete_diagnostic_report(current_user, report_id):
    report = DiagnosticReport.query.filter_by(id=report_id, user_id=current_user.id).first()
    if not report:
        return jsonify({'message': 'Report not found'}), 404
    db.session.delete(report)
    db.session.commit()
    return jsonify({'message': 'Diagnostic report deleted'}), 200

# --- Add Medication Request ---
@app.route('/api/medication-requests', methods=['POST'])
@token_required
def add_medication_request(current_user):
    data = request.get_json()
    request_obj = MedicationRequest(
        user_id=current_user.id,
        status=data.get('status'),
        intent=data.get('intent'),
        medication=data.get('medication'),
        authored_on=data.get('authored_on'),
        requester=data.get('requester'),
        dosage_instruction=json.dumps(data.get('dosage_instruction', {})),
        note=data.get('note', '')
    )
    db.session.add(request_obj)
    db.session.commit()
    return jsonify({'message': 'Medication request added', 'request_id': request_obj.id}), 201

# --- Update Medication Request ---
@app.route('/api/medication-requests/<int:request_id>', methods=['PUT'])
@token_required
def update_medication_request(current_user, request_id):
    request_obj = MedicationRequest.query.filter_by(id=request_id, user_id=current_user.id).first()
    if not request_obj:
        return jsonify({'message': 'Medication request not found'}), 404
    data = request.get_json()
    request_obj.status = data.get('status', request_obj.status)
    request_obj.intent = data.get('intent', request_obj.intent)
    request_obj.medication = data.get('medication', request_obj.medication)
    request_obj.authored_on = data.get('authored_on', request_obj.authored_on)
    request_obj.requester = data.get('requester', request_obj.requester)
    request_obj.dosage_instruction = json.dumps(data.get('dosage_instruction', json.loads(request_obj.dosage_instruction)))
    request_obj.note = data.get('note', request_obj.note)
    db.session.commit()
    return jsonify({'message': 'Medication request updated'}), 200

# --- View Medication Requests ---
@app.route('/api/medication-requests', methods=['GET'])
@token_required
def view_medication_requests(current_user):
    requests = MedicationRequest.query.filter_by(user_id=current_user.id).all()
    requests_list = []
    for r in requests:
        requests_list.append({
            'id': r.id,
            'status': r.status,
            'intent': r.intent,
            'medication': r.medication,
            'authored_on': r.authored_on,
            'requester': r.requester,
            'dosage_instruction': json.loads(r.dosage_instruction) if r.dosage_instruction else {},
            'note': r.note
        })
    return jsonify({'medication_requests': requests_list}), 200

# --- Delete Medication Request ---
@app.route('/api/medication-requests/<int:request_id>', methods=['DELETE'])
@token_required
def delete_medication_request(current_user, request_id):
    request_obj = MedicationRequest.query.filter_by(id=request_id, user_id=current_user.id).first()
    if not request_obj:
        return jsonify({'message': 'Medication request not found'}), 404
    db.session.delete(request_obj)
    db.session.commit()
    return jsonify({'message': 'Medication request deleted'}), 200

# --- Upload Health Document Route ---
@app.route('/api/upload-health-document', methods=['POST'])
@token_required
def upload_health_document(current_user):
    title = request.form.get('title')
    document_type = request.form.get('type')
    document_date = request.form.get('date')

    if not title or not document_type or not document_date:
        return jsonify({'error': 'Missing required fields: title, type, date'}), 400

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading'}), 400

    if file and allowed_file(file.filename):
        # Create unique filename with user ID and timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{current_user.id}_{timestamp}_{title.replace(' ', '_')}.{file_extension}"
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        # Store document metadata in database
        health_doc = HealthDocument(
            user_id=current_user.id,
            title=title,
            document_type=document_type,
            document_date=document_date,
            filename=unique_filename,
            file_path=file_path
        )
        db.session.add(health_doc)
        db.session.commit()

        return jsonify({
            'message': 'Health document uploaded successfully',
            'document_id': health_doc.id,
            'filename': unique_filename,
            'title': title,
            'type': document_type,
            'date': document_date
        }), 201
    else:
        return jsonify({'error': f'File type not allowed. Allowed types: {ALLOWED_EXTENSIONS}'}), 400

# --- View Health Documents Route ---
@app.route('/api/health-documents', methods=['GET'])
@token_required
def view_health_documents(current_user):
    documents = HealthDocument.query.filter_by(user_id=current_user.id).all()
    documents_list = []
    for doc in documents:
        documents_list.append({
            'id': doc.id,
            'title': doc.title,
            'document_type': doc.document_type,
            'document_date': doc.document_date,
            'filename': doc.filename,
            'uploaded_at': doc.uploaded_at.isoformat() if doc.uploaded_at else None
        })
    return jsonify({'health_documents': documents_list}), 200

# --- Update Health Document Metadata Route ---
@app.route('/api/health-documents/<int:document_id>', methods=['PUT'])
@token_required
def update_health_document(current_user, document_id):
    document = HealthDocument.query.filter_by(id=document_id, user_id=current_user.id).first()
    if not document:
        return jsonify({'message': 'Document not found'}), 404

    data = request.get_json()
    document.title = data.get('title', document.title)
    document.document_type = data.get('type', document.document_type)
    document.document_date = data.get('date', document.document_date)
    
    db.session.commit()
    return jsonify({'message': 'Document metadata updated successfully'}), 200

# --- Delete Health Document Route ---
@app.route('/api/health-documents/<int:document_id>', methods=['DELETE'])
@token_required
def delete_health_document(current_user, document_id):
    document = HealthDocument.query.filter_by(id=document_id, user_id=current_user.id).first()
    if not document:
        return jsonify({'message': 'Document not found'}), 404

    # Delete physical file
    try:
        if os.path.exists(document.file_path):
            os.remove(document.file_path)
    except Exception as e:
        pass  # Continue even if file deletion fails

    # Delete database record
    db.session.delete(document)
    db.session.commit()
    return jsonify({'message': 'Document deleted successfully'}), 200

# --- Replace/Update Health Document File Route ---
@app.route('/api/health-documents/<int:document_id>/file', methods=['PUT'])
@token_required
def replace_health_document_file(current_user, document_id):
    document = HealthDocument.query.filter_by(id=document_id, user_id=current_user.id).first()
    if not document:
        return jsonify({'message': 'Document not found'}), 404

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading'}), 400

    if file and allowed_file(file.filename):
        # Delete old file
        try:
            if os.path.exists(document.file_path):
                os.remove(document.file_path)
        except Exception:
            pass

        # Create new unique filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"{current_user.id}_{timestamp}_{document.title.replace(' ', '_')}.{file_extension}"
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        # Update database record
        document.filename = unique_filename
        document.file_path = file_path
        document.uploaded_at = datetime.now()
        
        db.session.commit()

        return jsonify({
            'message': 'Document file updated successfully',
            'filename': unique_filename
        }), 200
    else:
        return jsonify({'error': f'File type not allowed. Allowed types: {ALLOWED_EXTENSIONS}'}), 400

# --- Worker Routes ---
@app.route('/api/migrant-registration', methods=['GET'])
@worker_required
def migrant_registration(current_user):
    return jsonify({
        "message": "Migrant Registration page accessible",
        "worker_type": current_user.worker_profile.worker_type
    }), 200

@app.route('/api/patient-record-access', methods=['GET'])
@worker_required
def patient_record_access(current_user):
    return jsonify({
        "message": "Patient Record Access page accessible",
        "worker_type": current_user.worker_profile.worker_type
    }), 200

@app.route('/api/consent-for-full-record', methods=['POST'])
@worker_required
def consent_for_full_record(current_user):
    data = request.get_json()
    patient_id = data.get('patient_id')
    
    if not patient_id:
        return jsonify({'message': 'Patient ID required'}), 400
    
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    # In production, handle consent logic here
    return jsonify({
        "message": "Consent for full record requested",
        "patient_id": patient_id,
        "requested_by": current_user.name,
        "worker_type": current_user.worker_profile.worker_type
    }), 200

@app.route('/api/book-appointment', methods=['POST'])
@worker_required
def book_appointment(current_user):
    data = request.get_json()
    patient_id = data.get('patient_id')
    appointment_date = data.get('appointment_date')
    appointment_type = data.get('appointment_type')
    
    if not all([patient_id, appointment_date, appointment_type]):
        return jsonify({'message': 'Patient ID, date, and appointment type required'}), 400
    
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    # In production, handle appointment booking logic here
    return jsonify({
        "message": "Appointment booking processed",
        "patient_id": patient_id,
        "appointment_date": appointment_date,
        "appointment_type": appointment_type,
        "booked_by": current_user.name,
        "worker_type": current_user.worker_profile.worker_type
    }), 200

# --- Get Patient Records (Worker Access) ---
@app.route('/api/patient/<int:patient_id>/records', methods=['GET'])
@worker_required
def get_patient_records(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    # Get patient's health records
    health_records = HealthRecord.query.filter_by(user_id=patient_id).all()
    diagnostic_reports = DiagnosticReport.query.filter_by(user_id=patient_id).all()
    medication_requests = MedicationRequest.query.filter_by(user_id=patient_id).all()
    
    patient_data = {
        'patient_info': {
            'name': patient.name,
            'phone': patient.phone,
            'dob': patient.dob,
            'gender': patient.gender,
            'place_address': patient.place_address
        },
        'health_records': [{
            'id': r.id,
            'allergies': r.allergies,
            'current_medications': r.current_medications,
            'known_conditions': r.known_conditions,
            'height_cm': r.height_cm,
            'weight_kg': r.weight_kg,
            'blood_group': r.blood_group,
            'blood_pressure': r.blood_pressure
        } for r in health_records],
        'diagnostic_reports': [{
            'id': r.id,
            'report_type': r.report_type,
            'status': r.status,
            'effective_date': r.effective_date,
            'conclusion': r.conclusion
        } for r in diagnostic_reports],
        'medication_requests': [{
            'id': r.id,
            'medication': r.medication,
            'status': r.status,
            'authored_on': r.authored_on,
            'requester': r.requester
        } for r in medication_requests],
        'accessed_by': {
            'worker_name': current_user.name,
            'worker_type': current_user.worker_profile.worker_type,
            'access_time': datetime.now().isoformat()
        }
    }
    
    return jsonify(patient_data), 200

# --- Search Patients (Worker Access) ---
@app.route('/api/search-patients', methods=['GET'])
@worker_required
def search_patients(current_user):
    search_query = request.args.get('q', '')
    search_type = request.args.get('type', 'name')  # 'name', 'phone', 'abha'
    
    if not search_query:
        return jsonify({'message': 'Search query required'}), 400
    
    patients = []
    if search_type == 'name':
        patients = User.query.filter(User.name.ilike(f'%{search_query}%'), User.user_type == 'patient').all()
    elif search_type == 'phone':
        patients = User.query.filter(User.phone.ilike(f'%{search_query}%'), User.user_type == 'patient').all()
    elif search_type == 'abha':
        patients = User.query.filter(User.abha_no.ilike(f'%{search_query}%'), User.user_type == 'patient').all()
    
    patients_list = []
    for patient in patients:
        patients_list.append({
            'id': patient.id,
            'name': patient.name,
            'phone': patient.phone,
            'dob': patient.dob,
            'gender': patient.gender,
            'abha_no': patient.abha_no
        })
    
    return jsonify({
        'patients': patients_list,
        'search_query': search_query,
        'search_type': search_type,
        'searched_by': current_user.name
    }), 200

# --- Community Worker Routes for Patient Health Records ---

# --- Add Health Record for Patient (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/health-records', methods=['POST'])
@worker_required
def add_patient_health_record(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    data = request.get_json()
    record = HealthRecord(
        user_id=patient_id,
        allergies=data.get('allergies', ''),
        current_medications=data.get('current_medications', ''),
        known_conditions=data.get('known_conditions', ''),
        immunization_history=data.get('immunization_history', ''),
        height_cm=data.get('height_cm'),
        weight_kg=data.get('weight_kg'),
        blood_group=data.get('blood_group'),
        blood_pressure=data.get('blood_pressure'),
        smoking=data.get('smoking', 'No'),
        drinking=data.get('drinking', 'No'),
        physical_activity=data.get('physical_activity', ''),
        dietary_habits=data.get('dietary_habits', '')
    )
    db.session.add(record)
    db.session.commit()
    
    return jsonify({
        'message': 'Health record added successfully for patient',
        'record_id': record.id,
        'patient_name': patient.name,
        'added_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 201

# --- Update Patient Health Record (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/health-records/<int:record_id>', methods=['PUT'])
@worker_required
def update_patient_health_record(current_user, patient_id, record_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    # Get the health record for this specific patient
    record = HealthRecord.query.filter_by(id=record_id, user_id=patient_id).first()
    if not record:
        return jsonify({'message': 'Health record not found for this patient'}), 404
    
    data = request.get_json()
    record.allergies = data.get('allergies', record.allergies)
    record.current_medications = data.get('current_medications', record.current_medications)
    record.known_conditions = data.get('known_conditions', record.known_conditions)
    record.immunization_history = data.get('immunization_history', record.immunization_history)
    record.height_cm = data.get('height_cm', record.height_cm)
    record.weight_kg = data.get('weight_kg', record.weight_kg)
    record.blood_group = data.get('blood_group', record.blood_group)
    record.blood_pressure = data.get('blood_pressure', record.blood_pressure)
    record.smoking = data.get('smoking', record.smoking)
    record.drinking = data.get('drinking', record.drinking)
    record.physical_activity = data.get('physical_activity', record.physical_activity)
    record.dietary_habits = data.get('dietary_habits', record.dietary_habits)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Patient health record updated successfully',
        'patient_name': patient.name,
        'updated_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 200

# --- Add Diagnostic Report for Patient (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/diagnostic-reports', methods=['POST'])
@worker_required
def add_patient_diagnostic_report(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    data = request.get_json()
    report = DiagnosticReport(
        user_id=patient_id,
        report_type=data.get('report_type'),
        status=data.get('status'),
        code=data.get('code'),
        effective_date=data.get('effective_date'),
        issued_date=data.get('issued_date'),
        result=json.dumps(data.get('result', {})),
        conclusion=data.get('conclusion', '')
    )
    db.session.add(report)
    db.session.commit()
    
    return jsonify({
        'message': 'Diagnostic report added successfully for patient',
        'report_id': report.id,
        'patient_name': patient.name,
        'added_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 201

# --- Update Patient Diagnostic Report (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/diagnostic-reports/<int:report_id>', methods=['PUT'])
@worker_required
def update_patient_diagnostic_report(current_user, patient_id, report_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    # Get the diagnostic report for this specific patient
    report = DiagnosticReport.query.filter_by(id=report_id, user_id=patient_id).first()
    if not report:
        return jsonify({'message': 'Diagnostic report not found for this patient'}), 404
    
    data = request.get_json()
    report.report_type = data.get('report_type', report.report_type)
    report.status = data.get('status', report.status)
    report.code = data.get('code', report.code)
    report.effective_date = data.get('effective_date', report.effective_date)
    report.issued_date = data.get('issued_date', report.issued_date)
    report.result = json.dumps(data.get('result', json.loads(report.result) if report.result else {}))
    report.conclusion = data.get('conclusion', report.conclusion)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Patient diagnostic report updated successfully',
        'patient_name': patient.name,
        'updated_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 200

# --- Add Medication Request for Patient (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/medication-requests', methods=['POST'])
@worker_required
def add_patient_medication_request(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    data = request.get_json()
    request_obj = MedicationRequest(
        user_id=patient_id,
        status=data.get('status'),
        intent=data.get('intent'),
        medication=data.get('medication'),
        authored_on=data.get('authored_on'),
        requester=current_user.name,  # Set requester as the current worker
        dosage_instruction=json.dumps(data.get('dosage_instruction', {})),
        note=data.get('note', '')
    )
    db.session.add(request_obj)
    db.session.commit()
    
    return jsonify({
        'message': 'Medication request added successfully for patient',
        'request_id': request_obj.id,
        'patient_name': patient.name,
        'added_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 201

# --- Upload Health Document for Patient (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/upload-health-document', methods=['POST'])
@worker_required
def upload_patient_health_document(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    title = request.form.get('title')
    document_type = request.form.get('type')
    document_date = request.form.get('date')

    if not title or not document_type or not document_date:
        return jsonify({'error': 'Missing required fields: title, type, date'}), 400

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected for uploading'}), 400

    if file and allowed_file(file.filename):
        # Create unique filename with patient ID and timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        unique_filename = f"patient_{patient_id}_{timestamp}_{title.replace(' ', '_')}.{file_extension}"
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)

        # Store document metadata in database
        health_doc = HealthDocument(
            user_id=patient_id,  # Document belongs to patient
            title=title,
            document_type=document_type,
            document_date=document_date,
            filename=unique_filename,
            file_path=file_path
        )
        db.session.add(health_doc)
        db.session.commit()

        return jsonify({
            'message': 'Health document uploaded successfully for patient',
            'document_id': health_doc.id,
            'filename': unique_filename,
            'title': title,
            'type': document_type,
            'date': document_date,
            'patient_name': patient.name,
            'uploaded_by': current_user.name,
            'worker_type': current_user.worker_profile.worker_type
        }), 201
    else:
        return jsonify({'error': f'File type not allowed. Allowed types: {ALLOWED_EXTENSIONS}'}), 400

# --- Worker Profile Route ---
@app.route('/api/worker-profile', methods=['GET'])
@token_required
def get_worker_profile(current_user):
    if current_user.user_type != 'worker':
        return jsonify({'message': 'Access denied. Worker account required.'}), 403

    worker = current_user.worker_profile
    if not worker:
        return jsonify({'message': 'Worker profile not found'}), 404

    worker_details = {
        'name': current_user.name,
        'email': current_user.email,
        'phone': current_user.phone,
        'worker_type': worker.worker_type,
        'license_number': worker.license_number,
        'specialization': worker.specialization,
        'hospital_clinic': worker.hospital_clinic,
        'years_experience': worker.years_experience,
        'qualifications': worker.qualifications,
        'is_verified': worker.is_verified,
        'verification_date': worker.verification_date.isoformat() if worker.verification_date else None
    }
    
    return jsonify({
        'message': 'Worker profile fetched successfully',
        'worker_details': worker_details
    }), 200

# --- Register Patient Profile on Behalf (Community Worker) ---
@app.route('/api/patient-register-on-behalf', methods=['POST'])
@worker_required
def register_patient_on_behalf(current_user):
    data = request.get_json()
    
    # Check for required fields
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    dob = data.get('dob')
    gender = data.get('gender')
    phone = data.get('phone')
    place_address = data.get('place_address')
    abha_no = data.get('abha_no')  # Optional ABHA number

    if not all([email, password, name, dob, gender, place_address]):
        return jsonify({'message': 'All registration fields are required'}), 400

    # Check if user already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User with this email already exists'}), 400
    
    if phone and User.query.filter_by(phone=phone).first():
        return jsonify({'message': 'User with this phone number already exists'}), 400
    
    if abha_no and User.query.filter_by(abha_no=abha_no).first():
        return jsonify({'message': 'User with this ABHA number already exists'}), 400

    # Create new patient account
    new_patient = User(
        email=email, 
        name=name,
        phone=phone,
        dob=dob, 
        gender=gender,
        place_address=place_address,
        abha_no=abha_no,
        user_type='patient'
    )
    new_patient.set_password(password)
    
    db.session.add(new_patient)
    db.session.commit()

    return jsonify({
        'message': 'Patient registration successful. Account created on behalf of patient.',
        'patient_id': new_patient.id,
        'patient_name': new_patient.name,
        'registered_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 201

# --- Update Patient Profile on Behalf (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/profile', methods=['PUT'])
@worker_required
def update_patient_profile_on_behalf(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    # This expects the complete, combined JSON object from the React wizard:
    # { "clinical": {..}, "vitals": {..}, "lifestyle": {..} }
    profile_data = request.get_json()

    # Basic check to ensure the data structure looks correct
    if not isinstance(profile_data, dict) or not ('clinical' in profile_data and 'vitals' in profile_data):
        return jsonify({'message': 'Invalid profile data structure'}), 400

    # Convert the Python dictionary into a JSON string and save it to the database
    patient.profile_data = json.dumps(profile_data)
    db.session.commit()

    return jsonify({
        'message': 'Patient health profile updated successfully by worker',
        'patient_id': patient_id,
        'patient_name': patient.name,
        'profile_data': profile_data,
        'updated_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 200

# --- Update Patient Basic Information on Behalf (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/basic-info', methods=['PUT'])
@worker_required
def update_patient_basic_info_on_behalf(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    data = request.get_json()
    
    # Update basic patient information
    patient.name = data.get('name', patient.name)
    patient.phone = data.get('phone', patient.phone)
    patient.dob = data.get('dob', patient.dob)
    patient.gender = data.get('gender', patient.gender)
    patient.place_address = data.get('place_address', patient.place_address)
    
    # Update ABHA number if provided
    new_abha = data.get('abha_no')
    if new_abha and new_abha != patient.abha_no:
        # Check if ABHA number is already taken by another user
        existing_abha = User.query.filter_by(abha_no=new_abha).first()
        if existing_abha and existing_abha.id != patient_id:
            return jsonify({'message': 'ABHA number already registered to another user'}), 400
        patient.abha_no = new_abha
    
    db.session.commit()

    return jsonify({
        'message': 'Patient basic information updated successfully by worker',
        'patient_id': patient_id,
        'patient_name': patient.name,
        'updated_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 200

# --- Get Patient Profile on Behalf (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/profile', methods=['GET'])
@worker_required
def get_patient_profile_on_behalf(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    # Get basic patient details
    basic_details = {
        'id': patient.id,
        'name': patient.name,
        'phone': patient.phone,
        'dob': patient.dob,
        'place_address': patient.place_address,
        'gender': patient.gender,
        'abha_no': patient.abha_no,
        'email': patient.email
    }
    
    # Get health profile data
    try:
        profile_data = json.loads(patient.profile_data) if patient.profile_data != '{}' else {}
    except:
        profile_data = {}
    
    return jsonify({
        'message': 'Patient profile fetched successfully by worker',
        'basic_details': basic_details,
        'profile_data': profile_data,
        'profile_complete': patient.profile_data != '{}',
        'accessed_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 200

# --- Reset Patient Password on Behalf (Community Worker) ---
@app.route('/api/patient/<int:patient_id>/reset-password', methods=['PUT'])
@worker_required
def reset_patient_password_on_behalf(current_user, patient_id):
    # Verify patient exists
    patient = User.query.filter_by(id=patient_id, user_type='patient').first()
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    data = request.get_json()
    new_password = data.get('new_password')
    
    if not new_password or len(new_password) < 6:
        return jsonify({'message': 'New password required (minimum 6 characters)'}), 400
    
    # Set new password
    patient.set_password(new_password)
    db.session.commit()

    return jsonify({
        'message': 'Patient password reset successfully by worker',
        'patient_id': patient_id,
        'patient_name': patient.name,
        'reset_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 200

# --- Bulk Patient Registration (Community Worker) ---
@app.route('/api/bulk-patient-register', methods=['POST'])
@worker_required
def bulk_patient_register(current_user):
    data = request.get_json()
    patients_data = data.get('patients', [])
    
    if not patients_data or not isinstance(patients_data, list):
        return jsonify({'message': 'Patients data array required'}), 400
    
    successful_registrations = []
    failed_registrations = []
    
    for idx, patient_data in enumerate(patients_data):
        try:
            # Check required fields
            email = patient_data.get('email')
            password = patient_data.get('password', 'default123')  # Default password if not provided
            name = patient_data.get('name')
            dob = patient_data.get('dob')
            gender = patient_data.get('gender')
            phone = patient_data.get('phone')
            place_address = patient_data.get('place_address')
            abha_no = patient_data.get('abha_no')

            if not all([email, name, dob, gender, place_address]):
                failed_registrations.append({
                    'index': idx,
                    'data': patient_data,
                    'error': 'Missing required fields'
                })
                continue

            # Check if user already exists
            if User.query.filter_by(email=email).first():
                failed_registrations.append({
                    'index': idx,
                    'data': patient_data,
                    'error': 'Email already exists'
                })
                continue
            
            if phone and User.query.filter_by(phone=phone).first():
                failed_registrations.append({
                    'index': idx,
                    'data': patient_data,
                    'error': 'Phone number already exists'
                })
                continue

            # Create new patient
            new_patient = User(
                email=email, 
                name=name,
                phone=phone,
                dob=dob, 
                gender=gender,
                place_address=place_address,
                abha_no=abha_no,
                user_type='patient'
            )
            new_patient.set_password(password)
            
            db.session.add(new_patient)
            db.session.commit()
            
            successful_registrations.append({
                'patient_id': new_patient.id,
                'name': new_patient.name,
                'email': new_patient.email
            })
            
        except Exception as e:
            failed_registrations.append({
                'index': idx,
                'data': patient_data,
                'error': str(e)
            })

    return jsonify({
        'message': f'Bulk registration completed. {len(successful_registrations)} successful, {len(failed_registrations)} failed.',
        'successful_registrations': successful_registrations,
        'failed_registrations': failed_registrations,
        'registered_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 200

# --- Get Patient Records by Phone/Email (Worker Access) ---
@app.route('/api/patient-records', methods=['GET'])
@worker_required
def get_patient_records_by_identifier(current_user):
    phone = request.args.get('phone')
    email = request.args.get('email')
    
    if not phone and not email:
        return jsonify({'message': 'Phone number or email required'}), 400
    
    # Find patient by phone or email
    patient = None
    if phone:
        patient = User.query.filter_by(phone=phone, user_type='patient').first()
    elif email:
        patient = User.query.filter_by(email=email, user_type='patient').first()
    
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    # Get patient's health records
    health_records = HealthRecord.query.filter_by(user_id=patient.id).all()
    diagnostic_reports = DiagnosticReport.query.filter_by(user_id=patient.id).all()
    medication_requests = MedicationRequest.query.filter_by(user_id=patient.id).all()
    health_documents = HealthDocument.query.filter_by(user_id=patient.id).all()
    
    patient_data = {
        'patient_info': {
            'id': patient.id,
            'name': patient.name,
            'phone': patient.phone,
            'email': patient.email,
            'dob': patient.dob,
            'gender': patient.gender,
            'place_address': patient.place_address,
            'abha_no': patient.abha_no
        },
        'health_records': [{
            'id': r.id,
            'allergies': r.allergies,
            'current_medications': r.current_medications,
            'known_conditions': r.known_conditions,
            'immunization_history': r.immunization_history,
            'height_cm': r.height_cm,
            'weight_kg': r.weight_kg,
            'blood_group': r.blood_group,
            'blood_pressure': r.blood_pressure,
            'smoking': r.smoking,
            'drinking': r.drinking,
            'physical_activity': r.physical_activity,
            'dietary_habits': r.dietary_habits
        } for r in health_records],
        'diagnostic_reports': [{
            'id': r.id,
            'report_type': r.report_type,
            'status': r.status,
            'effective_date': r.effective_date,
            'issued_date': r.issued_date,
            'result': json.loads(r.result) if r.result else {},
            'conclusion': r.conclusion
        } for r in diagnostic_reports],
        'medication_requests': [{
            'id': r.id,
            'medication': r.medication,
            'status': r.status,
            'intent': r.intent,
            'authored_on': r.authored_on,
            'requester': r.requester,
            'dosage_instruction': json.loads(r.dosage_instruction) if r.dosage_instruction else {},
            'note': r.note
        } for r in medication_requests],
        'health_documents': [{
            'id': d.id,
            'title': d.title,
            'document_type': d.document_type,
            'document_date': d.document_date,
            'filename': d.filename,
            'uploaded_at': d.uploaded_at.isoformat() if d.uploaded_at else None
        } for d in health_documents],
        'accessed_by': {
            'worker_name': current_user.name,
            'worker_type': current_user.worker_profile.worker_type,
            'access_time': datetime.now().isoformat()
        }
    }
    
    return jsonify(patient_data), 200

# --- Add Health Record by Phone/Email (Community Worker) ---
@app.route('/api/patient-health-records', methods=['POST'])
@worker_required
def add_patient_health_record_by_identifier(current_user):
    data = request.get_json()
    phone = data.get('phone')
    email = data.get('email')
    
    if not phone and not email:
        return jsonify({'message': 'Phone number or email required'}), 400
    
    # Find patient by phone or email
    patient = None
    if phone:
        patient = User.query.filter_by(phone=phone, user_type='patient').first()
    elif email:
        patient = User.query.filter_by(email=email, user_type='patient').first()
    
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    record = HealthRecord(
        user_id=patient.id,
        allergies=data.get('allergies', ''),
        current_medications=data.get('current_medications', ''),
        known_conditions=data.get('known_conditions', ''),
        immunization_history=data.get('immunization_history', ''),
        height_cm=data.get('height_cm'),
        weight_kg=data.get('weight_kg'),
        blood_group=data.get('blood_group'),
        blood_pressure=data.get('blood_pressure'),
        smoking=data.get('smoking', 'No'),
        drinking=data.get('drinking', 'No'),
        physical_activity=data.get('physical_activity', ''),
        dietary_habits=data.get('dietary_habits', '')
    )
    db.session.add(record)
    db.session.commit()
    
    return jsonify({
        'message': 'Health record added successfully for patient',
        'record_id': record.id,
        'patient_id': patient.id,
        'patient_name': patient.name,
        'added_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 201

# --- Add Diagnostic Report by Phone/Email (Community Worker) ---
@app.route('/api/patient-diagnostic-reports', methods=['POST'])
@worker_required
def add_patient_diagnostic_report_by_identifier(current_user):
    data = request.get_json()
    phone = data.get('phone')
    email = data.get('email')
    
    if not phone and not email:
        return jsonify({'message': 'Phone number or email required'}), 400
    
    # Find patient by phone or email
    patient = None
    if phone:
        patient = User.query.filter_by(phone=phone, user_type='patient').first()
    elif email:
        patient = User.query.filter_by(email=email, user_type='patient').first()
    
    if not patient:
        return jsonify({'message': 'Patient not found'}), 404
    
    report = DiagnosticReport(
        user_id=patient.id,
        report_type=data.get('report_type'),
        status=data.get('status'),
        code=data.get('code'),
        effective_date=data.get('effective_date'),
        issued_date=data.get('issued_date'),
        result=json.dumps(data.get('result', {})),
        conclusion=data.get('conclusion', '')
    )
    db.session.add(report)
    db.session.commit()
    
    return jsonify({
        'message': 'Diagnostic report added successfully for patient',
        'report_id': report.id,
        'patient_id': patient.id,
        'patient_name': patient.name,
        'added_by': current_user.name,
        'worker_type': current_user.worker_profile.worker_type
    }), 201

# --- Add Medication Request by Phone/Email (Community Worker) ---
@app.route('/api/patient-medication-requests', methods=['POST'])
@worker_required
def add_patient_medication_request_by_identifier(current_user):
    data = request.get_jso
