from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, current_app
from flask import send_from_directory
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
import sys
import time
from sqlalchemy import text, extract
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from config import Config
from extensions import db, migrate
from models import Component, RiskAssessment, SafetyPolicy, SafetyAssurance, SafetyPromotion, EmergencyResponsePlan, HazardReport, OccurrenceReport, SafetyObjective, SafetyDrill, EmergencyDrill as ModelsEmergencyDrill, User, LoginLog
import pandas as pd
from io import BytesIO
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.units import inch
from datetime import datetime, timedelta, timezone

RISK_MATRIX = {
    '5A': 'Unacceptable', '5B': 'Unacceptable', '5C': 'Unacceptable', '5D': 'Tolerable', '5E': 'Acceptable',
    '4A': 'Unacceptable', '4B': 'Unacceptable', '4C': 'Tolerable', '4D': 'Acceptable', '4E': 'Acceptable',
    '3A': 'Unacceptable', '3B': 'Tolerable', '3C': 'Tolerable', '3D': 'Acceptable', '3E': 'Acceptable',
    '2A': 'Tolerable', '2B': 'Tolerable', '2C': 'Acceptable', '2D': 'Acceptable', '2E': 'Acceptable',
    '1A': 'Acceptable', '1B': 'Acceptable', '1C': 'Acceptable', '1D': 'Acceptable', '1E': 'Acceptable'
}

def create_app(config_class=Config):
    # Redirect instance path to a writable directory on Vercel (read-only filesystem elsewhere)
    if os.environ.get("VERCEL"):
        app = Flask(__name__, instance_path="/tmp")
    else:
        app = Flask(__name__)

    app.config.from_object(config_class)

    # Ensure Flask session cookie works reliably across requests.
    # Some environments can yield SECRET_KEY as None/empty, which breaks @login_required session persistence.
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = getattr(config_class, 'SECRET_KEY', None) or 'aviation-sms-erp-dev-secret-key-2024'

    app.secret_key = app.config['SECRET_KEY']

    # --- Email (Flask-Mail) configuration via environment variables ---
    app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

    mail = Mail(app)

    db.init_app(app)
    migrate.init_app(app, db)
    
    # Only run create_all + default user seeding locally.
    # On Vercel, do not touch the DB during boot to prevent 500s from transient connectivity/auth issues.
    if os.environ.get("VERCEL") is None:
        with app.app_context():
            try:
                db.create_all()
            except Exception as e:
                print(f"db.create_all() skipped/failed during startup: {e}")

        with app.app_context():
            try:
                if User.query.count() == 0:
                    default_user = User(
                        username='Admin',
                        password_hash=generate_password_hash('admin123'),
                        email='admin@aviation-sms.com',
                        role='Safety Manager'
                    )
                    db.session.add(default_user)
                    db.session.commit()
                    print("Default Admin user created")
            except Exception as e:
                print(f"Default user initialization skipped/failed during startup: {e}")

    # --- ERP / Emergency Drill Models (defined/active in app.py) ---
    # Reuse the existing table mapping from models.py to avoid duplicate-table mapping issues.

    # Production safety: verify critical tables/columns on Vercel cold starts.
    # Soft-fail: if sync fails, log the error and allow the server to continue running.
    if os.environ.get("VERCEL"):
        @app.before_request
        def _sync_schema_on_cold_start():
            if app.config.get("_schema_sync_done"):
                return
            app.config["_schema_sync_done"] = True

            try:
                import subprocess
                # Call the script as a separate process to avoid import-time side effects.
                subprocess.run(
                    [sys.executable, os.path.join(os.path.dirname(__file__), "scripts", "sync_all_tables.py")],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except Exception as e:
                app.logger.exception("Schema sync failed on cold start (soft-fail). Error: %s", e)
    class EmergencyDrill(db.Model):
        __table__ = ModelsEmergencyDrill.__table__

    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    def _safe_get_current_user():
        """
        Best-effort user lookup based on session user_id.
        Returns None if session is missing or user cannot be fetched.
        """
        uid = session.get('user_id')
        if not uid:
            return None
        try:
            return User.query.get(uid)
        except Exception:
            return None

    def _safe_get_current_tenant():
        """
        Best-effort tenant lookup:
        - If User has a `tenant_id`, try to load Tenant model if present.
        - Otherwise return None.
        """
        user = _safe_get_current_user()
        if not user:
            return None

        tenant_id = getattr(user, 'tenant_id', None)
        if not tenant_id:
            return None

        # Tenant model may or may not exist in this codebase yet.
        tenant_cls = globals().get('Tenant') or globals().get('Tenants')
        if tenant_cls is None:
            return None

        try:
            return tenant_cls.query.get(tenant_id)
        except Exception:
            return None

    def _safe_module_enabled(module_key: str) -> bool:
        """
        Best-effort module feature flags.
        Defaults to True if tenant or flags are missing, to keep the app resilient.
        Supported module_key values:
          - 'audits' -> track_audits
          - 'risk'   -> track_risk_management
        """
        tenant = _safe_get_current_tenant()
        if tenant is None:
            return True

        if module_key == 'audits':
            return bool(getattr(tenant, 'track_audits', True))
        if module_key == 'risk':
            return bool(getattr(tenant, 'track_risk_management', True))

        # Unknown module: default to True
        return True

    def require_module(module_key: str):
        """
        Lightweight route decorator to guard module pages using best-effort
        tenant subscription flags.

        Uses inject_tenant_features() flags (via _safe_module_enabled()).
        If a module is disabled: flash + redirect to /dashboard.
        """
        def decorator(f):
            @wraps(f)
            def wrapper(*args, **kwargs):
                enabled = _safe_module_enabled(module_key)
                if not enabled:
                    flash('This module is not active for your organization\'s subscription plan.')
                    return redirect(url_for('dashboard'))
                return f(*args, **kwargs)
            return wrapper
        return decorator

    def send_reporter_feedback(hazard_id):
        hazard = HazardReport.query.get_or_404(hazard_id)
        message = f'Your report regarding {hazard.unsafe_event} has been reviewed. Action taken: {hazard.safety_actions or "None"}. Status: {hazard.status}.'
        flash(message)

    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # Retry only the DB lookup during transient serverless connectivity issues.
            attempts = 3
            delays = [0.2, 0.6]  # before retry 1 and retry 2 respectively
            last_err = None

            for attempt in range(attempts):
                try:
                    user = User.query.filter_by(username=username).first()
                    break
                except SQLAlchemyError as e:
                    # Prevent session pollution on transient failures.
                    last_err = e
                    db.session.rollback()
                    user = None
                    if attempt < attempts - 1:
                        time.sleep(delays[attempt])
                    continue

            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                login_log = LoginLog(username=username, ip_address=request.remote_addr)
                db.session.add(login_log)
                db.session.commit()
                flash('Login successful!')
                return redirect(url_for('dashboard'))

            # Do not leak connection/host details to the user.
            if last_err is not None:
                flash('Temporary database connectivity issue—please try again.')
            else:
                flash('Invalid username or password.')

        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        flash('You have been logged out.')
        return redirect(url_for('login'))

    @app.route('/favicon.ico')
    def favicon_ico():
        return send_from_directory('static', 'favicon.ico', mimetype='image/x-icon')

    @app.route('/favicon.png')
    def favicon_png():
        return send_from_directory('static', 'favicon.png', mimetype='image/png')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        user = User.query.get(session['user_id'])

        # Multi-tenant isolation (best-effort):
        # If we can derive a tenant_id from the logged-in user and SafetyAssurance supports tenant_id,
        # filter tenant-specific queries. For other models, we keep existing behavior unless
        # their tenant filtering is explicitly supported in the codebase.
        tenant_id = getattr(user, 'tenant_id', None) if user is not None else None

        components = Component.query.all()
        risks = RiskAssessment.query.all()
        policies = SafetyPolicy.query.all()
        promotions = SafetyPromotion.query.all()
        erps = EmergencyResponsePlan.query.all()
        hazards = HazardReport.query.all()
        occurrences = OccurrenceReport.query.all()
        objectives = SafetyObjective.query.all()
        drills = SafetyDrill.query.all()

        if tenant_id is not None and hasattr(SafetyAssurance, 'tenant_id'):
            assurances = SafetyAssurance.query.filter_by(tenant_id=tenant_id).all()
        else:
            assurances = SafetyAssurance.query.all()

        return render_template(
            'dashboard.html',
            user=user,
            components=components,
            risks=risks,
            policies=policies,
            assurances=assurances,
            promotions=promotions,
            erps=erps,
            hazards=hazards,
            occurrences=occurrences,
            objectives=objectives,
            drills=drills
        )

    @app.route('/export/excel')
    def export_excel():
        components = Component.query.all()
        risks = RiskAssessment.query.all()
        components_df = pd.DataFrame([{'ID': c.id, 'Name': c.name, 'Serial Number': c.serial_number, 'Part Number': c.part_number, 'Install Date': c.install_date, 'Due Date': c.due_date, 'Status': c.status.value if c.status else None} for c in components])
        risks_df = pd.DataFrame([{'ID': r.id, 'Hazard Description': r.hazard_description, 'Probability': r.probability, 'Severity': r.severity, 'Risk Level': r.risk_level.value if r.risk_level else None, 'Mitigation Plan': r.mitigation_plan} for r in risks])
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            components_df.to_excel(writer, sheet_name='Components', index=False)
            risks_df.to_excel(writer, sheet_name='Risk Assessments', index=False)
        output.seek(0)
        return send_file(output, download_name='aviation_sms_exports.xlsx', as_attachment=True)

    @app.route('/export/pdf')
    def export_pdf():
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        p.setFont("Helvetica", 12)
        p.drawString(100, 750, "Aviation SMS Risk Assessment Report")
        y = 700
        risks = RiskAssessment.query.all()
        for r in risks:
            if y < 100:
                p.showPage()
                p.setFont("Helvetica", 12)
                y = 750
            p.drawString(100, y, f"ID: {r.id} - {r.hazard_description[:50]}")
            y -= 20
        p.save()
        buffer.seek(0)
        return send_file(buffer, download_name='risk_report.pdf', as_attachment=True)

    @app.route('/export/erp/pdf')
    def export_erp_pdf():
        buffer = BytesIO()
        p = canvas.Canvas(buffer, pagesize=A4)
        p.setFont("Helvetica", 12)
        p.drawString(100, 800, "Emergency Response Plans")
        y = 750
        erps = EmergencyResponsePlan.query.all()
        for erp in erps:
            if y < 100:
                p.showPage()
                p.setFont("Helvetica", 12)
                y = 800
            p.drawString(100, y, f"Plan: {erp.plan_name}")
            y -= 20
        p.save()
        buffer.seek(0)
        return send_file(buffer, download_name='erp_report.pdf', as_attachment=True)

    @app.route('/export/risk/excel')
    def export_risk_excel():
        risks = RiskAssessment.query.all()
        risk_data = []
        for r in risks:
            row = {'id': r.id, 'hazard': r.hazard_description, 'probability': r.probability, 'severity': r.severity, 'risk': r.risk_level.value if r.risk_level else '', 'mitigation': r.mitigation_plan}
            risk_data.append(row)
        df = pd.DataFrame(risk_data)
        output = BytesIO()
        df.to_excel(output, index=False, engine='openpyxl')
        output.seek(0)
        return send_file(output, download_name='risk_assessment.xlsx', as_attachment=True)

    @app.route('/erp/update', methods=['GET', 'POST'])
    @login_required
    def update_erp():
        erp = EmergencyResponsePlan.query.get_or_404(request.args.get('id'))
        if request.method == 'POST':
            erp.plan_name = request.form['plan_name']
            erp.description = request.form['description']
            erp.coordinator = request.form['coordinator']
            erp.phone = request.form['phone']
            erp.last_reviewed = datetime.utcnow()
            db.session.commit()
            flash('Emergency Response Plan updated!')
            return redirect(url_for('dashboard'))
        return render_template('erp_update.html', erp=erp)

    @app.route('/erp/new', methods=['GET', 'POST'])
    @login_required
    def new_erp():
        if request.method == 'POST':
            erp_image = request.files.get('erp_image')

            image_rel_path = None
            if erp_image and erp_image.filename != '':
                base_dir = os.path.join('static', 'uploads', 'erp')
                os.makedirs(base_dir, exist_ok=True)

                filename = secure_filename(erp_image.filename)
                # Basic uniqueness to avoid collisions
                name_root, ext = os.path.splitext(filename)
                filename = f"{name_root}_{int(datetime.utcnow().timestamp())}{ext}"

                save_path = os.path.join(base_dir, filename)
                erp_image.save(save_path)

                image_rel_path = os.path.join('uploads', 'erp', filename).replace('\\', '/')

            new_plan = EmergencyResponsePlan(
                plan_name=request.form.get('plan_name'),
                description=request.form.get('description'),
                coordinator=request.form.get('coordinator'),
                phone=request.form.get('phone')
            )

            # If the model supports an image path column, store it
            # (best-effort; won’t break if the column doesn’t exist)
            if image_rel_path is not None and hasattr(new_plan, 'erp_image'):
                setattr(new_plan, 'erp_image', image_rel_path)

            db.session.add(new_plan)
            db.session.commit()
            flash('Emergency Response Plan created!')
            return redirect(url_for('dashboard'))
        return render_template('log_erp.html')

    @app.route('/erp/list', methods=['GET', 'POST'])
    @login_required
    def list_erp():
        if request.method == 'POST':
            # Handle photo file upload if provided
            photo_file = request.files.get('erp_image')
            filename = None
            if photo_file and photo_file.filename != '':
                import os
                upload_dir = os.path.join('static', 'uploads')
                os.makedirs(upload_dir, exist_ok=True)
                filename = photo_file.filename
                photo_file.save(os.path.join(upload_dir, filename))

            # Create Drill entry matching AISL-QD-022 format
            new_drill = EmergencyDrill(
                report_ref=request.form.get('report_ref'),
                date=request.form.get('date'),
                component_type=request.form.get('component_type') or "N/A",
                time_since_new=request.form.get('time_since_new') or "N/A",
                ac_reg=request.form.get('ac_reg') or "N/A",
                time_since_oh=request.form.get('time_since_oh') or "N/A",
                part_no=request.form.get('part_no') or "N/A",
                client_name=request.form.get('client_name') or "N/A",
                serial_no=request.form.get('serial_no') or "N/A",
                description=request.form.get('description'),
                initial_findings=request.form.get('initial_findings'),
                other_info=request.form.get('other_info'),
                conclusion=request.form.get('conclusion'),
                reported_by=request.form.get('reported_by'),
                photo_path=filename
            )
            db.session.add(new_drill)
            db.session.commit()
            return redirect(url_for('list_erp'))

        drills = EmergencyDrill.query.all()
        return render_template('list_erp.html', drills=drills)

    @app.route('/erp/delete/<int:id>', methods=['POST', 'GET'])
    @login_required
    def delete_erp_entry(id):
        entry = EmergencyDrill.query.get_or_404(id)
        db.session.delete(entry)
        db.session.commit()
        return redirect(url_for('list_erp'))

    @app.route('/erp/edit/<int:id>', methods=['GET', 'POST'])
    @login_required
    def edit_erp_entry(id):
        entry = EmergencyDrill.query.get_or_404(id)
        if request.method == 'POST':
            entry.report_ref = request.form.get('report_ref')
            entry.date = request.form.get('date')
            entry.description = request.form.get('description')
            entry.initial_findings = request.form.get('initial_findings')
            entry.conclusion = request.form.get('conclusion')
            entry.reported_by = request.form.get('reported_by')
            db.session.commit()
            return redirect(url_for('list_erp'))
        return render_template('edit_drill.html', drill=entry)

    @app.route('/risk/new', methods=['GET', 'POST'])
    @login_required
    def new_risk():
        if request.method == 'POST':
            probability = int(request.form['probability'])
            severity = int(request.form['severity'])
            risk_key = f"{severity}{probability}"
            risk_level = RISK_MATRIX.get(risk_key, 'Unknown')
            new_risk = RiskAssessment(
                hazard_description=request.form['hazard_description'],
                probability=probability,
                severity=severity,
                risk_level=risk_level,
                mitigation_plan=request.form['mitigation_plan']
            )
            db.session.add(new_risk)
            db.session.commit()
            flash('Risk assessment created!')
            return redirect(url_for('dashboard'))
        return render_template('new_risk.html')

    @app.route('/risk/assessment')
    @login_required
    def risk_assessment():
        risks = RiskAssessment.query.all()
        return render_template('risk_assessment.html', risks=risks)

    @app.route('/risk/assessment/new')
    @login_required
    def risk_assessment_new():
        risks = RiskAssessment.query.all()
        return render_template('risk_assessment_new.html', risks=risks)

    @app.route('/hazard/report', methods=['GET', 'POST'])
    @login_required
    def report_hazard():
        if request.method == 'POST':
            hazard = HazardReport(
                unsafe_event=request.form['unsafe_event'],
                location=request.form['location'],
                description=request.form['description'],
                reported_by=session.get('user_id'),
                status='Reported'
            )
            db.session.add(hazard)
            db.session.commit()
            flash('Hazard reported successfully!')
            return redirect(url_for('dashboard'))
        return render_template('report_hazard.html')

    @app.route('/hazard/assess/<int:hazard_id>', methods=['GET', 'POST'])
    @login_required
    def assess_hazard(hazard_id):
        hazard = HazardReport.query.get_or_404(hazard_id)
        if request.method == 'POST':
            hazard.status = request.form['status']
            hazard.safety_actions = request.form['safety_actions']
            hazard.assessed_by = session.get('user_id')
            db.session.commit()
            send_reporter_feedback(hazard_id)
            return redirect(url_for('dashboard'))
        return render_template('assess_hazard.html', hazard=hazard)

    @app.route('/hazard/report/list')
    @login_required
    def report_hazard_list():
        hazards = HazardReport.query.all()
        return render_template('report_hazard.html', hazards=hazards)

    @app.route('/hazard/close/<int:hazard_id>', methods=['GET', 'POST'])
    @login_required
    def close_hazard(hazard_id):
        hazard = HazardReport.query.get_or_404(hazard_id)
        if request.method == 'POST':
            hazard.status = 'Closed'
            hazard.closure_date = datetime.utcnow()
            hazard.closure_comment = request.form.get('closure_comment')
            db.session.commit()
            send_reporter_feedback(hazard_id)
            return redirect(url_for('dashboard'))
        return render_template('close_hazard.html', hazard=hazard)

    @app.route('/occurrence/report', methods=['GET', 'POST'])
    @login_required
    def report_occurrence():
        if request.method == 'POST':
            occ = OccurrenceReport(
                occurrence_type=request.form['occurrence_type'],
                date_time=datetime.strptime(request.form['date_time'], '%Y-%m-%dT%H:%M'),
                location=request.form['location'],
                flight_number=request.form['flight_number'],
                description=request.form['description'],
                reported_by=session.get('user_id'),
                status='Reported'
            )
            db.session.add(occ)
            db.session.commit()
            flash('Occurrence reported!')
            return redirect(url_for('dashboard'))
        return render_template('report_occurrence.html')

    @app.route('/occurrence/form')
    @login_required
    def occurrence_form():
        return render_template('occurrence_form.html')

    @app.route('/inventory')
    @login_required
    def inventory():
        components = Component.query.all()
        return render_template('inventory.html', components=components)

    @app.route('/drills', methods=['GET', 'POST'])
    @login_required
    def manage_drills():
        if request.method == 'POST':
            new_drill = EmergencyDrill(
                report_ref=request.form.get('report_ref'),
                date=request.form.get('date'),
                component_type=request.form.get('component_type'),
                time_since_new=request.form.get('time_since_new'),
                ac_reg=request.form.get('ac_reg'),
                time_since_oh=request.form.get('time_since_oh'),
                part_no=request.form.get('part_no'),
                client_name=request.form.get('client_name'),
                serial_no=request.form.get('serial_no'),
                description=request.form.get('description'),
                initial_findings=request.form.get('initial_findings'),
                other_info=request.form.get('other_info'),
                conclusion=request.form.get('conclusion'),
                reported_by=request.form.get('reported_by')
            )
            db.session.add(new_drill)
            db.session.commit()
            flash('Fire Drill report saved successfully!')
            return redirect(url_for('manage_drills'))

        drills = EmergencyDrill.query.all()
        return render_template('drills.html', drills=drills)

    @app.route('/drills/add', methods=['GET', 'POST'])
    @login_required
    def add_drill():
        if request.method == 'POST':
            drill = SafetyDrill(
                drill_type=request.form['drill_type'],
                description=request.form['description'],
                location=request.form['location'],
                scheduled_date=datetime.strptime(request.form['scheduled_date'], '%Y-%m-%dT%H:%M'),
                conducted_by=session.get('user_id')
            )
            db.session.add(drill)
            db.session.commit()
            flash('Drill scheduled!')
            return redirect(url_for('drills'))
        return render_template('edit_drill.html')

    @app.route('/drills/edit/<int:drill_id>', methods=['GET', 'POST'])
    @login_required
    def edit_drill(drill_id):
        drill = SafetyDrill.query.get_or_404(drill_id)
        if request.method == 'POST':
            drill.drill_type = request.form['drill_type']
            drill.description = request.form['description']
            drill.location = request.form['location']
            drill.scheduled_date = datetime.strptime(request.form['scheduled_date'], '%Y-%m-%dT%H:%M')
            drill.completed = 'completed' in request.form
            db.session.commit()
            flash('Drill updated!')
            return redirect(url_for('drills'))
        return render_template('edit_drill.html', drill=drill)

    @app.route('/manage_objectives', methods=['GET', 'POST'])
    @login_required
    def manage_objectives():
        if request.method == 'POST':
            new_obj = SafetyObjective(
                customer_no=request.form.get('customer_no'),
                operator_id=request.form.get('operator_id'),
                text=request.form.get('objective_text')
            )
            db.session.add(new_obj)
            db.session.commit()
            flash('Safety Objective added successfully!')
            return redirect(url_for('manage_objectives'))
        
        objectives = SafetyObjective.query.all()
        return render_template('manage_objectives.html', objectives=objectives)

    @app.route('/delete_objective/<int:id>')
    @login_required
    def delete_objective(id):
        objective = SafetyObjective.query.get_or_404(id)
        db.session.delete(objective)
        db.session.commit()
        flash('Objective deleted.')
        return redirect(url_for('manage_objectives'))

    @app.route('/safety/assurance', methods=['GET'])
    @login_required
    @require_module('audits')
    def safety_assurance():
        user_id = session.get('user_id')

        tenant_id = None
        user = _safe_get_current_user()
        if user is not None:
            tenant_id = getattr(user, 'tenant_id', None)

        base_q = SafetyAssurance.query

        # Absolute isolation safeguard (best-effort):
        # Always filter by user_id if present; additionally filter by tenant_id if the column exists.
        if tenant_id is not None and hasattr(SafetyAssurance, 'tenant_id'):
            assurances = (
                base_q
                .filter_by(tenant_id=tenant_id, user_id=user_id)
                .order_by(SafetyAssurance.audit_date.desc())
                .all()
            )
        else:
            assurances = (
                base_q
                .filter_by(user_id=user_id)
                .order_by(SafetyAssurance.audit_date.desc())
                .all()
            )

        latest = assurances[0] if assurances else None
        return render_template('safety_assurance.html', latest=latest, assurances=assurances)

    @app.route('/safety/download-plan/<int:record_id>')
    @login_required
    def download_plan(record_id: int):
        import base64

        record = SafetyAssurance.query.get_or_404(record_id)

        # Optional: enforce user-level access (keeps consistent with existing page filtering).
        user_id = session.get('user_id')
        if getattr(record, 'user_id', None) is not None and record.user_id != user_id:
            flash('You do not have access to this plan.')
            return redirect(url_for('safety_assurance'))

        if not record.audit_plan_data:
            flash('No audit plan data found for this record.')
            return redirect(url_for('safety_assurance'))

        raw_bytes = base64.b64decode(record.audit_plan_data)

        return send_file(
            BytesIO(raw_bytes),
            as_attachment=True,
            download_name=record.audit_plan_filename or f'safety_assurance_plan_{record.id}'
        )

    @app.route('/safety/assurance', methods=['POST'])
    @login_required
    @require_module('audits')
    def safety_assurance_post():
        user_id = session.get('user_id')
        if not user_id:
            flash('Please log in to access this page.')
            return redirect(url_for('login'))

        # File helpers
        file = request.files.get('audit_plan')
        checklist_file = request.files.get('audit_checklist')

        import base64
        from datetime import datetime

        audit_date_in = request.form.get('audit_date')
        next_audit_date_in = request.form.get('next_audit_date')

        # 1. DATE FIX & DATABASE SAVE FIRST (exact structure requested)
        try:
            parsed_audit_date = datetime.strptime(audit_date_in.split('T')[0], '%Y-%m-%d').date() if audit_date_in else None
            parsed_next_date = datetime.strptime(next_audit_date_in.split('T')[0], '%Y-%m-%d').date() if next_audit_date_in else None
        except Exception:
            parsed_audit_date = datetime.utcnow().date()
            parsed_next_date = None

        # Set SQLAlchemy-searchable variables
        audit_date = parsed_audit_date
        next_audit_date = parsed_next_date

        status = request.form.get('status') or 'Open'
        finding_details = request.form.get('finding_details')
        auditee_email = request.form.get('auditee_email')
        notification_body = request.form.get('notification_body')
        audit_scope = request.form.get('audit_scope')
        target_month = request.form.get('target_month')
        dept_notified = True if request.form.get('department_notified') else False

        audit_plan_filename = None
        audit_plan_data = None
        if file and file.filename != '':
            allowed_ext = {'.pdf', '.docx', '.xlsx'}
            safe_name = secure_filename(file.filename)
            ext = os.path.splitext(safe_name)[1].lower()
            if ext not in allowed_ext:
                flash('Invalid file type. Allowed: PDF, DOCX, XLSX.')
                return redirect(url_for('safety_assurance'))

            file_bytes = file.read()
            file.seek(0)
            audit_plan_filename = file.filename
            audit_plan_data = base64.b64encode(file_bytes).decode('utf-8')

        checklist_name = None
        checklist_data = None
        if checklist_file and checklist_file.filename:
            checklist_name = checklist_file.filename
            checklist_data = checklist_file.read()
            checklist_file.seek(0)

        assurance = SafetyAssurance.query.filter_by(user_id=user_id, audit_date=audit_date).first()
        if assurance is None:
            assurance = SafetyAssurance(
                audit_date=audit_date,
                finding_details=finding_details,
                status=status,
                next_audit_date=next_audit_date,
                audit_scope=audit_scope,
                target_month=target_month,
                department_notified=dept_notified,
                auditee_email=auditee_email,
                notification_body=notification_body,
                checklist_name=checklist_name,
                checklist_data=checklist_data,
                user_id=user_id,
            )

        # Assign fields, including tenant-safe assignment, then commit BEFORE email code
        assurance.audit_date = parsed_audit_date
        assurance.next_audit_date = parsed_next_date

        # Safe Tenant Context Assignment (never throws AttributeError)
        user_record = User.query.get(session.get('user_id')) if session.get('user_id') else None
        if user_record and hasattr(user_record, 'tenant_id') and hasattr(assurance, 'tenant_id'):
            assurance.tenant_id = user_record.tenant_id

        assurance.finding_details = finding_details
        assurance.status = status
        assurance.audit_scope = audit_scope
        assurance.target_month = target_month
        assurance.department_notified = dept_notified
        assurance.auditee_email = auditee_email
        assurance.notification_body = notification_body

        if checklist_name is not None and checklist_data is not None:
            assurance.checklist_name = checklist_name
            assurance.checklist_data = checklist_data

        if audit_plan_filename is not None and audit_plan_data is not None:
            assurance.audit_plan_filename = audit_plan_filename
            assurance.audit_plan_data = audit_plan_data

        # 2. DATE FIX & DATABASE SAVE FIRST (commit immediately BEFORE executing the email code)
        try:
            db.session.add(assurance)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"DATABASE ERROR: {str(e)}")
            current_app.logger.error(str(e))
            flash('Database error while saving Safety Assurance record.')
            return redirect(url_for('safety_assurance'))

        # 3. HTML EMAIL LAYOUT WITH INTERACTIVE ACTIONS + 4. TOTAL ISOLATION SAFEGUARD
        try:
            if auditee_email:
                msg = Message(
                    subject=f"New Safety Audit Notification: {request.form.get('audit_scope', 'Schedules')}",
                    recipients=[auditee_email],
                )

                audit_id_str = str(assurance.id) if assurance.id else "PENDING"
                accept_url = f"https://aviation-sms-erp.vercel.app/safety/assurance/respond?action=accept&audit_id={audit_id_str}"
                reschedule_url = f"https://aviation-sms-erp.vercel.app/safety/assurance/respond?action=reschedule&audit_id={audit_id_str}"

                msg.html = f"""
<html>
<body style="font-family: Arial, sans-serif; background-color: #1a1a1a; color: #ffffff; margin: 0; padding: 20px;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #2b2b2b; border: 1px solid #444; padding: 15px; text-align: center;">
        <span style="font-size: 18px; font-weight: bold; color: #ffffff; letter-spacing: 1px;">INTERNAL AUDIT NOTIFICATION - AISL-SD-001</span><br>
        <span style="font-size: 13px; color: #b3b3b3;">Aero Instrument Service Limited (AISL) | Workshop ID: K/AMO/L/016</span>
    </div>
    
    <div style="max-width: 600px; margin: 0 auto; background-color: #242424; border-left: 1px solid #444; border-right: 1px solid #444; border-bottom: 1px solid #444; padding: 20px; color: #dddddd;">
        <h4 style="color: #ffc107; border-bottom: 1px solid #444; padding-bottom: 5px; margin-top: 0;">AUDIT DETAILS</h4>
        <table style="width: 100%; color: #dddddd; font-size: 14px; margin-bottom: 20px;">
            <tr><td style="padding: 5px; width: 30%; font-weight: bold; color: #aaaaaa;">Audit Area:</td><td style="padding: 5px;">{assurance.audit_scope if assurance.audit_scope else 'Maintenance Facilities'}</td></tr>
            <tr><td style="padding: 5px; font-weight: bold; color: #aaaaaa;">Auditor:</td><td style="padding: 5px;">Head of Safety Office</td></tr>
            <tr><td style="padding: 5px; font-weight: bold; color: #aaaaaa;">Schedule:</td><td style="padding: 5px;">{assurance.target_month if assurance.target_month else 'Scheduled Month'}</td></tr>
        </table>
        
        <p style="font-size: 14px; line-height: 1.5;">
            <strong>Preparation Notice:</strong><br>
            In accordance with <strong>AISL-005 (SMM)</strong>, please be advised of the scheduled audit. Preparation should follow the <strong>AISL-SD-002C</strong> checklist.
        </p>
        
        <div style="background-color: #2d3748; border: 1px solid #4a5568; padding: 15px; text-align: center; margin-top: 25px; border-radius: 6px;">
            <span style="font-size: 15px; font-weight: bold; color: #63b3ed;">📋 AUDIT SCHEDULE ACKNOWLEDGEMENT</span>
            <p style="font-size: 13px; color: #cbd5e0; margin: 10px 0 15px 0;">Please confirm your acceptance of this audit schedule or request rescheduling:</p>
            <a href="{accept_url}" style="background-color: #0056b3; color: white; padding: 10px 22px; text-decoration: none; font-weight: bold; border-radius: 4px; margin-right: 10px; display: inline-block; font-size: 13px;">✓ Accept Audit Schedule</a>
            <a href="{reschedule_url}" style="background-color: #dc3545; color: white; padding: 10px 22px; text-decoration: none; font-weight: bold; border-radius: 4px; display: inline-block; font-size: 13px;">✗ Request Reschedule</a>
            <br><span style="font-size: 11px; color: #a0aec0; display: inline-block; margin-top: 12px;">Audit ID: {audit_id_str}</span>
        </div>
    </div>
</body>
</html>
"""

                msg.body = (
                    f"{notification_body or 'Please review the audit schedule.'}\n\n"
                    f"Audit ID: {audit_id_str}\n"
                    f"Accept: {accept_url}\n"
                    f"Reschedule: {reschedule_url}\n"
                )

                # Best-effort attachments (will not break redirect)
                audit_plan_file = request.files.get('audit_plan')
                audit_checklist_file = request.files.get('audit_checklist')

                if audit_plan_file and audit_plan_file.filename != '':
                    audit_plan_file.seek(0)
                    msg.attach(
                        filename=audit_plan_file.filename,
                        content_type=getattr(audit_plan_file, 'content_type', None),
                        data=audit_plan_file.read(),
                    )
                    audit_plan_file.seek(0)

                if audit_checklist_file and audit_checklist_file.filename != '':
                    audit_checklist_file.seek(0)
                    msg.attach(
                        filename=audit_checklist_file.filename,
                        content_type=getattr(audit_checklist_file, 'content_type', None),
                        data=audit_checklist_file.read(),
                    )
                    audit_checklist_file.seek(0)

                mail.send(msg)

        except Exception as mail_err:
            current_app.logger.error(f"Mail dispatch error: {mail_err}")
            flash('Safety Assurance record saved successfully.')
            return redirect(url_for('safety_assurance'))

        flash('Safety Assurance record saved successfully.')
        return redirect(url_for('safety_assurance'))

    @app.context_processor
    def inject_tenant_features():
        """
        Template context helper for feature flags.
        Defensive lookup:
          - Uses session.get('user_id') -> User record -> linked tenant fields (if present)
          - Defaults to True when user/tenant/attributes are missing to keep app resilient.
        """
        tenant_features = {
            'track_audits': True,
            'track_risk_management': True,
        }

        user = _safe_get_current_user()
        if user is None:
            return tenant_features

        # Tenant model may not exist yet; attempt best-effort loading via globals.
        tenant_id = getattr(user, 'tenant_id', None)
        if not tenant_id:
            return tenant_features

        tenant_cls = globals().get('Tenant') or globals().get('Tenants')
        if tenant_cls is None:
            return tenant_features

        try:
            tenant = tenant_cls.query.get(tenant_id)
        except Exception:
            tenant = None

        if tenant is None:
            return tenant_features

        tenant_features['track_audits'] = bool(getattr(tenant, 'track_audits', True))
        tenant_features['track_risk_management'] = bool(getattr(tenant, 'track_risk_management', True))
        return tenant_features

    return app  # This MUST be the last line of the create_app function

if __name__ == "__main__":
    app = create_app()

    # Secure startup: never enable Flask debug/reloader on Vercel by default.
    debug_env = os.environ.get("DEBUG")
    debug = (debug_env is not None and debug_env.strip().lower() in ("1", "true", "yes", "y", "on"))
    if os.environ.get("VERCEL"):
        debug = False

    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=debug, port=port, use_reloader=debug)
