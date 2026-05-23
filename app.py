from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, current_app
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os
from sqlalchemy import text, extract
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
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure Flask session cookie works reliably across requests.
    # Some environments can yield SECRET_KEY as None/empty, which breaks @login_required session persistence.
    if not app.config.get('SECRET_KEY'):
        app.config['SECRET_KEY'] = getattr(config_class, 'SECRET_KEY', None) or 'aviation-sms-erp-dev-secret-key-2024'

    app.secret_key = app.config['SECRET_KEY']
    
    db.init_app(app)
    migrate.init_app(app, db)
    
    with app.app_context():
        db.create_all()
    
    with app.app_context():
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

    # --- ERP / Emergency Drill Models (defined/active in app.py) ---
    # Reuse the existing table mapping from models.py to avoid duplicate-table mapping issues.
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
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                login_log = LoginLog(username=username, ip_address=request.remote_addr)
                db.session.add(login_log)
                db.session.commit()
                flash('Login successful!')
                return redirect(url_for('dashboard'))
            flash('Invalid username or password.')
        return render_template('login.html')

    @app.route('/logout')
    def logout():
        session.pop('user_id', None)
        flash('You have been logged out.')
        return redirect(url_for('login'))

    @app.route('/dashboard')
    @login_required
    def dashboard():
        user = User.query.get(session['user_id'])
        components = Component.query.all()
        risks = RiskAssessment.query.all()
        policies = SafetyPolicy.query.all()
        assurances = SafetyAssurance.query.all()
        promotions = SafetyPromotion.query.all()
        erps = EmergencyResponsePlan.query.all()
        hazards = HazardReport.query.all()
        occurrences = OccurrenceReport.query.all()
        objectives = SafetyObjective.query.all()
        drills = SafetyDrill.query.all()
        return render_template('dashboard.html', user=user, components=components, risks=risks, policies=policies, assurances=assurances, promotions=promotions, erps=erps, hazards=hazards, occurrences=occurrences, objectives=objectives, drills=drills)

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

    return app  # This MUST be the last line of the create_app function

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000, use_reloader=True)

app = create_app()
