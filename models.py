from extensions import db
from datetime import datetime
from enum import Enum as PyEnum

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)  # e.g., 'AMO Manager', 'Safety Officer'

    # Relationships
    components = db.relationship('Component', backref='assigned_user', lazy=True)
    safety_policies = db.relationship('SafetyPolicy', backref='responsible_user', lazy=True)
    risk_assessments = db.relationship('RiskAssessment', backref='assessor', lazy=True)
    safety_assurances = db.relationship('SafetyAssurance', backref='auditor', lazy=True)
    safety_promotions = db.relationship('SafetyPromotion', backref='publisher', lazy=True)

    def __repr__(self):
        return f'<User {self.username}>'

class ComponentStatus(PyEnum):
    ACTIVE = 'active'
    OVERDUE = 'overdue'
    REMOVED = 'removed'

class Component(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    serial_number = db.Column(db.String(50), unique=True, nullable=False)
    part_number = db.Column(db.String(50), nullable=False)
    install_date = db.Column(db.DateTime, nullable=False)
    due_date = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.Enum(ComponentStatus), default=ComponentStatus.ACTIVE)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<Component {self.name} ({self.serial_number})>'

class SafetyPolicyStatus(PyEnum):
    DRAFT = 'draft'
    IMPLEMENTED = 'implemented'
    REVIEWED = 'reviewed'

class SafetyPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    safety_objectives = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    implementation_status = db.Column(db.Enum(SafetyPolicyStatus), default=SafetyPolicyStatus.DRAFT)
    manual_filename = db.Column(db.String(255))
    implementation_date = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<SafetyPolicy {self.safety_objectives}>'

class RiskLevel(PyEnum):
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    EXTREME = 'extreme'

class RiskAssessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hazard_description = db.Column(db.Text, nullable=False)
    probability = db.Column(db.Integer, nullable=False)  # 1-5 scale
    severity = db.Column(db.Enum('A', 'B', 'C', 'D', 'E', name='risk_assessment_severity_enum'), nullable=False)
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.Enum(RiskLevel, name='risk_assessment_risk_level_enum'), nullable=False)
    mitigation_plan = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<RiskAssessment {self.hazard_description[:50]}...>'

class SafetyAssurance(db.Model):
    __tablename__ = 'safety_assurance'

    id = db.Column(db.Integer, primary_key=True)

    audit_date = db.Column(db.DateTime, nullable=True)
    finding_details = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(100), nullable=True)
    next_audit_date = db.Column(db.DateTime, nullable=True)

    audit_plan_filename = db.Column(db.Text, nullable=True)  # Stores original name
    audit_plan_data = db.Column(db.Text, nullable=True)      # Stores the Base64 data string

    audit_scope = db.Column(db.String(255), nullable=True)
    target_month = db.Column(db.String(50), nullable=True)

    department_notified = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f'<SafetyAssurance {self.finding_details or "No findings"}>'

class SafetyPromotion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bulletin_title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    training_records = db.Column(db.Text)
    date_published = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f'<SafetyPromotion {self.bulletin_title}>'

class ERPStatus(PyEnum):
    ACTIVE = 'Active'
    UNDER_REVIEW = 'Under Review'
    NEEDS_DRILL = 'Needs Drill'

class EmergencyResponsePlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    PlanName = db.Column(db.String(100), nullable=False)
    LastDrillDate = db.Column(db.DateTime, nullable=True)
    NextDrillDate = db.Column(db.DateTime, nullable=False)
    Status = db.Column(db.Enum(ERPStatus), default=ERPStatus.ACTIVE)
    Observations = db.Column(db.Text, nullable=True)

    def __repr__(self):
        return f'<EmergencyResponsePlan {self.PlanName}>'


class HazardReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_no = db.Column(db.String(20), unique=True)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    taxonomy_specific = db.Column(db.String(100)) # e.g. ORG. Operational
    unsafe_event = db.Column(db.Text) # e.g. Oil spillage
    inherent_risk_score = db.Column(db.String(5)) # e.g. 4C
    safety_actions = db.Column(db.Text)
    status = db.Column(db.String(20), default='OPEN') # OPEN, CLOSED, MONITORING
    reporter_email = db.Column(db.String(100))

class OccurrenceReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_no = db.Column(db.String(20), unique=True)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)
    reporter_name = db.Column(db.String(100))
    location = db.Column(db.String(100))
    description = db.Column(db.Text)  # Part A: What happened
    personnel_injured = db.Column(db.Text)
    equipment_damaged = db.Column(db.Text)
    immediate_action = db.Column(db.Text)
    # Part B: Investigation (Safety Officer Only)
    severity = db.Column(db.String(1)) # A, B, C, D, E
    probability = db.Column(db.Integer) # 1, 2, 3, 4, 5
    risk_score = db.Column(db.String(5)) # e.g., 3C
    # Part C & D: Closing & Feedback
    corrective_action = db.Column(db.Text)
    residual_risk = db.Column(db.String(5))
    actual_close_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='OPEN') # OPEN, CLOSED, MONITORING
    feedback_given = db.Column(db.Boolean, default=False)
    closure_comment = db.Column(db.Text)

    root_cause = db.Column(db.Text)
    system_alteration = db.Column(db.Text)
    resp_manager = db.Column(db.String(100))
    reporter_feedback = db.Column(db.Text)
    feedback_date = db.Column(db.DateTime, nullable=True)


class SafetyObjective(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_no = db.Column(db.String(100))
    operator_id = db.Column(db.String(100))
    text = db.Column(db.Text)                 

    def __repr__(self):
        return f'<SafetyObjective {self.customer_no}: {self.text[:50]}...>'


class SafetyDrill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    drill_type = db.Column(db.String(100))
    custom_name = db.Column(db.String(100))
    observations = db.Column(db.Text)
    date_conducted = db.Column(db.DateTime, default=datetime.utcnow)


    def __repr__(self):
        return f'<SafetyDrill {self.drill_type or self.custom_name}>'


class EmergencyDrill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    report_ref = db.Column(db.String(50))
    date = db.Column(db.String(50))
    component_type = db.Column(db.String(100), default="N/A")
    time_since_new = db.Column(db.String(50), default="N/A")
    ac_reg = db.Column(db.String(50), default="N/A")
    time_since_oh = db.Column(db.String(50), default="N/A")
    part_no = db.Column(db.String(100), default="N/A")
    client_name = db.Column(db.String(100), default="N/A")
    serial_no = db.Column(db.String(100), default="N/A")
    description = db.Column(db.Text)
    initial_findings = db.Column(db.Text)
    other_info = db.Column(db.Text)
    conclusion = db.Column(db.Text)
    reported_by = db.Column(db.String(100))
    photo_path = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f'<EmergencyDrill {self.report_ref}>'


class LoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100))
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

