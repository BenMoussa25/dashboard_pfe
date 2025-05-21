from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

class AnalyticsLog(db.Model):
    __tablename__ = 'analytics_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = db.Column(db.String(36), db.ForeignKey('incidents.id'), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # 'status_change', 'assignment', etc.
    analyst_id = db.Column(db.String(36), db.ForeignKey('users.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    incident = db.relationship('Incident', back_populates='analytics_logs')
    analyst = db.relationship('User', back_populates='analytics_logs')
    
    def __repr__(self):
        return f'<AnalyticsLog {self.id}>'

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin', 'manager', 'analyst'
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    assigned_incidents = db.relationship('Incident', back_populates='assigned_user', lazy=True)
    analytics_logs = db.relationship('AnalyticsLog', back_populates='analyst', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Incident(db.Model):
    __tablename__ = 'incidents'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    source_ip = db.Column(db.String(45), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)  # 'Critical', 'High', 'Medium', 'Low'
    ml_model_name = db.Column(db.String(50), nullable=False)
    confidence_score = db.Column(db.Float)
    assigned_to = db.Column(db.String(36), db.ForeignKey('users.id'))
    assigned_user = db.relationship('User', back_populates='assigned_incidents') 
    status = db.Column(db.String(20), default='New')
    llm_summary = db.Column(db.Text)
    description = db.Column(db.Text)
    monitoring_system = db.Column(db.String(50))  # Which system detected this
    raw_detection_data = db.Column(db.JSON)  # Original detection data from the system
    is_auto_resolved = db.Column(db.Boolean, default=False)
    resolution_method = db.Column(db.String(50))  # 'manual', 'auto', 'system'
    
    # Relationships
    enrichments = db.relationship('Enrichment', backref='incident', lazy=True, cascade='all, delete-orphan')
    analytics_logs = db.relationship('AnalyticsLog', back_populates='incident', lazy=True)
    
    def __repr__(self):
        return f'<Incident {self.id}>'

class Enrichment(db.Model):
    __tablename__ = 'enrichments'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_id = db.Column(db.String(36), db.ForeignKey('incidents.id'), nullable=False)
    source = db.Column(db.String(50), nullable=False)  # 'VirusTotal', 'OpenCTI', etc.
    data = db.Column(db.JSON)  # Using JSON for flexible data storage
    
    def __repr__(self):
        return f'<Enrichment {self.id} for Incident {self.incident_id}>'

class MLModel(db.Model):
    __tablename__ = 'ml_models'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(50), unique=True, nullable=False)
    purpose = db.Column(db.String(100), nullable=False)
    model_type = db.Column(db.String(50), nullable=False)  # 'Anomaly Detection', 'Phishing Detection', etc.
    endpoint = db.Column(db.String(200), nullable=False)
    api_key = db.Column(db.String(100))
    version = db.Column(db.String(20))
    is_active = db.Column(db.Boolean, default=True)
    last_active = db.Column(db.DateTime)  # Add this line
    
    def __repr__(self):
        return f'<MLModel {self.name}>'

class LLMPrompt(db.Model):
    __tablename__ = 'llm_prompts'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type = db.Column(db.String(50), nullable=False)  # 'phishing', 'malware', etc.
    prompt_text = db.Column(db.Text, nullable=False)
    llm_provider = db.Column(db.String(50), nullable=False)  # 'OpenAI', 'Anthropic', etc.
    
    def __repr__(self):
        return f'<LLMPrompt {self.type}>'

class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.JSON, nullable=False)
    description = db.Column(db.Text)
    last_updated = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f'<SystemSetting {self.name}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)