import uuid
from datetime import datetime, timedelta
from random import choice, randint, uniform
from faker import Faker
from app import create_app, db
from app.models import User, Incident, Enrichment, MLModel, LLMPrompt, AnalyticsLog, SystemSetting

fake = Faker()

def create_fake_users(count=5):
    """Create fake users with different roles"""
    roles = ['admin', 'manager', 'analyst']
    users = []
    for _ in range(count):
        user = User(
            username=fake.user_name(),
            password_hash='$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW',  # 'password'
            role=choice(roles),
            is_active=True
        )
        users.append(user)
        db.session.add(user)
    db.session.commit()
    return users

def create_fake_ml_models():
    """Create fake ML models"""
    models = [
        {
            'name': 'Anomaly Detection',
            'purpose': 'Network behavior analysis',
            'model_type': 'anomaly',
            'endpoint': 'http://localhost:3001',
            'api_key': str(uuid.uuid4()),
            'version': '1.3.1',
            'is_active': True,
            'last_active': datetime.now() - timedelta(days=randint(0, 30))
        },
        {
            'name': 'Malware Detection',
            'purpose': 'Malicious file detection',
            'model_type': 'malware',
            'endpoint': 'http://localhost:4000',
            'api_key': str(uuid.uuid4()),
            'version': '1.7.4',
            'is_active': True,
            'last_active': datetime.now() - timedelta(days=randint(0, 30))
        },
        {
            'name': 'Phishing Detection',
            'purpose': 'Email and URL analysis',
            'model_type': 'phishing',
            'endpoint': 'http://localhost:6000',
            'api_key': str(uuid.uuid4()),
            'version': '1.0.2',
            'is_active': True,
            'last_active': datetime.now() - timedelta(days=randint(0, 30))
        },
        {
            'name': 'Windows Log Analysis',
            'purpose': 'Windows event log analysis',
            'model_type': 'windows_log',
            'endpoint': 'http://localhost:7000',
            'api_key': str(uuid.uuid4()),
            'version': '1.2.0',
            'is_active': True,
            'last_active': datetime.now() - timedelta(days=randint(0, 30))
        }
    ]
    
    ml_models = []
    for model_data in models:
        model = MLModel(**model_data)
        ml_models.append(model)
        db.session.add(model)
    db.session.commit()
    return ml_models

def create_fake_llm_prompts():
    """Create fake LLM prompts"""
    prompts = [
        {
            'type': 'phishing',
            'prompt_text': "Analyze this potential phishing attempt: {alert_details}",
            'llm_provider': 'OpenAI'
        },
        {
            'type': 'malware',
            'prompt_text': "Investigate this malware alert: {alert_details}",
            'llm_provider': 'OpenAI'
        },
        {
            'type': 'insider_threat',
            'prompt_text': "Examine this potential insider threat: {alert_details}",
            'llm_provider': 'Anthropic'
        }
    ]
    
    llm_prompts = []
    for prompt_data in prompts:
        prompt = LLMPrompt(**prompt_data)
        llm_prompts.append(prompt)
        db.session.add(prompt)
    db.session.commit()
    return llm_prompts

def create_fake_incidents(count=50, users=None, ml_models=None):
    """Create fake incidents"""
    if not users:
        users = User.query.filter_by(role='analyst').all()
    if not ml_models:
        ml_models = MLModel.query.all()
    
    incident_types = ['Phishing', 'Malware', 'DDoS', 'Data Exfiltration', 'Insider Threat', 'Unauthorized Access']
    severities = ['Critical', 'High', 'Medium', 'Low']
    statuses = ['New', 'In Progress', 'Closed', 'False Positive']
    
    incidents = []
    for _ in range(count):
        timestamp = fake.date_time_between(start_date='-30d', end_date='now')
        
        incident = Incident(
            timestamp=timestamp,
            source_ip=fake.ipv4(),
            type=choice(incident_types),
            severity=choice(severities),
            ml_model_name=choice(ml_models).name,
            confidence_score=round(uniform(0.7, 0.99), 2),  # 70-99%
            assigned_to=choice(users).id if randint(0, 4) > 0 else None,  # 80% chance of assignment
            status=choice(statuses),
            description=fake.text(max_nb_chars=200),
            llm_summary=fake.paragraph(nb_sentences=3) if randint(0, 1) else None  # 50% chance of having summary
        )
        
        incidents.append(incident)
        db.session.add(incident)
    db.session.commit()
    return incidents

def create_fake_enrichments(incidents=None):
    """Create fake enrichments for incidents"""
    if not incidents:
        incidents = Incident.query.all()
    
    enrichment_sources = ['VirusTotal', 'OpenCTI', 'Cortex', 'ThreatFox', 'AlienVault']
    
    for incident in incidents:
        # Create 1-3 enrichments per incident
        for _ in range(randint(1, 3)):
            enrichment = Enrichment(
                incident_id=incident.id,
                source=choice(enrichment_sources),
                data={
                    'score': randint(0, 100),
                    'details': fake.sentence(),
                    'link': fake.url(),
                    'last_updated': fake.date_time_this_month().isoformat()
                }
            )
            db.session.add(enrichment)
    db.session.commit()

def create_fake_analytics_logs(incidents=None, users=None):
    """Create fake analytics logs"""
    if not incidents:
        incidents = Incident.query.all()
    if not users:
        users = User.query.all()
    
    event_types = ['status_change', 'assignment', 'note_added', 'enrichment_added']
    
    for incident in incidents:
        # Create creation log
        creation_log = AnalyticsLog(
            incident_id=incident.id,
            analyst_id=choice(users).id,
            event_type='created',
            timestamp=incident.timestamp
        )
        db.session.add(creation_log)
        
        # Create status change logs if incident isn't new
        if incident.status != 'New':
            status_log = AnalyticsLog(
                incident_id=incident.id,
                analyst_id=incident.assigned_to or choice(users).id,
                event_type='status_change',
                timestamp=incident.timestamp + timedelta(hours=randint(1, 24))
            )
            db.session.add(status_log)
        
        # Create 1-3 random logs
        for _ in range(randint(1, 3)):
            log = AnalyticsLog(
                incident_id=incident.id,
                analyst_id=choice(users).id,
                event_type=choice(event_types),
                timestamp=incident.timestamp + timedelta(hours=randint(1, 72))
            )
            db.session.add(log)
    db.session.commit()

def create_system_settings():
    """Create default system settings"""
    settings = [
        {
            'name': 'fair_distribution_enabled',
            'value': True,
            'description': 'Whether to enable fair distribution of incidents among analysts'
        },
        {
            'name': 'analyst_capacity',
            'value': 20,
            'description': 'Default maximum incidents an analyst should have assigned'
        }
    ]
    
    for setting_data in settings:
        if not SystemSetting.query.filter_by(name=setting_data['name']).first():
            setting = SystemSetting(**setting_data)
            db.session.add(setting)
    db.session.commit()

def initialize_system_settings(app):
    """Initialize system settings for testing"""
    with app.app_context():
        from app.utils.settings import init_default_settings
        init_default_settings(app)

def seed_database(app):
    """Main function to seed the database"""
    with app.app_context():
        print("Initializing system settings...")
        initialize_system_settings(app)

        print("Creating fake users...")
        users = create_fake_users()
        
        print("Creating fake ML models...")
        ml_models = create_fake_ml_models()
        
        print("Creating fake LLM prompts...")
        llm_prompts = create_fake_llm_prompts()
        
        print("Creating system settings...")
        # Create default system settings
        settings = [
            {
                'name': 'fair_distribution_enabled',
                'value': True,
                'description': 'Whether to enable fair distribution of incidents among analysts'
            },
            {
                'name': 'analyst_capacity',
                'value': 20,
                'description': 'Default maximum incidents an analyst should have assigned'
            }
        ]
        
        for setting_data in settings:
            if not SystemSetting.query.filter_by(name=setting_data['name']).first():
                setting = SystemSetting(**setting_data)
                db.session.add(setting)
        db.session.commit()
        
        print("Creating fake incidents...")
        incidents = create_fake_incidents(users=users, ml_models=ml_models)
        
        print("Creating fake enrichments...")
        create_fake_enrichments(incidents=incidents)
        
        print("Creating fake analytics logs...")
        create_fake_analytics_logs(incidents=incidents, users=users)
        
        print("Database seeding completed successfully!")

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()
        seed_database(app)