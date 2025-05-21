from app.models import SystemSetting, db

class SettingsManager:
    @staticmethod
    def get_setting(name, default=None):
        setting = SystemSetting.query.filter_by(name=name).first()
        return setting.value if setting else default

    @staticmethod
    def set_setting(name, value, description=None):
        setting = SystemSetting.query.filter_by(name=name).first()
        if setting:
            setting.value = value
            if description:
                setting.description = description
        else:
            setting = SystemSetting(
                name=name,
                value=value,
                description=description
            )
            db.session.add(setting)
        db.session.commit()
        return setting

# Initialize default settings
DEFAULT_SETTINGS = {
    'fair_distribution_enabled': {
        'value': True,
        'description': 'Whether to enable fair distribution of incidents among analysts'
    },
    'analyst_capacity': {
        'value': 20,
        'description': 'Default maximum incidents an analyst should have assigned'
    }
}

from app.models import SystemSetting, db

def init_default_settings(app):
    """Initialize default settings"""
    default_settings = [
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
    
    with app.app_context():
        for setting_data in default_settings:
            if not SystemSetting.query.filter_by(name=setting_data['name']).first():
                setting = SystemSetting(**setting_data)
                db.session.add(setting)
        db.session.commit()