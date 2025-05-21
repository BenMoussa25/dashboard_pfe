from flask import Flask
from config import DevelopmentConfig
import logging
from logging.handlers import RotatingFileHandler
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app import create_app

app = create_app()

if __name__ == '__main__':
    # Configure logging
    handler = RotatingFileHandler('soc_dashboard.log', maxBytes=10000, backupCount=1)
    handler.setLevel(logging.INFO)
    app.logger.addHandler(handler)
    
    app.run(debug=True)