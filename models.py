from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Hotspot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hotspot_duration = db.Column(db.String(80), nullable=False)  # e.g., '30 minutes'
    amount = db.Column(db.Float, nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'), nullable=False)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone_number = db.Column(db.String(15), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    hotspot_id = db.Column(db.Integer, db.ForeignKey('hotspot.id'), nullable=False)
    expiry_time = db.Column(db.DateTime, nullable=False)
