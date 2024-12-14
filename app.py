from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_restful import Api

from models import db  # Import the db instance from models
from resources import AdminRegisterResource, AdminLoginResource, AdminResource, HotspotResource, PaymentResource

# Initialize Flask app
app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///wifi.db'  # Replace with your actual database URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Replace with your secret key

# Initialize extensions
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
api = Api(app)

# Add resources
api.add_resource(AdminRegisterResource, '/admin/register')
api.add_resource(AdminLoginResource, '/admin/login')
api.add_resource(AdminResource, '/admin', '/admin/<int:admin_id>')
api.add_resource(HotspotResource, '/hotspot', '/hotspot/<int:id>')
api.add_resource(PaymentResource, '/payment')

# Create tables before the first request
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
