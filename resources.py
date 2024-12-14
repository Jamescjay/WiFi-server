from flask_restful import Resource, reqparse, fields, marshal_with 
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from models import db, Admin, Hotspot, Payment
from datetime import datetime, timedelta
import requests

bcrypt = Bcrypt()

# Parsers
admin_parser = reqparse.RequestParser()
admin_parser.add_argument('name', required=False, help="Name is required.")
admin_parser.add_argument('email', required=True, help="Email is required.")
admin_parser.add_argument('password', required=True, help="Password is required.")

hotspot_parser = reqparse.RequestParser()
hotspot_parser.add_argument('hotspot_duration', required=True, help="Hotspot duration is required.")
hotspot_parser.add_argument('amount', type=float, required=True, help="Amount is required.")

payment_parser = reqparse.RequestParser()
payment_parser.add_argument('phone_number', required=True, help="Phone number is required.")
payment_parser.add_argument('hotspot_id', type=int, required=True, help="Hotspot ID is required.")

# Response fields for marshalling
admin_fields = {
    'id': fields.Integer,
    'name': fields.String,
    'email': fields.String,
}

hotspot_fields = {
    'id': fields.Integer,
    'hotspot_duration': fields.String,
    'amount': fields.Float,
}

payment_fields = {
    'id': fields.Integer,
    'phone_number': fields.String,
    'amount': fields.Float,
    'hotspot_id': fields.Integer,
    'expiry_time': fields.DateTime,
}


class AdminRegisterResource(Resource):
    def post(self):
        """Admin registration."""
        args = admin_parser.parse_args(strict=True)

        # Check if the email is already taken
        existing_admin = Admin.query.filter_by(email=args['email']).first()
        if existing_admin:
            return {"message": "Email already taken."}, 400

        if not args['name']:
            return {"message": "Name is required for registration."}, 400

        hashed_password = bcrypt.generate_password_hash(args['password']).decode('utf-8')
        admin = Admin(name=args['name'], email=args['email'], password=hashed_password)
        
        try:
            db.session.add(admin)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {'message': f"Failed to register admin: {str(e)}"}, 500

        access_token = create_access_token(identity=args['email'])
        refresh_token = create_refresh_token(identity=args['email'])
        return {
            'message': 'Admin registered successfully.',
            'access_token': access_token,
            'refresh_token': refresh_token
        }, 201


class AdminLoginResource(Resource):
    def post(self):
        """Admin login."""
        args = admin_parser.parse_args(strict=True)
        admin = Admin.query.filter_by(email=args['email']).first()

        if admin and bcrypt.check_password_hash(admin.password, args['password']):
            access_token = create_access_token(identity=admin.email)
            refresh_token = create_refresh_token(identity=admin.email)
            return {
                'message': 'Login successful.',
                'access_token': access_token,
                'refresh_token': refresh_token
            }, 200
        return {'message': 'Invalid email or password.'}, 401


class AdminResource(Resource):
    @marshal_with(admin_fields)
    @jwt_required()
    def get(self):
        """Get all admins."""
        admins = Admin.query.all()
        return admins, 200

    @jwt_required()
    def delete(self, admin_id=None):
        """
        Delete the logged-in admin account or a specific admin.
        If no admin_id is provided, deletes the currently logged-in admin.
        If admin_id is provided, deletes the specified admin.
        """
        current_user = get_jwt_identity()
        
        # If admin_id is provided, delete the specific admin
        if admin_id:
            admin = Admin.query.get(admin_id)
            if admin:
                db.session.delete(admin)
                db.session.commit()
                return {'message': f'Admin with ID {admin_id} deleted successfully.'}, 200
            return {'message': f'Admin with ID {admin_id} not found.'}, 404
        
        # Otherwise, delete the currently logged-in admin
        admin = Admin.query.filter_by(email=current_user).first()
        if admin:
            db.session.delete(admin)
            db.session.commit()
            return {'message': 'Logged-in admin account deleted successfully.'}, 200
        
        return {'message': 'Logged-in admin account not found.'}, 404



class HotspotResource(Resource):
    @marshal_with(hotspot_fields)
    @jwt_required()
    def post(self):
        """Create a new hotspot."""
        args = hotspot_parser.parse_args(strict=True)
        current_user = get_jwt_identity()
        admin = Admin.query.filter_by(email=current_user).first()

        if not admin:
            return {'message': 'Unauthorized.'}, 401

        hotspot = Hotspot(hotspot_duration=args['hotspot_duration'], amount=args['amount'], admin_id=admin.id)
        db.session.add(hotspot)
        db.session.commit()
        return hotspot, 201

    @marshal_with(hotspot_fields)
    @jwt_required()
    def put(self, id):
        """Update a hotspot."""
        args = hotspot_parser.parse_args(strict=True)
        hotspot = Hotspot.query.get(id)

        if hotspot:
            hotspot.hotspot_duration = args['hotspot_duration']
            hotspot.amount = args['amount']
            db.session.commit()
            return hotspot, 200
        return {'message': 'Hotspot not found.'}, 404

    @marshal_with(hotspot_fields)
    def get(self, id=None):
        """Get all or specific hotspot."""
        if id:
            hotspot = Hotspot.query.get(id)
            if hotspot:
                return hotspot, 200
            return {'message': 'Hotspot not found.'}, 404
        hotspots = Hotspot.query.all()
        return hotspots, 200

    @jwt_required()
    def delete(self, id=None):
        """Delete a hotspot."""
        if id:
            hotspot = Hotspot.query.get(id)
            if hotspot:
                db.session.delete(hotspot)
                db.session.commit()
                return {'message': 'Hotspot deleted successfully.'}, 200
            return {'message': 'Hotspot not found.'}, 404
        Hotspot.query.delete()
        db.session.commit()
        return {'message': 'All hotspots deleted successfully.'}, 200


class PaymentResource(Resource):
    @marshal_with(payment_fields)
    def post(self):
        """Process a payment."""
        args = payment_parser.parse_args(strict=True)
        hotspot = Hotspot.query.get(args['hotspot_id'])

        if not hotspot:
            return {'message': 'Hotspot not found.'}, 404

        # Simulate Safaricom Daraja API call
        payment_response = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            json={
                "BusinessShortCode": "478563",
                "Password": "encoded_password",
                "Timestamp": "timestamp",
                "TransactionType": "CustomerPayBillOnline",
                "Amount": hotspot.amount,
                "PartyA": args['phone_number'],
                "PartyB": "478563",
                "PhoneNumber": args['phone_number'],
                "CallBackURL": "https://your-callback-url.com",
                "AccountReference": "Hotspot",
                "TransactionDesc": "Payment for hotspot"
            }
        )

        if payment_response.status_code == 200:
            expiry_time = datetime.utcnow() + timedelta(minutes=int(hotspot.hotspot_duration.split()[0]))
            payment = Payment(phone_number=args['phone_number'], amount=hotspot.amount, hotspot_id=args['hotspot_id'], expiry_time=expiry_time)
            db.session.add(payment)
            db.session.commit()
            return payment, 200
        return {'message': 'Payment failed.'}, 400
