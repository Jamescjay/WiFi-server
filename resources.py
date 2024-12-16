from flask_restful import Resource, reqparse, fields, marshal_with 
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from models import db, Admin, Hotspot, Payment
from datetime import datetime, timedelta
import requests
import base64

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
    'hotspot_duration': fields.Integer,
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

        # Daraja API credentials
        consumer_key = "vPcFJwePGPxsp01iuRjUYe1DBUO4wBskE4Ybiy5wB4BA28ZI"
        consumer_secret = "T8Frn90T03oLH36DJC8pKDNpZUsGqHth3yUXVN6ipHFXMx7awzLmycEZSARIvvHI"
        passkey = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
        business_shortcode = "174379"

        # Generate access token
        auth = requests.auth.HTTPBasicAuth(consumer_key, consumer_secret)
        token_response = requests.get(
            "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
            auth=auth
        )
        if token_response.status_code != 200:
            return {'message': 'Failed to generate access token.'}, 500
        access_token = token_response.json()['access_token']

        # Prepare the password
        now = datetime.now()
        timestamp = now.strftime('%Y%m%d%H%M%S')
        password_string = f"{business_shortcode}{passkey}{timestamp}"
        password = base64.b64encode(password_string.encode()).decode()

        # Prepare the STK Push request
        payload = {
            "BusinessShortCode": business_shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": hotspot.amount,  # Amount based on the hotspot
            "PartyA": args['phone_number'],  # Customer's phone number
            "PartyB": business_shortcode,
            "PhoneNumber": args['phone_number'],  # Customer's phone number
            "CallBackURL": "https://63f8-41-90-172-14.ngrok-free.app/payment/callback",
            "AccountReference": "Hotspot",
            "TransactionDesc": f"Payment for hotspot {hotspot.id}"
        }

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        # Send the STK Push request
        stk_response = requests.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            json=payload,
            headers=headers
        )

        if stk_response.status_code == 200:
            # Parse the STK Push response
            stk_data = stk_response.json()
            if stk_data.get('ResponseCode') == "0":
                # Calculate expiry time
                expiry_time = datetime.utcnow() + timedelta(minutes=hotspot.hotspot_duration)

                # Save payment to the database
                payment = Payment(
                    phone_number=args['phone_number'],
                    amount=hotspot.amount,
                    hotspot_id=args['hotspot_id'],
                    expiry_time=expiry_time
                )
                db.session.add(payment)
                db.session.commit()
                return payment, 200
            else:
                return {
                    'message': 'STK Push failed.',
                    'error': stk_data.get('errorMessage', 'Unknown error')
                }, 400

        return {'message': 'Failed to send STK Push request.'}, 500
