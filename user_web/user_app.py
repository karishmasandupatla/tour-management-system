from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from urllib.parse import urlparse
from functools import wraps
from flask_cors import CORS
import os, json, uuid, datetime

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')

# Enable CORS for specific origins
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:5173", "https://your-firebase-app.web.app"]}})

# Environment-based configuration
IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production'
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())  # Use env var in production, random key locally

# Session configuration
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_COOKIE_SECURE'] = True if IS_PRODUCTION else False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)
app.config['SESSION_COOKIE_DOMAIN'] = None

# MongoDB connection setup (for local development; replace with Firestore in production)
uri = "mongodb+srv://karishma_22:mongodb_work7@ks.n6eovrv.mongodb.net/?retryWrites=true&w=majority&appName=KS"
client = MongoClient(uri, server_api=ServerApi('1'))

# Verify MongoDB connection
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(f"MongoDB connection error: {e}")

# MongoDB database and collections (replace with Firestore collections in production)
db = client["Travel"]
user_collection = db["User"]
tour_collection = db["tour"]
booking_collection = db["Booking"]
review_collection = db["Reviews"]

# Login required decorator with debugging
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"Checking session for route {request.path}: user_id={session.get('user_id')}")
        if 'user_id' not in session:
            session.clear()  # Clear any invalid session
            print(f"Redirecting to login from {request.path}")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

# Route to serve welcome page
@app.route("/", methods=['GET'])
def index():
    """Render the welcome page with MongoDB connection status."""
    if 'user_id' not in session:
        print("Redirecting to login from /")
        return redirect(url_for('login_page'))
    name = os.environ.get("NAME", "World")
    try:
        client.admin.command('ping')
        status = "MongoDB is connected"
    except Exception as e:
        status = f"MongoDB connection failed: {str(e)}"
    return render_template('index.html', name=name, status=status, session=session)

# Route to serve signup page
@app.route("/signup", methods=['GET'])
def signup_page():
    return render_template('signup.html')

# Route to serve login page
@app.route("/login", methods=['GET'])
def login_page():
    return render_template('login.html')

# Route to serve customer welcome page
@app.route("/customer_welcome", methods=['GET'])
@login_required
def customer_welcome():
    return render_template('customer_welcome.html', session=session)

# Route to serve users page
@app.route("/users", methods=['GET'])
@login_required
def users_page():
    return render_template('users.html', session=session)

# Route to serve user details page
@app.route("/user_details", methods=['GET'])
@login_required
def user_details_page():
    return render_template('user_details.html', session=session)

# Route to serve delete user page
@app.route("/delete_user", methods=['GET'])
@login_required
def delete_user_page():
    return render_template('delete_user.html', session=session)

# Route to serve update user page
@app.route("/update_user", methods=['GET'])
@login_required
def update_user_page():
    return render_template('update_user.html', session=session)

# Route to serve favicon
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

# Function to read users with role-based access
def read_users(current_user_role):
    try:
        if current_user_role not in ["admin", "travel_agent"]:
            return jsonify({"message": "Access denied: Only admins and travel agents can read user data"}), 403
        client.admin.command('ping')
        users = user_collection.find()
        result = [
            {
                "Email": user.get("email"),
                "FullName": user.get("full_name"),
                "UserRole": user.get("user_role"),
                "AccountStatus": user.get("account_status")
            }
            for user in users
        ]
        return jsonify(result), 200
    except Exception as e:
        print(f"Error during reading users: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to get users (admin/travel_agent only)
@app.route('/api/users', methods=['GET'])
@login_required
def get_users():
    current_user_role = session.get('user_role')
    return read_users(current_user_role)

# Function to read all users
def read_users_byall():
    try:
        client.admin.command('ping')
        users = user_collection.find()
        result = [
            {
                "Email": user.get("email"),
                "FullName": user.get("full_name"),
                "UserRole": user.get("user_role"),
                "AccountStatus": user.get("account_status")
            }
            for user in users
        ]
        return jsonify(result), 200
    except Exception as e:
        print(f"Error during reading users: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to get all users
@app.route('/api/users/all', methods=['GET'])
@login_required
def get_users_by_all():
    return read_users_byall()

# Function to get user by email with role-based access
def get_user_by_email(email, current_user_role):
    try:
        if current_user_role not in ['admin', 'travel_agent']:
            return jsonify({"message": "Access denied: Only admins or travel agents can view this data"}), 403
        client.admin.command('ping')
        user = user_collection.find_one({"email": email})
        if user:
            user_data = {
                "user_id": user.get("user_id"),
                "email": user.get("email"),
                "full_name": user.get("full_name"),
                "account_created_at": user.get("account_created_at"),
                "last_login_date": user.get("last_login_date"),
                "logout_time": user.get("logout_time"),
                "user_role": user.get("user_role"),
                "email_verified": user.get("email_verified"),
                "account_status": user.get("account_status")
            }
            return jsonify(user_data), 200
        return jsonify({"message": "User not found"}), 404
    except Exception as e:
        print(f"Error during fetching user by email: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to get user by email
@app.route('/api/user/<email>', methods=['GET'])
@login_required
def get_user_by_email_route(email):
    current_user_role = session.get('user_role')
    return get_user_by_email(email, current_user_role)

# Function to sign up a new user
def sign_up_user(data):
    try:
        client.admin.command('ping')
        if user_collection.find_one({"email": data.get("email")}):
            return jsonify({"message": "Email already registered"}), 400

        hashed_password = generate_password_hash(data.get("password"))
        user_data = {
            "user_id": str(uuid.uuid4()),
            "email": data.get("email"),
            "password_hashed": hashed_password,
            "full_name": data.get("full_name"),
            "account_created_at": datetime.datetime.utcnow().isoformat(),
            "last_login_date": None,
            "logout_time": None,
            "user_role": "customer",
            "email_verified": False,
            "account_status": "active"
        }
        user_collection.insert_one(user_data)
        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        print(f"Error during sign-up: {str(e)}")
        return jsonify({"message": f"Connection Problem: {str(e)}"}), 500

# API to register user
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    if not data or not all(key in data for key in ["email", "password", "full_name"]):
        return jsonify({"message": "Missing required fields: email, password, full_name are required"}), 400
    return sign_up_user(data)

# Function to log in a user
def login_user(data):
    try:
        client.admin.command('ping')
        email = data.get("email")
        password = data.get("password")
        user = user_collection.find_one({"email": email})
        if user and check_password_hash(user.get("password_hashed"), password):
            user_collection.update_one(
                {"email": email},
                {"$set": {"last_login_date": datetime.datetime.utcnow().isoformat()}}
            )
            # Set session data
            session['user_id'] = user.get("user_id")
            session['user_role'] = user.get("user_role")
            session['full_name'] = user.get("full_name")
            response_data = {
                "message": "Login successful",
                "user_id": user.get("user_id"),
                "full_name": user.get("full_name"),
                "user_role": user.get("user_role"),
                "account_status": user.get("account_status"),
                "redirect": "/customer_welcome" if user.get("user_role") == "customer" else "/users"
            }
            return jsonify(response_data), 200
        return jsonify({"message": "Invalid email or password"}), 401
    except Exception as e:
        print(f"Error during login: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to login user
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not all(key in data for key in ["email", "password"]):
        return jsonify({"message": "Missing required fields"}), 400
    return login_user(data)

# Function to request a password reset
def request_password_reset(data):
    try:
        client.admin.command('ping')
        email = data.get("email")
        user = user_collection.find_one({"email": email})
        if not user:
            return jsonify({"message": "Email not found"}), 404

        reset_token = str(uuid.uuid4())
        expiration_time = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()
        user_collection.update_one(
            {"email": email},
            {"$set": {
                "reset_token": reset_token,
                "reset_token_expiration": expiration_time
            }}
        )
        return jsonify({
            "message": "Password reset requested. Use the token to reset your password.",
            "reset_token": reset_token
        }), 200
    except Exception as e:
        print(f"Error during password reset request: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to request password reset
@app.route('/api/reset_password_request', methods=['POST'])
def reset_password_request():
    data = request.get_json()
    if not data or "email" not in data:
        return jsonify({"message": "Email is required"}), 400
    return request_password_reset(data)

# Function to reset password using token
def reset_password(data):
    try:
        client.admin.command('ping')
        token = data.get("reset_token")
        new_password = data.get("new_password")
        if not token or not new_password:
            return jsonify({"message": "Reset token and new password are required"}), 400

        user = user_collection.find_one({"reset_token": token})
        if not user:
            return jsonify({"message": "Invalid or expired reset token"}), 401

        expiration = user.get("reset_token_expiration")
        if expiration and datetime.datetime.fromisoformat(expiration) < datetime.datetime.utcnow():
            return jsonify({"message": "Reset token has expired"}), 401

        hashed_password = generate_password_hash(new_password)
        user_collection.update_one(
            {"reset_token": token},
            {"$set": {
                "password_hashed": hashed_password,
                "reset_token": None,
                "reset_token_expiration": None
            }}
        )
        return jsonify({"message": "Password reset successfully"}), 200
    except Exception as e:
        print(f"Error during password reset: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to reset password
@app.route('/api/reset_password', methods=['POST'])
def reset_password_endpoint():
    data = request.get_json()
    if not data or not all(key in data for key in ["reset_token", "new_password"]):
        return jsonify({"message": "Reset token and new password are required"}), 400
    return reset_password(data)

# Function to log out a user
def logout_user(data):
    try:
        client.admin.command('ping')
        user_id = data.get("user_id")
        if not user_id:
            return jsonify({"message": "User ID required"}), 400
        result = user_collection.update_one(
            {"user_id": user_id},
            {"$set": {"logout_time": datetime.datetime.utcnow().isoformat()}}
        )
        if result.matched_count > 0:
            session.clear()
            print(f"Session cleared for user_id={user_id}")
            response = make_response(jsonify({"message": "Logout successful", "redirect": "/login"}))
            response.set_cookie('session', '', expires=0, secure=IS_PRODUCTION, httponly=True, samesite='Lax')
            return response, 200
        return jsonify({"message": "User not found"}), 404
    except Exception as e:
        print(f"Error during logout: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to logout user
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    data = request.get_json()
    if not data or "user_id" not in data:
        return jsonify({"message": "User ID required"}), 400
    return logout_user(data)

# Function to delete user by full name
def delete_user_by_full_name(full_name, current_user_role):
    try:
        if current_user_role != 'admin':
            return jsonify({"message": "Access denied: Only admins can delete users"}), 403
        client.admin.command('ping')
        result = user_collection.delete_one({"full_name": full_name})
        if result.deleted_count > 0:
            return jsonify({"message": f"User '{full_name}' deleted successfully"}), 200
        return jsonify({"message": f"User '{full_name}' not found"}), 404
    except Exception as e:
        print(f"Error during deleting user: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to delete user by name
@app.route('/api/user/delete/<full_name>', methods=['DELETE'])
@login_required
def delete_user(full_name):
    current_user_role = session.get('user_role')
    return delete_user_by_full_name(full_name, current_user_role)

# Function to update user by email
def update_user_partial(email, updated_data):
    try:
        client.admin.command('ping')
        result = user_collection.update_one(
            {"email": email},
            {"$set": updated_data}
        )
        if result.matched_count > 0:
            return jsonify({"message": "User updated successfully"}), 200
        return jsonify({"message": "User not found"}), 404
    except Exception as e:
        print(f"Error during updating user data: {str(e)}")
        return jsonify({"message": "Connection Problem"}), 500

# API to update user by email
@app.route('/api/user/update', methods=['PATCH'])
@login_required
def patch_user():
    updated_data = request.get_json()
    if not updated_data or 'email' not in updated_data:
        return jsonify({"message": "Email is required"}), 400
    email = updated_data.pop('email')
    return update_user_partial(email, updated_data)

# Tours Routes
# Route to render tours page
@app.route('/tours', methods=['GET'])
@login_required
def tours_page():
    result, status = read_tours()
    if status == 200:
        return render_template('tours.html', tours=result, session=session)
    return render_template('tours.html', tours=[], error=result.get("error"), session=session)

# API route for getting tours
@app.route('/api/tours', methods=['GET'])
@login_required
def get_tours():
    result, status = read_tours()
    return jsonify(result), status

# Function to read tour data
def read_tours():
    try:
        client.admin.command('ping')
        tours = tour_collection.find()
        result = []
        for tour in tours:
            image_url = tour.get("image_url", [])
            if isinstance(image_url, str):
                image_url = [image_url]
            d = {
                "TourID": tour.get("TourID"),
                "TourName": tour.get("TourName"),
                "Duration": tour.get("Duration"),
                "StartDate": tour.get("StartDate"),
                "EndDate": tour.get("EndDate"),
                "Destinations": tour.get("Destinations", []),
                "image_url": image_url
            }
            result.append(d)
        return result, 200
    except Exception as e:
        print(f"Error during reading tours: {str(e)}")
        return {"error": str(e)}, 500
#
# API route for getting tours for customer/user page
@app.route('/api/customer_tours', methods=['GET'])
@login_required
def get_customer_tours():
    result, status = read_tours()  # Reusing read_tours() for now
    return jsonify(result), status

# Function to read tour data (same as admin, reusable for now)
def read_tours():
    try:
        client.admin.command('ping')
        tours = tour_collection.find()
        result = []
        for tour in tours:
            image_url = tour.get("image_url", [])
            if isinstance(image_url, str):
                image_url = [image_url]
            d = {
                "TourID": tour.get("TourID"),
                "TourName": tour.get("TourName"),
                "Duration": tour.get("Duration"),
                "StartDate": tour.get("StartDate"),
                "EndDate": tour.get("EndDate"),
                "Destinations": tour.get("Destinations", []),
                "image_url": image_url
            }
            result.append(d)
        return result, 200
    except Exception as e:
        print(f"Error during reading tours: {str(e)}")
        return {"error": str(e)}, 500

# Route to render customer tours page
@app.route('/customer_tours', methods=['GET'])
@login_required
def customer_tours_page():
    result, status = read_tours()
    if status == 200:
        return render_template('customer_tours.html', tours=result, session=session)
    return render_template('customer_tours.html', tours=[], error=result.get("error"), session=session)

# Route to render tour by ID page
@app.route('/tour/<tour_id>', methods=['GET'])
@login_required
def tour_page(tour_id):
    tour, status = read_tour_by_id(tour_id)
    return render_template('tour.html', tour=tour, status=status, session=session)

# API route for get tour by id
@app.route('/api/tour/<tour_id>', methods=['GET'])
@login_required
def get_tour_by_id(tour_id):
    result, status = read_tour_by_id(tour_id)
    return jsonify(result), status

# Function to read tour data by tour_id
def read_tour_by_id(tour_id):
    try:
        client.admin.command('ping')
        tour = tour_collection.find_one({"TourID": tour_id})
        if tour:
            image_url = tour.get("image_url", [])
            if isinstance(image_url, str):
                image_url = [image_url]
            result = {
                "TourID": tour.get("TourID"),
                "TourName": tour.get("TourName"),
                "Duration": tour.get("Duration"),
                "StartDate": tour.get("StartDate"),
                "EndDate": tour.get("EndDate"),
                "Destinations": tour.get("Destinations", []),
                "image_url": image_url
            }
            return result, 200
        return {"message": "Tour not found"}, 404
    except Exception as e:
        print(f"Error during reading tour by id: {str(e)}")
        return {"error": str(e)}, 500

# Route to render add tour page
@app.route('/add_tour', methods=['GET'])
@login_required
def add_tour_page():
    return render_template('add_tour.html', session=session)

# API route for adding tour data
@app.route('/api/tour/add', methods=['POST'])
@login_required
def add_tour():
    try:
        data = request.json
        required_fields = ['TourID', 'TourName', 'Duration', 'StartDate', 'EndDate', 'Destinations', 'image_url']
        if not all(field in data for field in required_fields):
            return jsonify({"error": "Missing required fields"}), 400

        image_urls = data['image_url']
        urls_to_validate = image_urls if isinstance(image_urls, list) else [image_urls]
        for url in urls_to_validate:
            if not isinstance(url, str):
                return jsonify({"error": "Each item in image_url must be a string"}), 400
            try:
                result = urlparse(url)
                if not all([result.scheme, result.netloc]):
                    return jsonify({"error": f"Invalid URL format in image_url: {url}"}), 400
            except Exception as e:
                return jsonify({"error": f"Invalid URL format in image_url: {url}"}), 400

        result, status = insert_tour(data)
        return jsonify(result), status
    except Exception as e:
        print(f"Error in add_tour: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Function to add new tour data
def insert_tour(tour_data):
    try:
        client.admin.command('ping')
        result = tour_collection.insert_one(tour_data)
        return {"message": "Tour added successfully", "id": str(result.inserted_id)}, 200
    except Exception as e:
        print(f"Error during tour insert: {str(e)}")
        return {"error": str(e)}, 500

# Route to render update tour page
@app.route('/update_tour/<tourid>', methods=['GET'])
@login_required
def update_tour_page(tourid):
    tour, status = read_tour_by_id(tourid)
    return render_template('update_tour.html', tour=tour, status=status, session=session)

# API route for updating tour data
@app.route('/api/tour/update/<tourid>', methods=['PUT'])
@login_required
def update_tour(tourid):
    try:
        data = request.json
        if not data:
            return jsonify({"error": "No data provided to update"}), 400
        result, status = update_tour_by_id(tourid, data)
        return jsonify(result), status
    except Exception as e:
        print(f"Error in /api/tour/update/<tourid>: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Function to update tour data by tour id
def update_tour_by_id(tourid, update_data):
    try:
        client.admin.command('ping')
        query = {"TourID": tourid}
        new_values = {"$set": update_data}
        result = tour_collection.update_one(query, new_values)
        if result.matched_count > 0:
            return {"message": "Tour updated successfully"}, 200
        return {"message": "No tour found with the given TourID"}, 404
    except Exception as e:
        print(f"Error in update_tour_by_id: {str(e)}")
        return {"error": str(e)}, 500

# Route to render nearby tours page
@app.route('/nearby_tours', methods=['GET'])
@login_required
def nearby_tours_page():
    city = request.args.get('city', '')
    if city:
        result, status = find_nearby_tours(city)
        if status == 200:
            return render_template('nearby_tours.html', tours=result.get('NearbyTours', []), city=city, status=status, session=session)
        return render_template('nearby_tours.html', tours=[], city=city, error=result.get('message', result.get('error')), session=session)
    return render_template('nearby_tours.html', tours=[], city='', session=session)

# API route for nearby tours
@app.route('/api/tours/nearby/<city>', methods=['GET'])
@login_required
def get_nearby_tours(city):
    result, status = find_nearby_tours(city)
    return jsonify(result), status

# Function to read tour data by city name
def find_nearby_tours(city):
    try:
        client.admin.command('ping')
        query = {"Destinations": {"$regex": city, "$options": "i"}}
        results = tour_collection.find(query)
        tours = []
        for tour in results:
            image_url = tour.get("image_url", [])
            if isinstance(image_url, str):
                image_url = [image_url]
            tours.append({
                "TourID": tour.get("TourID"),
                "TourName": tour.get("TourName"),
                "Duration": tour.get("Duration"),
                "StartDate": tour.get("StartDate"),
                "EndDate": tour.get("EndDate"),
                "Destinations": tour.get("Destinations", []),
                "image_url": image_url
            })
        if tours:
            return {"NearbyTours": tours}, 200
        return {"message": f"No tours found near {city}"}, 404
    except Exception as e:
        print(f"Error in find_nearby_tours: {str(e)}")
        return {"error": str(e)}, 500

# Route to render delete tour page
@app.route('/delete_tour', methods=['GET'])
@login_required
def delete_tour_page():
    return render_template('delete_tour.html', tour_name='', session=session)

# Route to render delete tour page with pre-filled TourName
@app.route('/delete_tour/<tour_name>', methods=['GET'])
@login_required
def delete_tour_page_with_name(tour_name):
    return render_template('delete_tour.html', tour_name=tour_name, session=session)

# API route for deleting tour by name
@app.route('/api/tour/delete/name/<tour_name>', methods=['DELETE'])
@login_required
def delete_tour_name(tour_name):
    result, status = delete_tour_by_name(tour_name)
    return jsonify(result), status

# Function to delete tour data by tour name
def delete_tour_by_name(tour_name):
    try:
        client.admin.command('ping')
        query = {"TourName": tour_name}
        result = tour_collection.delete_one(query)
        if result.deleted_count > 0:
            return {"message": f"Tour '{tour_name}' deleted successfully"}, 200
        return {"message": f"Tour '{tour_name}' not found"}, 404
    except Exception as e:
        print(f"Error in delete_tour_by_name: {str(e)}")
        return {"error": str(e)}, 500

# Route to render delete tour by ID page
@app.route('/delete_tour/id/<tour_id>', methods=['GET'])
@login_required
def delete_tour_by_id_page(tour_id):
    tour, status = read_tour_by_id(tour_id)
    return render_template('delete_tour_by_id.html', tour=tour, status=status, session=session)

# API route for deleting tour by ID
@app.route('/api/tour/delete/id/<tour_id>', methods=['DELETE'])
@login_required
def delete_tour_by_id(tour_id):
    result, status = delete_tour_by_id(tour_id)
    return jsonify(result), status

# Function to delete tour data by tour id
def delete_tour_by_id(tour_id):
    try:
        client.admin.command('ping')
        query = {"TourID": tour_id}
        result = tour_collection.delete_one(query)
        if result.deleted_count > 0:
            return {"message": f"Tour with ID '{tour_id}' deleted successfully"}, 200
        return {"message": f"Tour with ID '{tour_id}' not found"}, 404
    except Exception as e:
        print(f"Error in delete_tour_by_id: {str(e)}")
        return {"error": str(e)}, 500

# Booking Routes
# Route to get all bookings
@app.route('/bookings', methods=['GET'])
@login_required
def get_bookings():
    bookings = read_bookings()
    if isinstance(bookings, dict) and "error" in bookings:
        return render_template("get_bookings.html", error=bookings["error"], session=session)
    return render_template("get_bookings.html", bookings=bookings, session=session)

# Function to read all booking data
def read_bookings():
    try:
        client.admin.command('ping')
        bookings = booking_collection.find()
        result = [
            {
                "user_id": booking.get("user_id"),
                "user_email": booking.get("user_email"),
                "tour_id": booking.get("tour_id"),
                "tour_destination": booking.get("tour_destination"),
                "tour_dates": booking.get("tour_dates"),
                "booking_status": booking.get("booking_status"),
                "payment_status": booking.get("payment_status"),
                "payment_amount": booking.get("payment_amount"),
                "booking_reference": booking.get("booking_reference")
            }
            for booking in bookings
        ]
        return result
    except Exception as e:
        print(f"Error during reading bookings: {str(e)}")
        return {"error": str(e)}


# Route to get bookings by tour ID
@app.route('/booking', methods=['GET', 'POST'])
@login_required
def get_booking_by_tour_id():
    if request.method == 'POST':
        tour_id = request.form.get('tour_id')
        if not tour_id:
            return render_template("get_booking.html", error="Tour ID is required", session=session)

        bookings = read_bookings_by_tour_id(tour_id)
        if isinstance(bookings, dict) and "error" in bookings:
            return render_template("get_booking.html", error=bookings["error"], session=session)
        if not bookings:
            return render_template("get_booking.html", message="No bookings found for the provided tour ID",
                                   session=session)
        return render_template("get_booking.html", bookings=bookings, session=session)

    return render_template("get_booking.html", session=session)


# Function to read bookings by tour_id
def read_bookings_by_tour_id(tour_id):
    try:
        client.admin.command('ping')
        bookings = booking_collection.find({"tour_id": tour_id})
        result = [
            {
                "user_id": booking.get("user_id"),
                "user_email": booking.get("user_email"),
                "tour_id": booking.get("tour_id"),
                "tour_destination": booking.get("tour_destination"),
                "tour_dates": booking.get("tour_dates"),
                "booking_status": booking.get("booking_status"),
                "payment_status": booking.get("payment_status"),
                "payment_amount": booking.get("payment_amount"),
                "booking_reference": booking.get("booking_reference")
            }
            for booking in bookings
        ]
        return result
    except Exception as e:
        print(f"Error during reading bookings by tour_id: {str(e)}")
        return {"error": str(e)}
#
# Decorator to restrict access to customers
def customer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'customer':
            return render_template("error.html", error="Access denied: Only customers can view bookings", session=session), 403
        return f(*args, **kwargs)
    return decorated_function

# Route to get bookings for the logged-in customer
@app.route('/customer_view_booking', methods=['GET', 'POST'])
@login_required
@customer_required
def customer_view_booking():
    if request.method == 'POST':
        tour_id = request.form.get('tour_id')
        user_id = session.get('user_id')
        if not user_id:
            return render_template("view_booking_by_user.html", error="User ID not found in session", session=session)

        bookings = read_bookings_by_user_id(user_id, tour_id)
        if isinstance(bookings, dict) and "error" in bookings:
            return render_template("view_booking_by_user.html", error=bookings["error"], session=session)
        if not bookings:
            return render_template("view_booking_by_user.html", message="No bookings found for your account", session=session)
        return render_template("view_booking_by_user.html", bookings=bookings, session=session)

    return render_template("view_booking_by_user.html", session=session)

# Function to read bookings by user_id and optional tour_id
def read_bookings_by_user_id(user_id, tour_id=None):
    try:
        query = {"user_id": user_id}
        if tour_id and tour_id.strip():
            query["tour_id"] = tour_id.strip()

        bookings = booking_collection.find(query)
        result = [
            {
                "user_id": booking.get("user_id", ""),
                "user_email": booking.get("user_email", ""),
                "tour_id": booking.get("tour_id", ""),
                "tour_destination": booking.get("tour_destination", ""),
                "tour_dates": booking.get("tour_dates", ""),
                "booking_status": booking.get("booking_status", ""),
                "payment_status": booking.get("payment_status", ""),
                "payment_amount": booking.get("payment_amount", 0.0),
                "booking_reference": booking.get("booking_reference", "")
            }
            for booking in bookings
        ]
        return result
    except pymongo.errors.ConnectionError as e:
        print(f"Database connection error: {str(e)}")
        return {"error": "Failed to connect to the database"}
    except Exception as e:
        print(f"Error during reading bookings by user_id: {str(e)}")
        return {"error": f"Failed to retrieve bookings: {str(e)}"}

# Route to add a booking
@app.route('/add_booking', methods=['GET', 'POST'])
@login_required
def add_booking():
    if request.method == 'POST':
        booking_data = {
            "user_id": request.form.get('user_id'),
            "user_email": request.form.get('user_email'),
            "tour_id": request.form.get('tour_id'),
            "tour_destination": request.form.get('tour_destination'),
            "tour_dates": request.form.get('tour_dates'),
            "booking_status": request.form.get('booking_status'),
            "payment_status": request.form.get('payment_status'),
            "payment_amount": float(request.form.get('payment_amount')),
            "booking_reference": request.form.get('booking_reference')
        }
        required_fields = ["user_id", "user_email", "tour_id", "tour_destination", "tour_dates", "booking_status",
                           "payment_status", "payment_amount", "booking_reference"]
        for field in required_fields:
            if not booking_data[field]:
                return render_template("add_booking.html", error=f"Missing required field: {field}", session=session)
        result = insert_booking(booking_data)
        if "error" in result:
            return render_template("add_booking.html", error=result["error"], session=session)
        return render_template("add_booking.html", message=result["message"], session=session)
    return render_template("add_booking.html", session=session)

# Function to insert a new booking
def insert_booking(booking_data):
    try:
        client.admin.command('ping')
        result = booking_collection.insert_one(booking_data)
        return {"message": "Booking added successfully", "booking_reference": booking_data['booking_reference']}
    except Exception as e:
        print(f"Error during adding new booking: {str(e)}")
        return {"error": "Connection Problem"}

#
# Route to render customer booking tour page
@app.route('/customer_booking_tour', methods=['GET', 'POST'])
@login_required
def customer_booking_tour():
    # Restrict access to customers only
    if session.get('user_role') != 'customer':
        return jsonify({"message": "Access denied: Only customers can book tours"}), 403

    if request.method == 'POST':
        # Extract form data from customer_booking_tour.html
        booking_data = {
            "user_id": session.get('user_id'),
            "user_email": session.get('email', ''),
            "tour_id": request.form.get('tour_id'),
            "tour_destination": request.form.get('tour_destination'),
            "tour_dates": request.form.get('tour_dates'),
            "booking_status": "Pending",  # Default status
            "payment_status": "Initiated",  # Default payment status
            "payment_amount": float(request.form.get('payment_amount', 0)),
            "booking_reference": str(uuid.uuid4())  # Generate unique booking reference
        }

        # Validate required fields
        required_fields = ["tour_id", "tour_destination", "tour_dates", "payment_amount"]
        for field in required_fields:
            if not booking_data[field]:
                return render_template("customer_booking_tour.html", error=f"Missing required field: {field}", session=session)

        # Verify tour exists
        tour = tour_collection.find_one({"TourID": booking_data["tour_id"]})
        if not tour:
            return render_template("customer_booking_tour.html", error="Invalid Tour ID", session=session)

        # Insert booking
        result = insert_booking(booking_data)
        if "error" in result:
            return render_template("customer_booking_tour.html", error=result["error"], session=session)
        return render_template("customer_booking_tour.html", message=result["message"], session=session)

    # GET request: Render the booking form
    return render_template("customer_booking_tour.html", session=session)

# Route to delete a booking
@app.route('/delete_booking', methods=['GET', 'POST'])
@login_required
def delete_booking_by_reference():
    if request.method == 'POST':
        booking_reference = request.form.get('booking_reference')
        result = delete_booking(booking_reference)
        if "error" in result:
            return render_template("delete_booking.html", error=result["error"], session=session)
        return render_template("delete_booking.html", message=result["message"], session=session)
    return render_template("delete_booking.html", session=session)

# Function to delete a booking by booking_reference
def delete_booking(booking_reference):
    try:
        client.admin.command('ping')
        result = booking_collection.delete_one({"booking_reference": booking_reference})
        if result.deleted_count > 0:
            return {"message": f"Booking with reference {booking_reference} deleted successfully"}
        return {"message": "Booking not found"}
    except Exception as e:
        print(f"Error during deleting booking: {str(e)}")
        return {"error": "Connection Problem"}

# Route to initiate checkout session
@app.route('/checkout_session', methods=['GET', 'POST'])
@login_required
def checkout_session():
    if request.method == 'POST':
        booking_reference = request.form.get('booking_reference')
        if not booking_reference:
            return render_template("checkout_session.html", error="Booking reference is required", session=session)
        result = initiate_checkout_session(booking_reference)
        if "error" in result:
            return render_template("checkout_session.html", error=result["error"], session=session)
        if "message" in result:
            return render_template("checkout_session.html", message=result["message"], session=session)
        return render_template("checkout_session.html", checkout_session=result, session=session)
    return render_template("checkout_session.html", session=session)

# Function to initiate a checkout session
def initiate_checkout_session(booking_reference):
    try:
        client.admin.command('ping')
        booking = booking_collection.find_one({"booking_reference": booking_reference})
        if not booking:
            return {"message": "Booking not found"}
        if booking.get("payment_status") == "Paid":
            return {"message": "Payment already completed for this booking"}
        return {
            "booking_reference": booking_reference,
            "payment_amount": booking.get("payment_amount"),
            "currency": "USD",
            "payment_status": "Initiated",
            "payment_url": f"https://payment-gateway.example.com/pay/{booking_reference}"
        }
    except Exception as e:
        print(f"Error during checkout session creation: {str(e)}")
        return {"error": "Connection Problem"}

# Route to update payment status
@app.route('/update_payment', methods=['GET', 'POST'])
@login_required
def update_payment():
    if request.method == 'POST':
        booking_reference = request.form.get('booking_reference')
        result = update_payment_status(booking_reference)
        if "error" in result:
            return render_template("update_payment.html", error=result["error"], session=session)
        return render_template("update_payment.html", message=result["message"], session=session)
    return render_template("update_payment.html", session=session)

# Function to update payment status
def update_payment_status(booking_reference):
    try:
        client.admin.command('ping')
        booking = booking_collection.find_one({"booking_reference": booking_reference})
        if not booking:
            return {"message": "Booking not found"}
        if booking.get("payment_status") == "Paid":
            return {"message": "Payment is already marked as Paid"}
        booking_collection.update_one(
            {"booking_reference": booking_reference},
            {"$set": {"payment_status": "Paid", "booking_status": "Confirmed"}}
        )
        return {"message": f"Payment status updated to Paid for booking {booking_reference}"}
    except Exception as e:
        print(f"Error during updating payment status: {str(e)}")
        return {"error": "Connection Problem"}

# Review Routes
# Route to display all reviews
@app.route("/reviews", methods=['GET'])
@login_required
def all_reviews():
    return render_template('all_reviews.html', session=session)

# Route to display reviews by user
@app.route("/user_reviews", methods=['GET'])
@login_required
def user_reviews():
    return render_template('user_reviews.html', session=session)

# Route to add a new review
@app.route("/add_review", methods=['GET'])
@login_required
def add_review_page():
    return render_template('add_review.html', session=session)

# Route to update a review
@app.route("/update_review", methods=['GET'])
@login_required
def update_review_page():
    return render_template('update_review.html', session=session)

# Route to delete a review
@app.route("/delete_review", methods=['GET'])
@login_required
def delete_review_page():
    return render_template('delete_review.html', session=session)

# API to get all reviews
@app.route('/api/reviews', methods=['GET'])
@login_required
def get_reviews():
    return jsonify(read_reviews()), 200

# Function to read all review data
def read_reviews():
    try:
        client.admin.command('ping')
        reviews = review_collection.find()
        return [
            {
                "review_id": review.get("review_id"),
                "user_id": review.get("user_id"),
                "user_email": review.get("user_email"),
                "tour_id": review.get("tour_id"),
                "tour_destination": review.get("tour_destination"),
                "rating": review.get("rating"),
                "review_text": review.get("review_text"),
                "review_date": review.get("review_date")
            }
            for review in reviews
        ]
    except Exception as e:
        print(f"Error during reading reviews: {str(e)}")
        return []

# API to get reviews by user_id
@app.route('/api/reviews/user/<user_id>', methods=['GET'])
@login_required
def get_reviews_user(user_id):
    return jsonify(get_reviews_byuser(user_id)), 200

# Function to read reviews by user_id
def get_reviews_byuser(user_id):
    try:
        client.admin.command('ping')
        reviews = review_collection.find({"user_id": user_id})
        return [
            {
                "review_id": review.get("review_id"),
                "user_id": review.get("user_id"),
                "user_email": review.get("user_email"),
                "tour_id": review.get("tour_id"),
                "tour_destination": review.get("tour_destination"),
                "rating": review.get("rating"),
                "review_text": review.get("review_text"),
                "review_date": review.get("review_date")
            }
            for review in reviews
        ]
    except Exception as e:
        print(f"Error during getting reviews by user: {str(e)}")
        return []

#
# User API route for user purpose
@app.route('/api/user/review/add', methods=['POST'])
@login_required
def insert_user_review():
    data = request.json
    result, status = add_review_user(data)
    return jsonify(result), status

# User function
def add_review_user(review_data):
    try:
        client.admin.command('ping')
        review_data['timestamp'] = datetime.utcnow()
        review_collection.insert_one(review_data)
        return {"message": "User review added successfully"}, 201
    except Exception as e:
        print(f"Error in user review: {str(e)}")
        return {"message": "Connection Problem"}, 500

# User review form page route
@app.route("/add_review_by_user", methods=['GET'])
@login_required
def add_review_by_user_page():
    return render_template('add_review_by_user.html', session=session)

# API to add review data
@app.route('/api/review/add', methods=['POST'])
@login_required
def insert_review():
    data = request.json
    result, status = add_review(data)
    return jsonify(result), status

# Function to add a review data
def add_review(review_data):
    try:
        client.admin.command('ping')
        review_collection.insert_one(review_data)
        return {"message": "Review added successfully"}, 201
    except Exception as e:
        print(f"Error during adding review: {str(e)}")
        return {"message": "Connection Problem"}, 500

# API to delete review by id
@app.route('/api/review/delete/<review_id>', methods=['DELETE'])
@login_required
def remove_review(review_id):
    result, status = delete_review(review_id)
    return jsonify(result), status

# Function to delete review by review_id
def delete_review(review_id):
    try:
        client.admin.command('ping')
        result = review_collection.delete_one({"review_id": review_id})
        if result.deleted_count > 0:
            return {"message": "Review deleted successfully"}, 200
        return {"message": "Review not found"}, 404
    except Exception as e:
        print(f"Error during deleting review: {str(e)}")
        return {"message": "Connection Problem"}, 500

# API to update review by review_id
@app.route('/api/review/update/<review_id>', methods=['PATCH'])
@login_required
def edit_review(review_id):
    data = request.json
    result, status = update_review(review_id, data)
    return jsonify(result), status

# Function to update review by review_id
def update_review(review_id, updated_data):
    try:
        client.admin.command('ping')
        allowed_fields = {"rating", "review_text"}
        update_fields = {k: v for k, v in updated_data.items() if k in allowed_fields}
        if not update_fields:
            return {"message": "No valid fields to update"}, 400
        result = review_collection.update_one(
            {"review_id": review_id},
            {"$set": update_fields}
        )
        if result.matched_count > 0:
            return {"message": "Review updated successfully"}, 200
        return {"message": "Review not found"}, 404
    except Exception as e:
        print(f"Error during updating review: {str(e)}")
        return {"message": "Connection Problem"}, 500

# Route to serve about page
@app.route("/about", methods=['GET'])
@login_required
def about_page():
    return render_template('About_Page.html', session=session)

# Prevent caching of protected pages
@app.after_request
def add_no_cache_headers(response):
    if request.path not in ['/login', '/signup', '/favicon.ico', '/api/signup', '/api/reset_password_request', '/api/reset_password']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 3000)))