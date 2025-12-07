"""
app.py - RickXpress (Flask + SQLAlchemy + Flask-Login)

How to run (quick):
1. python -m venv venv
2. venv\\Scripts\\activate     # Windows
   source venv/bin/activate   # Linux / macOS
3. pip install -r requirements.txt
4. python app.py

This file creates an SQLite DB: instance/RickXpress.db
"""

import os
from datetime import datetime

from flask import (
    Flask, render_template, redirect, url_for, flash,
    request, abort, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user, login_required,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash

# -----------------------
# App + Config
# -----------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance")
if not os.path.exists(DB_PATH):
    os.makedirs(DB_PATH)

app = Flask(__name__, instance_relative_config=False)
app.config["SECRET_KEY"] = os.environ.get("RickXpress_SECRET", "dev-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(DB_PATH, "RickXpress.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# -----------------------
# Models
# -----------------------
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=True)  # optional
    phone = db.Column(db.String(32), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="customer")  # customer, rider, admin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_rider_requested = db.Column(db.Boolean, default=False)

    # relationships
    vehicles = db.relationship("Vehicle", backref="owner", lazy="dynamic")

    rides_as_customer = db.relationship(
        "Ride",
        foreign_keys="Ride.customer_id",
        backref="customer_rel",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )
    rides_as_driver = db.relationship(
        "Ride",
        foreign_keys="Ride.driver_id",
        backref="driver_rel",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def get_display_name(self):
        return self.full_name or self.phone


class Vehicle(db.Model):
    __tablename__ = "vehicles"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    vehicle_type = db.Column(db.String(80), nullable=False)
    other_vehicle_type = db.Column(db.String(120), nullable=True)
    vehicle_number = db.Column(db.String(32), nullable=False)
    model = db.Column(db.String(120), nullable=True)
    color = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default="Active")  # Active / Inactive
    driver_location = db.Column(db.String(200), nullable=True)  # where the driver stays / base
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def display_type(self):
        if self.vehicle_type and self.vehicle_type.lower() == "other":
            return self.other_vehicle_type or "Other"
        return self.vehicle_type


class Booking(db.Model):
    __tablename__ = "bookings"

    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicles.id"), nullable=False)

    # driver assigned (owner of the vehicle) - stored for quick access and rider dashboard
    driver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    pickup = db.Column(db.String(200), nullable=False)
    drop = db.Column(db.String(200), nullable=False)

    distance_km = db.Column(db.Float, nullable=True)
    fare_amount = db.Column(db.Float, nullable=True)

    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # relationships
    customer = db.relationship("User", backref="bookings_customer", foreign_keys=[customer_id])
    vehicle = db.relationship("Vehicle", backref="bookings_vehicle")
    driver = db.relationship("User", foreign_keys=[driver_id], backref="bookings_driver")


class Ride(db.Model):
    __tablename__ = "rides"
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    driver_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    from_location = db.Column(db.String(255), nullable=False)
    to_location = db.Column(db.String(255), nullable=False)
    fare_estimate = db.Column(db.Float, nullable=True)
    status = db.Column(db.String(32), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PublicRideRequest(db.Model):
    __tablename__ = "public_ride_requests"

    id = db.Column(db.Integer, primary_key=True)

    customer_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    from_location = db.Column(db.String(200), nullable=False)
    to_location = db.Column(db.String(200), nullable=False)

    offer_fare = db.Column(db.Float, nullable=False)
    date = db.Column(db.String(20), nullable=False)
    time = db.Column(db.String(20), nullable=False)

    vehicle_type = db.Column(db.String(100), nullable=True)
    seats = db.Column(db.Integer, nullable=True)

    status = db.Column(db.String(20), default="Open")
    # Open, Accepted, Completed, Cancelled

    accepted_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    customer = db.relationship("User", foreign_keys=[customer_id])
    rider = db.relationship("User", foreign_keys=[accepted_by])


# -----------------------
# Login manager
# -----------------------
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


# -----------------------
# Helper: create DB + sample data
# -----------------------
def create_sample_data():
    """Create tables and a sample user if DB empty."""
    db.create_all()
    if User.query.count() == 0:
        admin = User(full_name="Admin User", username="admin", phone="+919999999999", email="admin@RickXpress.local", role="admin")
        admin.set_password("adminpass")
        rider = User(full_name="Test Driver", username="testD", phone="+919800000001", email="test@RickXpress.local", role="rider")
        rider.set_password("riderpass")
        customer = User(full_name="Test Customer", username="cust", phone="+919700000002", email="cust@RickXpress.local", role="customer")
        customer.set_password("custpass")

        db.session.add_all([admin, rider, customer])
        db.session.commit()

        # add a vehicle for rider (with driver_location populated)
        v = Vehicle(
            owner_id=rider.id,
            vehicle_type="Auto Rickshaw",
            other_vehicle_type=None,
            vehicle_number="MH-08-1234",
            model="Piaggio",
            color="Yellow",
            status="Active",
            driver_location="Dapoli"
        )
        db.session.add(v)
        db.session.commit()
        print("Sample data created: admin/rider/customer")


# -----------------------
# Routes (matching templates)
# -----------------------

@app.route("/")
def home():
    # index.html contains the search form that GETs /rides?pickup=...&drop=...
    return render_template("index.html")


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        message = request.form.get("message")
        flash(f"Thanks, {name or 'there'} — we received your message.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")


# -----------------------
# Auth: register / login / logout
# -----------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        full_name = request.form.get("name")
        username = request.form.get("username") or None
        phone = request.form.get("phone")
        email = request.form.get("email") or None
        password = request.form.get("password")
        is_rider = True if request.form.get("is_rider") else False

        if not phone or not password or not full_name:
            flash("Please fill required fields", "danger")
            return redirect(url_for("register"))

        # -------- FIXED DUPLICATE CHECK --------
        filters = [User.phone == phone]

        if email:
            filters.append(User.email == email)

        if username:
            filters.append(User.username == username)

        existing = User.query.filter(db.or_(*filters)).first()

        if existing:
            flash("User with that phone/email/username already exists", "warning")
            return redirect(url_for("register"))
        # ----------------------------------------

        role = "customer"

        user = User(
            full_name=full_name,
            username=username,
            phone=phone,
            email=email,
            role=role,
            is_rider_requested=is_rider
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)

        session["dashboard_mode"] = "customer"

        flash(f"Account created. Welcome, {user.get_display_name()}!", "success")
        return redirect(url_for("dashboard"))

    return render_template("signup.html")

@app.route("/request_rider", methods=["POST"])
@login_required
def request_rider():
    if current_user.role != "customer":
        flash("You are already a rider or admin.", "info")
        return redirect(url_for('profile'))
    else:
        current_user.is_rider_requested = True
        db.session.commit()
        db.session.refresh(current_user)

        flash("Rider request submitted. Admin will review soon.", "success")
    return redirect(url_for("profile"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        identifier = (request.form.get("identifier") or "").strip()
        password = request.form.get("password")
        if not identifier or not password:
            flash("Please provide identifier and password", "danger")
            return redirect(url_for("login"))

        # Match using OR across allowed fields
        user = User.query.filter(
            (User.phone == identifier) |
            (User.email == identifier) |
            (User.username == identifier) |
            (User.full_name == identifier)
        ).first()

        if user and user.check_password(password):
            login_user(user)
            # set a sensible default dashboard mode for this user
            if user.role == "admin":
                session["dashboard_mode"] = "admin"  # admin can switch later
            elif user.role == "rider":
                session["dashboard_mode"] = "customer"  # start in customer mode, rider can switch
            else:
                session["dashboard_mode"] = "customer"

            flash("Welcome back, {}".format(user.get_display_name()), "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard"))

        flash("Invalid credentials", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    # remove dashboard mode from session so next user doesn't inherit it
    session.pop("dashboard_mode", None)
    logout_user()
    flash("Logged out", "info")
    return redirect(url_for("login"))


# -----------------------
# Dashboard / Profile
# -----------------------
@app.route("/dashboard")
@login_required
def dashboard():
    # determine dashboard mode
    mode = session.get("dashboard_mode")
    if not mode:
        # default mode based on role
        if current_user.role == "admin":
            mode = "customer"
        elif current_user.role == "rider":
            mode = "customer"
        else:
            mode = "customer"
        session["dashboard_mode"] = mode

    # minimal current ride example
    current_ride = None
    ride = Ride.query.filter_by(customer_id=current_user.id, status="Pending").first()
    if ride:
        current_ride = {
            "driver": ride.driver_rel.get_display_name() if ride.driver_rel else "Not assigned",
            "vehicle": ride.driver_rel.vehicles.first().display_type() if ride.driver_rel and ride.driver_rel.vehicles.count() else "N/A",
            "fare": ride.fare_estimate or 0,
            "status": ride.status
        }

    # prepare rider requests if applicable
    rider_requests = []
    if current_user.role in ("rider", "admin"):
        # if rider mode is active or admin wants to see rider panel, show pending requests
        if session.get("dashboard_mode") == "rider" or current_user.role == "admin":
            # riders see bookings where they are the driver and status is Pending
            rider_requests = Booking.query.filter_by(driver_id=current_user.id, status="Pending").order_by(Booking.created_at.desc()).all()

    # prepare customer bookings for customer panel
    customer_bookings = Booking.query.filter_by(customer_id=current_user.id).order_by(Booking.created_at.desc()).all()

    # ADMIN STAT CARDS
    admin_stats = {}
    if current_user.role == "admin":

        admin_stats = {
            "total_users": User.query.count(),
            "total_riders": User.query.filter_by(role="rider").count(),
            "total_vehicles": Vehicle.query.count(),
            "total_bookings": Booking.query.count(),
            "pending_bookings": Booking.query.filter_by(status="Pending").count(),
            "completed_bookings": Booking.query.filter_by(status="Completed").count(),
            "today_bookings": Booking.query.filter(
                db.func.date(Booking.created_at) == datetime.utcnow().date()
            ).count(),
        }

        # If you have PublicRideRequest model:
        try:
            admin_stats["public_requests"] = PublicRideRequest.query.count()
        except:
            admin_stats["public_requests"] = 0
            
        rider_requests = User.query.filter_by(
            role="customer", 
            is_rider_requested=True
        ).all()

            
            
    return render_template(
        "dashboard.html",
        current_ride=current_ride,
        history=[],  # legacy
        rider_requests=rider_requests,
        customer_bookings=customer_bookings,
        admin_stats=admin_stats
    )


@app.route("/dashboard/set/<mode>")
@login_required
def set_mode(mode):
    allowed_modes = ["customer"]
    if current_user.role == "rider":
        allowed_modes = ["customer", "rider"]
    if current_user.role == "admin":
        allowed_modes = ["customer", "rider", "admin"]
    if mode not in allowed_modes:
        abort(403)
    session["dashboard_mode"] = mode
    return redirect(url_for("dashboard"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_user.full_name = request.form.get("name") or current_user.full_name
        current_user.phone = request.form.get("phone") or current_user.phone
        current_user.email = request.form.get("email") or current_user.email
        current_user.username = request.form.get("username") or current_user.username
        db.session.commit()
        flash("Profile updated", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html")


# -----------------------
# Rides + Search (index -> /rides?pickup=...&drop=...)
# -----------------------
@app.route("/rides")
def rides():
    """
    Search active vehicles by driver_location (partial match, case-insensitive).
    If pickup provided and no matches, fall back to showing all active vehicles.
    """
    pickup = (request.args.get("pickup") or "").strip()
    drop = (request.args.get("drop") or "").strip()

    q = Vehicle.query.filter_by(status="Active")

    if pickup:
        like = f"%{pickup}%"
        try:
            q = q.filter(Vehicle.driver_location.ilike(like))
        except Exception:
            # some DB backends might not support ilike; ignore filter in that case
            q = q.filter(Vehicle.driver_location != None)

    vehicles = q.order_by(Vehicle.id.desc()).all()

    # fallback: if user asked a pickup but there were no matches, show all active vehicles
    if pickup and len(vehicles) == 0:
        vehicles = Vehicle.query.filter_by(status="Active").order_by(Vehicle.id.desc()).all()

    return render_template("rides.html", vehicles=vehicles, pickup=pickup, drop=drop)

@app.route("/ride/request/new", methods=["GET", "POST"])
@login_required
def post_public_ride():

    if current_user.role not in ["customer", "rider", "admin"]:
        abort(403)

    if request.method == "POST":
        req = PublicRideRequest(
            customer_id=current_user.id,
            from_location=request.form.get("from_location"),
            to_location=request.form.get("to_location"),
            offer_fare=float(request.form.get("fare")),
            date=request.form.get("date"),
            time=request.form.get("time"),
            vehicle_type=request.form.get("vehicle_type"),
            seats=int(request.form.get("seats") or 0),

        )

        db.session.add(req)
        db.session.commit()

        flash("Your ride request is now public!", "success")
        return redirect(url_for("rides"))

    return render_template("public_ride_form.html")

@app.route("/rider/public_requests")
@login_required
def public_requests():

    if current_user.role not in ["rider", "admin"]:
        abort(403)

    requests = PublicRideRequest.query.filter_by(status="Open").order_by(PublicRideRequest.id.desc()).all()

    return render_template("public_requests.html", requests=requests)

@app.route("/rider/public_request/<int:req_id>/accept")
@login_required
def accept_public_ride(req_id):

    if current_user.role not in ["rider", "admin"]:
        abort(403)

    req = PublicRideRequest.query.get_or_404(req_id)

    if req.status != "Open":
        flash("This request is already accepted.", "warning")
        return redirect(url_for("public_requests"))

    req.status = "Accepted"
    req.accepted_by = current_user.id
    db.session.commit()

    flash("You accepted this ride request.", "success")
    return redirect(url_for("public_requests"))

@app.route("/rider/accepted_rides")
@login_required
def rider_accepted_rides():

    if current_user.role not in ["rider", "admin"]:
        abort(403)

    rides = PublicRideRequest.query.filter_by(
        accepted_by=current_user.id
    ).order_by(PublicRideRequest.id.desc()).all()

    return render_template("rider_accepted_rides.html", rides=rides)

@app.route("/rider/completed_rides")
@login_required
def rider_completed_rides():

    if current_user.role not in ["rider", "admin"]:
        abort(403)

    rides = PublicRideRequest.query.filter_by(
        accepted_by=current_user.id,
        status="Completed"
    ).all()

    return render_template("rider_completed_rides.html", rides=rides)


@app.route("/vehicle/<int:vehicle_id>")
def vehicle_details(vehicle_id):
    """
    Show vehicle & owner details and booking form.
    """
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    owner = vehicle.owner  # relationship
    return render_template("ride_details.html", vehicle=vehicle, owner=owner)


# -----------------------
# Booking flow (simple)
# -----------------------
@app.route("/book_vehicle", methods=["POST"])
@login_required
def book_vehicle():
    """
    Handler for booking from the vehicle details page.
    Form fields: vehicle_id, pickup, drop
    Creates a Booking (status=Pending) and redirects to booking_status.
    """
    vehicle_id = request.form.get("vehicle_id")
    pickup = request.form.get("pickup")
    drop = request.form.get("drop")

    if not vehicle_id or not pickup or not drop:
        flash("Please provide pickup, drop and vehicle selection.", "danger")
        return redirect(url_for("rides"))

    vehicle = Vehicle.query.get_or_404(vehicle_id)

    booking = Booking(
        customer_id=current_user.id,
        vehicle_id=vehicle.id,
        driver_id=vehicle.owner_id,  # assign driver (owner of vehicle) for rider requests
        pickup=pickup,
        drop=drop,
        distance_km=None,
        fare_amount=None,
        status="Pending"
    )
    db.session.add(booking)
    db.session.commit()

    # after creating booking, redirect to booking status page which shows contact numbers
    return redirect(url_for("booking_status", booking_id=booking.id))


@app.route("/booking/<int:booking_id>")
@login_required
def booking_status(booking_id):
    booking = Booking.query.get_or_404(booking_id)

    # permissions:
    # - admin
    # - customer who booked
    # - rider who owns the vehicle (driver)
    allowed = False
    if current_user.role == "admin":
        allowed = True
    elif booking.customer_id == current_user.id:
        allowed = True
    elif current_user.role == "rider" and booking.driver_id == current_user.id:
        allowed = True

    if not allowed:
        abort(403)

    driver = booking.vehicle.owner
    customer = booking.customer
    return render_template("booking_status.html", booking=booking, driver=driver, customer=customer)


@app.route("/booking_history")
@login_required
def booking_history():
    bookings = Booking.query.filter_by(customer_id=current_user.id).order_by(Booking.created_at.desc()).all()
    public_requests = PublicRideRequest.query.filter_by(customer_id=current_user.id).order_by(PublicRideRequest.created_at.desc()).all()
    return render_template("booking_history.html", bookings=bookings, public_requests=public_requests)


# -----------------------
# Rider actions: Accept / Reject requests
# -----------------------
@app.route("/booking/<int:booking_id>/accept", methods=["POST", "GET"])
@login_required
def booking_accept(booking_id):
    b = Booking.query.get_or_404(booking_id)
    if current_user.role != "rider" or b.driver_id != current_user.id:
        abort(403)
    b.status = "Accepted"
    db.session.commit()
    flash("Ride accepted!", "success")
    return redirect(url_for("dashboard"))


@app.route("/booking/<int:booking_id>/reject", methods=["POST", "GET"])
@login_required
def booking_reject(booking_id):
    b = Booking.query.get_or_404(booking_id)
    if current_user.role != "rider" or b.driver_id != current_user.id:
        abort(403)
    b.status = "Rejected"
    db.session.commit()
    flash("Ride rejected!", "info")
    return redirect(url_for("dashboard"))


@app.route("/rider/requests")
@login_required
def rider_requests():

    if current_user.role not in ["rider", "admin"]:
        abort(403)

    # Fetch bookings where the vehicle belongs to this rider
    bookings = (
        Booking.query
        .join(Vehicle, Booking.vehicle_id == Vehicle.id)
        .filter(Vehicle.owner_id == current_user.id)
        .order_by(Booking.id.desc())
        .all()
    )

    return render_template("rider_requests.html", bookings=bookings)

@app.route("/rider/booking/<int:booking_id>/accept")
@login_required
def rider_accept_booking(booking_id):

    if current_user.role not in ["rider", "admin"]:
        abort(403)

    booking = Booking.query.get_or_404(booking_id)

    # Check rider owns the vehicle
    if booking.vehicle.owner_id != current_user.id:
        abort(403)

    booking.status = "Accepted"
    booking.updated_at = datetime.utcnow()
    db.session.commit()

    flash("Booking accepted!", "success")
    return redirect(url_for("rider_requests"))

@app.route("/rider/booking/<int:booking_id>/reject")
@login_required
def rider_reject_booking(booking_id):

    if current_user.role not in ["rider", "admin"]:
        abort(403)

    booking = Booking.query.get_or_404(booking_id)

    # Check rider owns the vehicle
    if booking.vehicle.owner_id != current_user.id:
        abort(403)

    booking.status = "Rejected"
    booking.updated_at = datetime.utcnow()
    db.session.commit()

    flash("Booking rejected.", "info")
    return redirect(url_for("rider_requests"))


# -----------------------
# Vehicle management (rider/admin only) - keep existing handlers
# -----------------------
def rider_or_admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.role not in ("rider", "admin"):
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


@app.route("/vehicles")
@login_required
def vehicle_management():
    vehicles = Vehicle.query.filter_by(owner_id=current_user.id).order_by(Vehicle.id.desc()).all()
    return render_template("vehicle_management.html", vehicles=vehicles)


@app.route("/vehicle/add", methods=["GET", "POST"])
@login_required
def vehicle_add():
    # only admins and riders can add vehicles
    if current_user.role not in ["admin", "rider"]:
        abort(403)

    owners = []
    if current_user.role == "admin":
        owners = User.query.filter(User.role.in_(["rider", "admin"])).all()

    if request.method == "POST":
        v = Vehicle(
            owner_id=request.form.get("owner_id") if current_user.role == "admin" else current_user.id,
            vehicle_type=request.form.get("vehicle_type"),
            other_vehicle_type=request.form.get("other_vehicle_type"),
            vehicle_number=request.form.get("vehicle_number"),
            model=request.form.get("model"),
            color=request.form.get("color"),
            status=request.form.get("status") or "Active",
            driver_location=request.form.get("driver_location")
        )
        db.session.add(v)
        db.session.commit()
        flash("Vehicle added successfully!", "success")
        return redirect(url_for("vehicle_management"))

    return render_template("vehicle_add.html", owners=owners)


@app.route("/vehicle/<int:vehicle_id>/edit", methods=["GET", "POST"])
@login_required
def vehicle_edit(vehicle_id):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    if current_user.role == "rider" and vehicle.owner_id != current_user.id:
        abort(403)

    owners = []
    if current_user.role == "admin":
        owners = User.query.filter(User.role.in_(["rider", "admin"])).all()

    if request.method == "POST":
        vehicle.vehicle_type = request.form.get("vehicle_type")
        vehicle.other_vehicle_type = request.form.get("other_vehicle_type")
        vehicle.vehicle_number = request.form.get("vehicle_number")
        vehicle.model = request.form.get("model")
        vehicle.color = request.form.get("color")
        vehicle.status = request.form.get("status")
        vehicle.driver_location = request.form.get("driver_location")
        if current_user.role == "admin":
            vehicle.owner_id = request.form.get("owner_id")
        db.session.commit()
        flash("Vehicle updated successfully!", "success")
        return redirect(url_for("vehicle_management"))

    return render_template("vehicle_details.html", vehicle=vehicle, owners=owners)


@app.route("/vehicle/<int:id>/delete", methods=["POST", "GET"])
@login_required
@rider_or_admin_required
def delete_vehicle(id):
    v = Vehicle.query.get_or_404(id)
    if current_user.role == "rider" and v.owner_id != current_user.id:
        abort(403)
    db.session.delete(v)
    db.session.commit()
    flash("Vehicle deleted", "info")
    return redirect(url_for("vehicle_management"))


@app.route("/vehicle/<int:vehicle_id>/status/<status>")
@login_required
def vehicle_set_status(vehicle_id, status):
    vehicle = Vehicle.query.get_or_404(vehicle_id)
    if current_user.role == "rider" and vehicle.owner_id != current_user.id:
        abort(403)
    vehicle.status = status
    db.session.commit()
    flash("Status updated successfully!", "success")
    return redirect(url_for("vehicle_management"))


# -----------------------
# Utilities
# -----------------------
@app.context_processor
def inject_current_year():
    return {"current_year": datetime.utcnow().year}


# -----------------------
# Error handlers
# -----------------------
@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

# -----------------------------------
# ADMIN PANEL ROUTES
# -----------------------------------

def admin_only():
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    if current_user.role != "admin":
        abort(403)


# -------------------------------
# ADMIN: USERS LIST
# -------------------------------
@app.route("/admin/users")
@login_required
def admin_users():
    admin_only()

    users = User.query.order_by(User.id.desc()).all()
    return render_template("admin/users.html", users=users)

@app.route("/admin/make_rider/<int:user_id>")
@login_required
def admin_make_rider(user_id):
    if current_user.role != "admin":
        abort(403)

    user = User.query.get_or_404(user_id)
    user.role = "rider"
    db.session.commit()

    flash(f"{user.full_name} is now a Rider!", "success")
    return redirect(url_for("admin_users"))

@app.route("/admin/remove_rider/<int:user_id>")
@login_required
def admin_remove_rider(user_id):
    if current_user.role != "admin":
        abort(403)

    user = User.query.get_or_404(user_id)
    user.role = "customer"
    db.session.commit()

    flash(f"{user.full_name} is now Customer only.", "info")
    return redirect(url_for("admin_users"))

# -------------------------------
# ADMIN: VEHICLES LIST
# -------------------------------
@app.route("/admin/vehicles")
@login_required
def admin_vehicles():
    admin_only()

    vehicles = Vehicle.query.order_by(Vehicle.id.desc()).all()
    return render_template("admin/vehicles.html", vehicles=vehicles)


# -------------------------------
# ADMIN: BOOKINGS LIST
# -------------------------------
@app.route("/admin/bookings")
@login_required
def admin_bookings():
    admin_only()

    bookings = (
        Booking.query.order_by(Booking.id.desc())
        .all()
    )
    return render_template("admin/bookings.html", bookings=bookings)


# -------------------------------
# ADMIN: PUBLIC RIDE REQUESTS
# -------------------------------
@app.route("/admin/public_requests")
@login_required
def admin_public_requests():
    admin_only()

    requests = (
        PublicRideRequest.query.order_by(PublicRideRequest.id.desc())
        .all()
    )
    return render_template("admin/public_requests.html", requests=requests)


# -----------------------
# Run
# -----------------------
if __name__ == "__main__":
    # Ensure DB is created within app context
    with app.app_context():
        create_sample_data()
    app.run(debug=True)
