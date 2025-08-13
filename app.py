from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SECRET_KEY'] = 'ChandraMontgomeryHarris' 
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Medication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    generic_name = db.Column(db.String(100), nullable=False)
    brand_name = db.Column(db.String(100))
    indication = db.Column(db.Text)
    side_effects = db.Column(db.Text)

class Calculation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    problem = db.Column(db.Text)
    solution = db.Column(db.Text)

class Law(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    summary = db.Column(db.Text)

# --- User Loader for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes (Website Pages) ---

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.')
            return redirect(url_for('register'))
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    meds = Medication.query.order_by(Medication.generic_name).limit(5).all()
    calculations = Calculation.query.order_by(Calculation.title).limit(5).all()
    laws = Law.query.order_by(Law.title).limit(5).all()
    return render_template('dashboard.html', medications=meds, calculations=calculations, laws=laws)

@app.route('/medications')
@login_required
def medications():
    all_meds = Medication.query.all()
    return render_template('medications.html', medications=all_meds)

@app.route('/calculations')
@login_required
def calculations():
    all_calcs = Calculation.query.all()
    return render_template('calculations.html', calculations=all_calcs)

@app.route('/laws')
@login_required
def laws():
    all_laws = Law.query.all()
    return render_template('laws.html', laws=all_laws)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Add some initial data if the tables are empty
        if not Medication.query.first():
            db.session.add(Medication(generic_name='Lisinopril', brand_name='Zestril', indication='Treats high blood pressure and heart failure.'))
            db.session.add(Medication(generic_name='Levothyroxine', brand_name='Synthroid', indication='Treats an underactive thyroid gland.'))
            db.session.commit()
        if not Calculation.query.first():
            db.session.add(Calculation(title='Ratio Strength', problem='How many grams of boric acid are needed to make 120 mL of a 2% solution?', solution='2% = 2g/100mL. (2g / 100mL) * 120mL = 2.4g'))
            db.session.commit()
        if not Law.query.first():
            db.session.add(Law(title='HIPAA', summary='The Health Insurance Portability and Accountability Act sets standards for protecting sensitive patient data.'))
            db.session.commit()
            
    app.run(debug=True)
