from flask import Flask, render_template, redirect, url_for, flash, request, session, Response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, HiddenField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import csv
from io import StringIO
from collections import defaultdict


application = Flask(__name__)



application.config["SECRET_KEY"] = "your-secret-key"
"""
def get_secret():
    secret_name = "db/secret"  # Replace with your secret name
    region_name = "us-east-1"  # Replace with your region

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        response = client.get_secret_value(SecretId=secret_name)
    except Exception as e:
        print("Failed to fetch secret:", e)
        raise e

    secret = json.loads(response['SecretString'])
    return secret

# Get credentials from Secrets Manager
creds = get_secret()
user = creds['username']
password = creds['password']
host = creds['host']
port = creds['port']
dbname = creds['dbname']
print("Hello this is Database Name:", dbname)

application.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{user}:{password}@{host}:{port}/{dbname}'
"""
application.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres1234@database-3.cal68me0ewga.us-east-1.rds.amazonaws.com:5432/database3'
application.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(application)

# --- Models ---

class Transaction(db.Model):
    __tablename__ = 'transaction'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)
    transaction_type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    users_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # automatische Zeit






class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.Text, nullable=False)


# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class TransactionForm(FlaskForm):
    csrf_token = HiddenField()

# --- Routes ---
@application.route('/register', methods=["GET", "POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash("Email already registered.", "warning")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(form.password.data)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@application.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            session['user_id'] = user.id  # Store user ID in session
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "danger")
    return render_template('login.html', form=form)

@application.route('/delete_transaction/<int:txn_id>', methods=['POST'])
def delete_transaction(txn_id):
    user_id = session.get('user_id')
    txn = Transaction.query.filter_by(id=txn_id, users_id=user_id).first()

    if txn:
        db.session.delete(txn)
        db.session.commit()
        flash('Transaction deleted successfully.', 'success')
    else:
        flash('Transaction not found or unauthorized.', 'danger')

    return redirect(url_for('dashboard'))

@application.route('/edit_transaction/<int:txn_id>', methods=['GET', 'POST'])
def edit_transaction(txn_id):
    user_id = session.get('user_id')
    txn = Transaction.query.filter_by(id=txn_id, users_id=user_id).first()

    if not txn:
        flash('Transaction not found or unauthorized.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        txn.category = request.form.get('category')
        txn.transaction_type = request.form.get('transaction_type')
        txn.amount = float(request.form.get('amount'))
        db.session.commit()
        flash('Transaction updated successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('edit_transaction.html', txn=txn)




@application.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("You need to log in first.", "warning")
        return redirect(url_for('login'))

    return render_template("dashboard.html")

@application.route('/charts')
def charts():
    user_id = session.get('user_id')
    if not user_id:
        flash("Please log in first.", "danger")
        return redirect(url_for('login'))

    selected_category = request.args.get('category')
    print(selected_category, user_id )
    if selected_category:
        transactions = Transaction.query.filter_by(users_id=user_id, category=selected_category).all()
    else:
        transactions = Transaction.query.filter_by(users_id=user_id).all()

    return render_template('charts.html', transactions=transactions, selected_category=selected_category)



@application.route('/input', methods=['GET', 'POST'])
def input_data():
    form = TransactionForm()

    if request.method == 'POST' and form.validate_on_submit():
        category = request.form.get('category')
        transaction_type = request.form.get('transaction_type')
        amount = request.form.get('amount')
        users_id = session['user_id']

        if not (category and transaction_type and amount):
            flash("Please fill in all fields.", "danger")
            return redirect(url_for('input_data'))

        try:
            amount = float(amount)
            new_transaction = Transaction(category=category, transaction_type=transaction_type, amount=amount, users_id=users_id)
            db.session.add(new_transaction)
            db.session.commit()
            flash("Transaction added successfully.", "success")
            return redirect(url_for('dashboard'))

        except ValueError:
            flash("Invalid amount.", "danger")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")

        return redirect(url_for('input_data'))

    return render_template('input_data.html', form=form)
@application.route('/')
def home():
    return render_template("home.html")

@application.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user from session
    flash("You have been logged out.", "info")
    return redirect(url_for('home'))


@application.route('/download_csv')
def download_csv():
    user_id = session.get('user_id')
    if not user_id:
        flash('Bitte einloggen, um Daten herunterzuladen.', 'warning')
        return redirect(url_for('login'))

    selected_category = request.args.get('category')

    query = Transaction.query.filter_by(users_id=user_id)
    if selected_category:
        query = query.filter_by(category=selected_category)

    transactions = query.all()

    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Category', 'Type', 'Amount (€)'])
    for txn in transactions:
        cw.writerow([txn.category, txn.transaction_type, f"{txn.amount:.2f}"])

    output = Response(si.getvalue(), mimetype='text/csv')
    output.headers['Content-Disposition'] = 'attachment; filename=transactions.csv'
    return output


@application.route("/stats")
def stats():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    transaction_type = request.args.get("type", default="Ausgaben")

    data = (
        db.session.query(Transaction.category, db.func.sum(Transaction.amount))
        .filter(Transaction.users_id == user_id)
        .filter(Transaction.transaction_type == transaction_type)
        .group_by(Transaction.category)
        .all()
    )
    chart_data = {category: amount for category, amount in data}

    transactions = db.session.query(
        Transaction.category,
        Transaction.amount,
        Transaction.created_at
    ).filter_by(transaction_type=transaction_type).all()

    time_series_data = defaultdict(lambda: defaultdict(float))

    for category, amount, created_at in transactions:
        month_str = created_at.strftime('%Y-%m')
        time_series_data[category][month_str] += amount

    transactions_all = db.session.query(
        Transaction.category,
        Transaction.amount,
        Transaction.created_at,
        Transaction.transaction_type
    ).all()

    inflow = sum(t.amount for t in transactions_all if t.transaction_type == 'Zuflüsse')
    expense = sum(t.amount for t in transactions_all if t.transaction_type == 'Ausgaben')
    net_balance = round(inflow - expense, 2)

    return render_template("stats.html", chart_data=chart_data, selected_type=transaction_type, time_series_data=time_series_data, net_balance=net_balance)

# Create tables if not already created
with application.app_context():
    db.create_all()

if __name__ == '__main__':
    application.run(debug=True)
