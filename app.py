from flask import Flask, render_template, redirect, url_for, request, session
from flask_mysqldb import MySQL
import hashlib
import csv
from io import StringIO
from flask import Response
from flask_socketio import SocketIO, emit, join_room, leave_room

from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'  # Default MySQL username in XAMPP is 'root'
app.config['MYSQL_PASSWORD'] = ''  # Default MySQL password is empty
app.config['MYSQL_DB'] = 'school_emergency_db'

mysql = MySQL(app)  # Initialize the MySQL extension
socketio = SocketIO(app)
# Secret key for session management
app.secret_key = 'your_secret_key_here'

@socketio.on('connect')
def handle_connect():
    print("User connected")

@socketio.on('disconnect')
def handle_disconnect():
    print("User disconnected")


# Routes for rendering the login and signup pages
@app.route('/')
def home():
    return redirect(url_for('login'))


@app.route('/download_report')
def download_report():
    # Make sure the user is logged in and is an admin
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))

    conn = mysql.connection
    cursor = conn.cursor()

    # Admin sees all reports
    cursor.execute("""
        SELECT ir.*, s.name AS school_name
        FROM incident_report ir
        JOIN schools s ON ir.school_id = s.id
    """)

    reports = cursor.fetchall()
    columns = [desc[0] for desc in cursor.description]  # Get column names

    # Create CSV in memory
    output = StringIO()
    csv_writer = csv.writer(output)
    csv_writer.writerow(columns)  # Write header row
    for report in reports:
        csv_writer.writerow(report)  # Write data rows

    output.seek(0)

    # Send the CSV file as a response
    return Response(
        output,
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=incident_reports.csv"}
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password entered by the user for comparison
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Connect to the database
        conn = mysql.connection
        cursor = conn.cursor()

        # Query the database to check if the user exists and compare the hashed passwords
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        # Check if the user exists and the password matches
        if user and user[2] == hashed_password:  # user[2] is the stored hashed password
            # Store session variables
            session['username'] = user[1]  # user[1] is the username
            session['role'] = user[4]  # user[4] is the role
            session['school_id'] = user[5]  # user[5] is the school_id

            # Redirect to the appropriate dashboard based on the role
            if user[4] == 'admin':
                return redirect(url_for('dashboard', role='admin'))
            elif user[4] == 'staff':
                return redirect(url_for('dashboard', role='staff'))
            elif user[4] == 'student':
                return redirect(url_for('dashboard', role='student'))
            elif user[4] == 'parent':
                return redirect(url_for('dashboard', role='parent'))
            elif user[4] == 'responder':
                return redirect(url_for('dashboard', role='responder'))
        else:
            return "Invalid credentials, please try again."

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        school_name = request.form['school']

        # Hash the password before saving it (important for security)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Connect to the database
        conn = mysql.connection
        cursor = conn.cursor()

        # First, check if the school already exists in the school table
        cursor.execute("SELECT id FROM schools WHERE name = %s", (school_name,))
        school = cursor.fetchone()

        # If the school does not exist, insert it into the schools table
        if not school:
            cursor.execute("INSERT INTO schools (name) VALUES (%s)", (school_name,))
            conn.commit()
            # Get the newly created school's ID
            cursor.execute("SELECT id FROM schools WHERE name = %s", (school_name,))
            school_id = cursor.fetchone()[0]
        else:
            # If the school exists, get the school's ID
            school_id = school[0]

        # Insert the new user into the users table with the school_id
        cursor.execute("INSERT INTO users (username, password, email, role, school_id) VALUES (%s, %s, %s, %s, %s)",
                       (username, hashed_password, email, 'student', school_id))
        conn.commit()

        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/profile')
def profile():
    if 'username' not in session:
        return redirect(url_for('login'))  # Ensure the user is logged in

    username = session['username']

    # Fetch user profile data from the database
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT username, email, role FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user:
        return render_template('profile.html', user=user)
    else:
        return "User not found", 404



@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    role = session['role']
    if role == 'admin':
        return render_template('admin_dashboard.html')
    elif role == 'staff':
        return render_template('staff_dashboard.html')
    elif role == 'student':
        return render_template('student_dashboard.html')
    elif role == 'parent':
        return render_template('parent_dashboard.html')
    elif role == 'responder':
        return render_template('responder_dashboard.html')
    else:
        return redirect(url_for('login'))  # Default fallback to login

@app.route('/add_incident', methods=['GET'])
def add_incident():
    if 'username' not in session:
        return redirect(url_for('login'))  # Ensure the user is logged in
    else:
        return render_template('add_incident.html')


@app.route('/submit_incident', methods=['POST'])
def submit_incident():
    if 'username' not in session:
        return redirect(url_for('login'))  # Ensure the user is logged in

    # Get data from the form
    incident_type = request.form['incident_type']
    incident_date = request.form['incident_date']
    incident_time = request.form['incident_time']
    cause = request.form['cause']
    injuries = request.form['injuries']
    deaths = request.form['deaths']

    # Suspect Information (optional)
    suspect_first_name = request.form.get('suspect_first_name', None)
    suspect_last_name = request.form.get('suspect_last_name', None)
    suspect_gender = request.form.get('suspect_gender', None)
    suspect_age = request.form.get('suspect_age', None)

    # School ID of the logged-in user
    school_id = session['school_id']

    # Insert the new incident report into the database
    conn = mysql.connection
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO incident_report (incident_type, incident_date, incident_time, cause, injuries, deaths,
                                      suspect_first_name, suspect_last_name, suspect_gender, suspect_age, status, school_id)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        incident_type, incident_date, incident_time, cause, injuries, deaths,
        suspect_first_name, suspect_last_name, suspect_gender, suspect_age, 'open', school_id
    ))

    conn.commit()

    # Redirect to the incident reports page after successful submission
    return redirect(url_for('view_reports'))


# Send Alert Route
# Send Alert Route
# @app.route('/send_alert', methods=['GET', 'POST'])
# def send_alert():
#     if 'username' not in session:
#         return redirect(url_for('login'))
#
#     if request.method == 'POST':
#         # Get form data
#         alert_message = request.form['message']
#         alert_type = request.form['alert_type']  # Get the alert type
#         recipients = request.form.getlist('recipients')  # Get selected recipients
#
#         # Insert the alert into the database
#         conn = mysql.connection
#         cursor = conn.cursor()
#         cursor.execute("INSERT INTO alerts (message, alert_type, sent_at) VALUES (%s, %s, NOW())",
#                        (alert_message, alert_type))
#         conn.commit()
#
#         # Get all users who should receive the notification
#         for recipient in recipients:
#             if recipient == 'staff' or recipient == 'responder':
#                 cursor.execute("SELECT id FROM users WHERE role IN ('staff', 'responder')")
#                 users = cursor.fetchall()
#             elif recipient == 'students':
#                 cursor.execute("SELECT id FROM users WHERE role = 'student'")
#                 users = cursor.fetchall()
#             elif recipient == 'parents':
#                 cursor.execute("SELECT id FROM users WHERE role = 'parent'")
#                 users = cursor.fetchall()
#
#             # Insert a notification for each user and push to SocketIO
#             for user in users:
#                 user_id = user[0]
#                 cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (user_id, alert_message))
#                 socketio.emit('new_notification', {'message': alert_message}, room=user_id)
#
#         conn.commit()
#
#         return redirect(url_for('view_alerts'))  # Redirect to the alerts page after sending an alert
#
#     return render_template('send_alert.html')  # Render the form for creating a new alert

@app.route('/view_alerts')
def view_alerts():
    if 'username' not in session:
        return redirect(url_for('login'))  # Ensure the user is logged in

    conn = mysql.connection
    cursor = conn.cursor()

    # Fetch all alerts sent across all schools
    cursor.execute("SELECT * FROM alerts ORDER BY sent_at DESC")
    alerts = cursor.fetchall()

    return render_template('view_alerts.html', alerts=alerts)


@app.route('/view_notifications')
def view_notifications():
    if 'username' not in session:
        return redirect(url_for('login'))

    user_id = session.get('user_id')  # Ensure the user_id is stored in the session after login

    conn = mysql.connection
    cursor = conn.cursor()

    # Fetch unread notifications for the logged-in user
    cursor.execute("SELECT * FROM notifications WHERE user_id = %s AND is_read = FALSE", (user_id,))
    notifications = cursor.fetchall()

    # Debug: Print notifications to console
    print("Notifications for user_id {}:".format(user_id), notifications)

    # Mark notifications as read once viewed
    cursor.execute("UPDATE notifications SET is_read = TRUE WHERE user_id = %s AND is_read = FALSE", (user_id,))
    conn.commit()

    return render_template('view_notifications.html', notifications=notifications)

# Real-Time Updates Route
@app.route('/real_time_updates')
def real_time_updates():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch real-time updates (could be status of emergencies, ongoing incidents)
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM emergency_updates WHERE school_id = %s", (session['school_id'],))
    updates = cursor.fetchall()

    return render_template('real_time_updates.html', updates=updates)

# Emergency Procedures Route
@app.route('/emergency_procedures')
def emergency_procedures():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch emergency procedures from the database
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM emergency_procedures WHERE school_id = %s", (session['school_id'],))
    procedures = cursor.fetchall()

    return render_template('emergency_procedures.html', procedures=procedures)

# Training Modules Route
@app.route('/training_modules')
def training_modules():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Fetch training modules from the database
    conn = mysql.connection
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM training_modules WHERE school_id = %s", (session['school_id'],))
    modules = cursor.fetchall()

    return render_template('training_modules.html', modules=modules)

@app.route('/view_users')
def view_users():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))  # Ensure the user is logged in and is an admin

    # Connect to the database
    conn = mysql.connection
    cursor = conn.cursor()

    # Fetch all users
    cursor.execute("SELECT u.id, u.username, u.email, u.role, s.name AS school_name FROM users u JOIN schools s ON u.school_id = s.id")
    users = cursor.fetchall()

    # Convert result tuples into dictionaries with column names
    columns = [desc[0] for desc in cursor.description]  # Get column names
    users_dict = [dict(zip(columns, row)) for row in users]  # Convert each row to a dictionary

    return render_template('view_users.html', users=users_dict)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))  # Ensure the user is logged in and is an admin

    conn = mysql.connection
    cursor = conn.cursor()

    # Fetch the user details
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()

    if request.method == 'POST':
        # Get the form data
        username = request.form['username']
        email = request.form['email']
        role = request.form['role']
        school_id = request.form['school_id']

        # Update user details in the database
        cursor.execute("""
            UPDATE users 
            SET username = %s, email = %s, role = %s, school_id = %s 
            WHERE id = %s
        """, (username, email, role, school_id, user_id))
        conn.commit()

        return redirect(url_for('view_users'))  # Redirect to the users list

    # Fetch all schools for the dropdown
    cursor.execute("SELECT id, name FROM schools")
    schools = cursor.fetchall()

    return render_template('edit_user.html', user=user, schools=schools)

@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))  # Ensure the user is logged in and is an admin

    conn = mysql.connection
    cursor = conn.cursor()

    # Delete the user from the database
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()

    return redirect(url_for('view_users'))  # Redirect to the users list


@app.route('/view_reports_admin', methods=['GET', 'POST'])
def view_reports_admin():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))  # Ensure the user is logged in and is an admin

    conn = mysql.connection
    cursor = conn.cursor()

    # Fetch all reports along with their school name
    cursor.execute("""
        SELECT ir.id, ir.incident_type, ir.incident_date, ir.incident_time, ir.cause, ir.injuries, 
               ir.deaths, ir.suspect_first_name, ir.suspect_last_name, ir.suspect_gender, ir.suspect_age, 
               ir.status, s.name AS school_name
        FROM incident_report ir
        JOIN schools s ON ir.school_id = s.id
    """)

    reports = cursor.fetchall()

    # Convert result tuples into dictionaries
    columns = [desc[0] for desc in cursor.description]  # Get column names
    reports_dict = [dict(zip(columns, row)) for row in reports]  # Convert each row to a dictionary

    # Handle status update
    if request.method == 'POST':
        incident_id = request.form.get('incident_id')
        new_status = request.form.get('status')

        if incident_id and new_status:
            cursor.execute("""
                UPDATE incident_report 
                SET status = %s
                WHERE id = %s
            """, (new_status, incident_id))
            conn.commit()

            return redirect(url_for('view_reports_admin'))  # Redirect to the same page to refresh the table

    return render_template('view_reports_admin.html', reports=reports_dict)


@app.route('/view_reports')
def view_reports():
    if 'username' not in session:
        return redirect(url_for('login'))  # Ensure the user is logged in

    conn = mysql.connection
    cursor = conn.cursor()

    # Admin sees all reports; others see only their own school's reports
    if session['role'] == 'admin':
        cursor.execute("""
            SELECT ir.*, s.name AS school_name
            FROM incident_report ir
            JOIN schools s ON ir.school_id = s.id
        """)
    else:
        cursor.execute("""
            SELECT ir.*, s.name AS school_name
            FROM incident_report ir
            JOIN schools s ON ir.school_id = s.id
            WHERE ir.school_id = %s
        """, (session['school_id'],))

    # Fetch all rows
    reports = cursor.fetchall()

    # Convert result tuples into dictionaries with column names
    columns = [desc[0] for desc in cursor.description]  # Get column names
    reports_dict = [dict(zip(columns, row)) for row in reports]  # Convert each row to a dictionary

    # Print the reports for debugging
    # print("Reports data (as dictionary):", reports_dict)

    return render_template('view_reports.html', reports=reports_dict)




# View Reports Route
# @app.route('/view_reports')
# def view_reports():
#     if 'username' not in session:
#         return redirect(url_for('login'))  # Ensure the user is logged in
#
#     # Fetch incident reports from the database
#     conn = mysql.connection
#     cursor = conn.cursor()
#     cursor.execute("SELECT * FROM incident_report WHERE school_id = %s", (session['school_id'],))
#     reports = cursor.fetchall()
#
#     return render_template('view_reports.html', reports=reports)



# Sample Route for Viewing Evacuation Plans
@app.route('/view_evacuations')
def view_evacuations():
    if 'username' not in session:
        return redirect(url_for('login'))  # Ensure the user is logged in

    # Connect to the database
    conn = mysql.connection
    cursor = conn.cursor()

    # SQL query to fetch evacuation plans for the current school
    cursor.execute("""
        SELECT * FROM evacuation_plans 
        WHERE school_id = %s
    """, (session['school_id'],))

    evacuation_plans = cursor.fetchall()  # Fetch all evacuation plans

    # Fetch the school name for the logged-in user
    cursor.execute("""
        SELECT name FROM schools WHERE id = %s
    """, (session['school_id'],))
    school_name = cursor.fetchone()[0]  # Get the school name

    # Close the cursor and connection
    cursor.close()

    return render_template('view_evacuations.html', evacuation_plans=evacuation_plans, school_name=school_name)


@app.route('/add_evacuations', methods=['GET', 'POST'])
def add_evacuations():
    if 'username' not in session or session['role'] != 'admin':
        return redirect(url_for('login'))  # Ensure the user is logged in as admin

    if request.method == 'POST':
        # Get data from the form
        plan_name = request.form['plan_name']
        evacuation_timing = request.form['evacuation_timing']
        assembly_points = request.form['assembly_points']
        accountability_procedure = request.form['accountability_procedure']

        # Insert into database
        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO evacuation_plans (school_id, plan_name, evacuation_timing, assembly_points, accountability_procedure)
            VALUES (%s, %s, %s, %s, %s)
        """, (session['school_id'], plan_name, evacuation_timing, assembly_points, accountability_procedure))
        conn.commit()

        return redirect(url_for('view_evacuations'))  # Redirect to view evacuation plans

    return render_template('add_evacuations.html')



@app.route('/send_alert', methods=['GET', 'POST'])
def send_alert():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get form data
        alert_message = request.form['message']
        alert_type = request.form['alert_type']  # Get the alert type
        recipients = request.form.getlist('recipients')  # Get selected recipients

        # Insert the alert into the database
        conn = mysql.connection
        cursor = conn.cursor()
        cursor.execute("INSERT INTO alerts (message, alert_type, sent_at) VALUES (%s, %s, NOW())",
                       (alert_message, alert_type))
        conn.commit()

        # Get all users who should receive the notification
        for recipient in recipients:
            if recipient == 'staff' or recipient == 'responder':
                cursor.execute("SELECT id FROM users WHERE role IN ('staff', 'responder')")
                users = cursor.fetchall()
            elif recipient == 'students':
                cursor.execute("SELECT id FROM users WHERE role = 'student'")
                users = cursor.fetchall()
            elif recipient == 'parents':
                cursor.execute("SELECT id FROM users WHERE role = 'parent'")
                users = cursor.fetchall()

            # Insert a notification for each user and push to SocketIO
            for user in users:
                user_id = user[0]
                cursor.execute("INSERT INTO notifications (user_id, message) VALUES (%s, %s)", (user_id, alert_message))
                socketio.emit('new_notification', {'message': alert_message}, room=user_id)

        conn.commit()

        return redirect(url_for('view_alerts'))  # Redirect to the alerts page after sending an alert

    return render_template('send_alert.html')  # Render the form for creating a new alert

# @socketio.on('connect')
# def handle_connect():
#     user_id = session.get('user_id')  # Ensure you have the user ID in session
#     if user_id:
#         # Join a room corresponding to the user's ID
#         join_room(user_id)
#     print("User connected: ", user_id)
#
# @socketio.on('disconnect')
# def handle_disconnect():
#     user_id = session.get('user_id')
#     if user_id:
#         # Leave the room when the user disconnects
#         leave_room(user_id)
#     print("User disconnected: ", user_id)

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
    # socketio.run(app, debug=True)
