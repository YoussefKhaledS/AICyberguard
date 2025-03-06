from flask import Flask, render_template, request, redirect, url_for , session
import os , sys , bcrypt
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.PEclassification import classify_pe_file
from db import connectToDB, addUser, getUser , init_DB, getAllUsers

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Folder to save uploaded files
app.secret_key = "your_secret_key"

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Connect to the database
connection = connectToDB()
init_DB(connection)

@app.route('/')
def home():
    return render_template('upload.html')


@app.route('/upload', methods=['GET', 'POST'])
def upload():
    message = None
    if request.method == 'POST':
        # Check if a file is uploaded
        if 'file' not in request.files:
            message = "No file uploaded."
            return render_template('upload.html', message=message)

        file = request.files['file']

        # Check if the file is empty
        if file.filename == '':
            message = "No file selected."
            return render_template('upload.html', message=message)

        # Check if the file is a PE file (e.g., .exe or .dll)
        if file and (file.filename.endswith('.exe') or file.filename.endswith('.dll')):
            file_path = os.path.join(
                app.config['UPLOAD_FOLDER'], file.filename)
            print(f"Saving file to: {file_path}")
            file.save(file_path)
            
            # Classify the uploaded file
            result = classify_pe_file(file_path)
            print(result)
            # Redirect to the result page with classification details
            # return redirect(url_for('result', result=result))
        else:
            message = "Invalid file type. Please upload a .exe or .dll file."

    return render_template('upload.html', message=message)


@app.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    message = None
    message_type = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Check if the username or email already exists
        if getUser(connection, username , email):
            message = "User already exists."
            message_type = "error"
        else:
            # Add the new user to the database
            addUser(connection, username, email, password)
            message = "User registered successfully!"
            message_type = "success"
            return redirect(url_for("login"))
    return render_template('signup.html', message=message, message_type=message_type)


@app.route('/login', methods=['GET', 'POST'])
def login():
    message = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = getUser(connection, username)

        # Assuming user[2] is the hashed password
        if user and bcrypt.checkpw(password.encode(), user[3]):
            session['username'] = username
            # Redirect to dashboard or homepage
            return redirect(url_for('home'))
        else:
            message = "Invalid username or password"

    return render_template('login.html', message=message, message_type="danger" if message else "")
# print(getAllUsers(connection))

if __name__ == '__main__':
    app.run(debug=True)
