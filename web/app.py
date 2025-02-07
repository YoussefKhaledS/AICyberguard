from flask import Flask, render_template, request, redirect, url_for
import os , sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from models.PEclassification import classify_pe_file

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Folder to save uploaded files

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])


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



if __name__ == '__main__':
    app.run(debug=True)
