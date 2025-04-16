from flask import Flask, request, jsonify, send_file
import os
from flask_cors import CORS
import base64
import re
import random
import string
import pdfplumber
import docx
from werkzeug.utils import secure_filename
from phi_scan import phi_scan  # Import the PHI scanning function

app = Flask(__name__)
CORS(app, resources={r"/upload": {"origins": "http://localhost:3000"}})

# Ensure uploads directory exists
UPLOAD_FOLDER = "./uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def generate_random_token(length=8):
    """
    Generate a random string of uppercase and lowercase letters and digits of the given length.
    """
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        # Get file from the request
        file = request.files["file"]
        handling_method = request.form[
            "handlingMethod"
        ]  # Get handling method from form data

        # Save the file to the uploads folder for further processing
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(file_path)

        # Process the file based on the handling method
        processed_file_path = process_file(file_path, handling_method)

        # Read the processed file
        with open(processed_file_path, "rb") as f:
            processed_file = f.read()

        # Encode the processed file to base64
        encoded_file = base64.b64encode(processed_file).decode("utf-8")

        return jsonify(
            {"status": "success", "file": encoded_file}
        )  # Send back the base64 encoded file
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"status": "error", "message": "Error processing the file"}), 500


def process_file(file_path, handling_method):
    """
    Process the file based on the handling method.
    Modify the file content and return the path to the processed file.
    """
    # First, scan the file for potential PHI
    phi_data = phi_scan(file_path)

    # Check file extension and handle accordingly
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension == ".pdf":
        text = extract_text_from_pdf(file_path)
    elif file_extension in [".doc", ".docx"]:
        text = extract_text_from_doc(file_path)
    else:
        # If the file is not recognized, handle it as plain text
        with open(file_path, "r") as file:
            text = file.read()

    # Process the text using the selected handling method
    processed_text = process_text(text, handling_method, phi_data)

    # Save the processed text back to the file
    processed_file_path = file_path.replace(
        os.path.splitext(file_path)[1], "_processed.txt"
    )
    with open(processed_file_path, "w") as file:
        file.write(processed_text)

    return processed_file_path


def extract_text_from_pdf(file_path):
    """
    Extract text from a PDF file using pdfplumber.
    """
    text = ""
    with pdfplumber.open(file_path) as pdf:
        for page in pdf.pages:
            text += page.extract_text() + "\n"
    return text


def extract_text_from_doc(file_path):
    """
    Extract text from a Word document (both .docx and .doc files).
    """
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension == ".docx":
        return extract_text_from_docx(file_path)
    elif file_extension == ".doc":
        # For .doc files, we can use pythoncom or a different approach if needed.
        # For now, we just return a placeholder.
        return "This is a .doc file. PDF or DOCX files are preferred."
    else:
        return ""


def extract_text_from_docx(file_path):
    """
    Extract text from a .docx file using the python-docx library.
    """
    doc = docx.Document(file_path)
    text = ""
    for para in doc.paragraphs:
        text += para.text + "\n"
    return text


def process_text(text, handling_method, phi_data):
    """
    Process the text by applying the selected handling method (redact, tokenize, or remove).
    """
    if handling_method == "redact":
        return redact_text(text, phi_data)
    elif handling_method == "tokenize":
        return tokenize_text(text, phi_data)
    elif handling_method == "remove":
        return remove_text(text, phi_data)
    else:
        raise ValueError(f"Unknown handling method: {handling_method}")


def redact_text(text, phi_data):
    """
    Redact sensitive information in the text by replacing occurrences of PHI with '[REDACTED]'.
    """
    for phi_type, substrings in phi_data.items():
        for substring in substrings:
            text = text.replace(substring, "[REDACTED]")
    return text


def tokenize_text(text, phi_data):
    """
    Tokenize the content by replacing PHI with random strings of 8 characters.
    """
    for phi_type, substrings in phi_data.items():
        for substring in substrings:
            random_token = generate_random_token()  # Generate a random token
            text = text.replace(substring, random_token)
    return text


def remove_text(text, phi_data):
    """
    Remove sensitive content by replacing PHI substrings with spaces of the same length.
    """
    for phi_type, substrings in phi_data.items():
        for substring in substrings:
            spaces = " " * len(substring)
            text = text.replace(substring, spaces)
    return text


if __name__ == "__main__":
    app.run(debug=True)
