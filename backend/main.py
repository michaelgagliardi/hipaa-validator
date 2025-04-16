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
import traceback

app = Flask(__name__)
CORS(app, resources={r"/upload": {"origins": "http://localhost:3000"}})

# Ensure directories exist
UPLOAD_FOLDER = "./uploads"
PROCESSED_FOLDER = "./processed"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["PROCESSED_FOLDER"] = PROCESSED_FOLDER


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
        handling_method = request.form["handlingMethod"]

        # Secure the filename
        filename = secure_filename(file.filename)
        file_ext = os.path.splitext(filename)[1].lower()

        # Save the file
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        print(f"File saved to {file_path}")
        print(f"File extension: {file_ext}")
        print(f"Handling method: {handling_method}")

        # Process the file
        if file_ext == ".pdf":
            print("Starting PDF processing...")
            # For PDFs, extract the text and save to a text file
            text = extract_text_from_pdf(file_path)
            print(f"PDF text extracted, length: {len(text)}")

            # Scan text for PHI
            phi_data = phi_scan_text(text)

            # Process the text
            processed_text = process_text(text, handling_method, phi_data)

            # Save the processed text
            base_name = os.path.splitext(os.path.basename(file_path))[0]
            processed_file_path = os.path.join(
                app.config["PROCESSED_FOLDER"], f"{base_name}_processed.txt"
            )
            with open(processed_file_path, "w", encoding="utf-8") as f:
                f.write(processed_text)

            # Read the processed file
            with open(processed_file_path, "rb") as f:
                processed_file = f.read()

            # Encode the processed file to base64
            encoded_file = base64.b64encode(processed_file).decode("utf-8")

            return jsonify(
                {
                    "status": "success",
                    "file": encoded_file,
                    "fileType": "txt",  # Always return as text for PDFs
                }
            )
        else:
            # For other file types, process normally
            processed_file_path = process_file(file_path, handling_method, file_ext)

            # Read the processed file
            with open(processed_file_path, "rb") as f:
                processed_file = f.read()

            # Encode the processed file to base64
            encoded_file = base64.b64encode(processed_file).decode("utf-8")

            return jsonify(
                {
                    "status": "success",
                    "file": encoded_file,
                    "fileType": "txt",  # Always return as text for all file types
                }
            )
    except Exception as e:
        print(f"Error processing file: {str(e)}")
        traceback.print_exc()
        return (
            jsonify(
                {"status": "error", "message": f"Error processing the file: {str(e)}"}
            ),
            500,
        )


def process_file(file_path, handling_method, file_ext):
    """
    Process the file based on its type, preserving the original format when possible.
    """
    base_name = os.path.splitext(os.path.basename(file_path))[0]

    # For PDFs, we'll keep the original format
    if file_ext == ".pdf":
        try:
            # Extract text from PDF
            text = extract_text_from_pdf(file_path)

            # Scan for PHI
            phi_data = phi_scan_text(text)

            # Create a text version with PHI handling applied
            processed_text = process_text(text, handling_method, phi_data)

            # Save the processed text
            text_file_path = os.path.join(
                app.config["PROCESSED_FOLDER"], f"{base_name}_processed.txt"
            )
            with open(text_file_path, "w", encoding="utf-8") as f:
                f.write(processed_text)

            # For PDFs, return the text file but maintain the original file extension in the response
            return text_file_path, ".pdf"

        except Exception as e:
            print(f"Error processing PDF: {str(e)}")
            # Create an error text file
            error_file_path = os.path.join(
                app.config["PROCESSED_FOLDER"], f"{base_name}_error.txt"
            )
            with open(error_file_path, "w", encoding="utf-8") as f:
                f.write(f"Error processing PDF: {str(e)}")
            return error_file_path, ".txt"

    # For all other file types, process as text
    else:
        try:
            # Extract text based on file type
            if file_ext in [".doc", ".docx"]:
                text = extract_text_from_doc(file_path, file_ext)
            else:
                # For text-based files, read directly
                try:
                    with open(file_path, "r", encoding="utf-8") as file:
                        text = file.read()
                except UnicodeDecodeError:
                    # Handle encoding issues
                    with open(
                        file_path, "r", encoding="utf-8", errors="replace"
                    ) as file:
                        text = file.read()

            # Scan for PHI
            phi_data = phi_scan_text(text)

            # Process the text
            processed_text = process_text(text, handling_method, phi_data)

            # Save processed text
            processed_file_path = os.path.join(
                app.config["PROCESSED_FOLDER"], f"{base_name}_processed.txt"
            )
            with open(processed_file_path, "w", encoding="utf-8") as f:
                f.write(processed_text)

            return processed_file_path, ".txt"

        except Exception as e:
            print(f"Error processing file: {str(e)}")
            error_file_path = os.path.join(
                app.config["PROCESSED_FOLDER"], f"{base_name}_error.txt"
            )
            with open(error_file_path, "w", encoding="utf-8") as f:
                f.write(f"Error processing file: {str(e)}")
            return error_file_path, ".txt"


def extract_text_from_pdf(file_path):
    """
    Extract text from a PDF file using pdfplumber with better error handling.
    """
    text = ""
    try:
        print(f"Opening PDF file: {file_path}")
        with pdfplumber.open(file_path) as pdf:
            page_count = len(pdf.pages)
            print(f"PDF has {page_count} pages")

            for i, page in enumerate(pdf.pages):
                try:
                    print(f"Processing page {i+1}/{page_count}")
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
                    else:
                        print(f"No text extracted from page {i+1}")
                except Exception as e:
                    print(f"Error extracting text from page {i+1}: {str(e)}")
                    traceback.print_exc()
                    text += f"[Error extracting page {i+1}: {str(e)}]\n"

        if not text.strip():
            print("No text was extracted from any page of the PDF")
            text = "[No readable text found in the PDF. The file may be scanned or contain only images]"

        return text
    except Exception as e:
        print(f"Error opening or processing PDF: {str(e)}")
        traceback.print_exc()
        return f"[Error processing PDF: {str(e)}]"


def extract_text_from_doc(file_path, file_ext):
    """
    Extract text from Word documents (.docx).
    For .doc files, just return a message (not supported on non-Windows).
    """
    try:
        if file_ext == ".docx":
            doc = docx.Document(file_path)
            text = "\n".join([para.text for para in doc.paragraphs])
            return text
        elif file_ext == ".doc":
            return "DOC file processing requires Windows. Please convert to DOCX format for cross-platform compatibility."
    except Exception as e:
        print(f"Error extracting text from Word document: {str(e)}")
        return ""


def phi_scan_text(text):
    """
    Scan text directly for PHI.
    Creates a temporary file for the PHI scanning function to process.
    """
    import tempfile

    # Write text to a temporary file for PHI scanning
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(
            delete=False, mode="w", encoding="utf-8"
        ) as temp_file:
            temp_file_path = temp_file.name
            temp_file.write(text)

        # Scan the text file for PHI
        phi_data = phi_scan(temp_file_path)
        return phi_data
    except Exception as e:
        print(f"Error scanning for PHI: {str(e)}")
        return {}
    finally:
        # Clean up the temporary file
        if temp_file_path and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)


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
