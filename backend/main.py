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
import io
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.colors import red, black
from reportlab.lib.pagesizes import letter

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
    If a specific length is provided, the token will match that length exactly.
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

        # Process the file based on its type
        if file_ext == ".pdf":
            print("Starting PDF processing...")
            # Process PDF and keep it as PDF
            processed_file_path = process_pdf(file_path, handling_method)

            # Read the processed file
            with open(processed_file_path, "rb") as f:
                processed_file = f.read()

            # Encode the processed file to base64
            encoded_file = base64.b64encode(processed_file).decode("utf-8")

            return jsonify(
                {
                    "status": "success",
                    "file": encoded_file,
                    "fileType": "pdf",  # Return as PDF
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
                    "fileType": os.path.splitext(processed_file_path)[1][
                        1:
                    ],  # Return appropriate file type
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


def process_pdf(file_path, handling_method):
    """
    Process a PDF file by extracting text, detecting PHI, and creating a new PDF with
    PHI handled according to the specified method.
    """
    base_name = os.path.splitext(os.path.basename(file_path))[0]
    output_path = os.path.join(
        app.config["PROCESSED_FOLDER"], f"{base_name}_processed.pdf"
    )

    try:
        # 1. Extract text from the PDF
        text_content = extract_text_from_pdf(file_path)

        # 2. Scan for PHI in the extracted text
        phi_data = phi_scan_text(text_content)

        # 3. Process the PDF based on PHI data
        if not phi_data:
            # If no PHI found, just return the original PDF
            with open(file_path, "rb") as f_in:
                with open(output_path, "wb") as f_out:
                    f_out.write(f_in.read())
        else:
            # If PHI found, create a new PDF with redacted/tokenized PHI
            create_processed_pdf(file_path, output_path, phi_data, handling_method)

        return output_path
    except Exception as e:
        print(f"Error processing PDF: {str(e)}")
        traceback.print_exc()

        # If PDF processing fails, create a text file with error message
        error_path = os.path.join(
            app.config["PROCESSED_FOLDER"], f"{base_name}_error.txt"
        )
        with open(error_path, "w") as f:
            f.write(f"Error processing PDF: {str(e)}")
        return error_path


def create_processed_pdf(input_path, output_path, phi_data, handling_method):
    """
    Create a new PDF with PHI redacted/tokenized according to handling method.
    Uses a text-based approach to identify and handle PHI in the PDF.
    """
    try:
        # Extract full text from PDF for processing
        with pdfplumber.open(input_path) as pdf:
            # Create a list to store page text information
            pages_text = []

            # Extract text with position information from each page
            for page_num, page in enumerate(pdf.pages):
                page_text = page.extract_text(x_tolerance=3, y_tolerance=3)
                words = page.extract_words(x_tolerance=3, y_tolerance=3)

                # Store page information for processing
                pages_text.append(
                    {
                        "page_num": page_num,
                        "text": page_text,
                        "words": words,
                        "dimensions": (page.width, page.height),
                    }
                )

        # Initialize the PDF reader/writer for generating new PDF
        reader = PdfReader(input_path)
        writer = PdfWriter()

        # Track the number of redactions made
        redaction_count = 0

        # Process each page
        for page_data in pages_text:
            page_num = page_data["page_num"]
            words = page_data["words"]
            width, height = page_data["dimensions"]

            # Get original page
            page = reader.pages[page_num]

            # Create a new PDF with overlay content for redactions
            packet = io.BytesIO()
            can = canvas.Canvas(packet, pagesize=(width, height))

            # Process each PHI instance to find and redact in the current page
            for phi_type, instances in phi_data.items():
                for phi_instance in instances:
                    # Skip empty or very short strings (less than 3 chars)
                    if not phi_instance or len(phi_instance) < 3:
                        continue

                    # Find matching words on the page
                    matched_words = []
                    for word_data in words:
                        word_text = word_data["text"]
                        # Check for exact match or if the word contains the PHI
                        if word_text == phi_instance or phi_instance in word_text:
                            matched_words.append(word_data)

                    # Process each matched word based on handling method
                    for word_data in matched_words:
                        x0, y0, x1, y1 = (
                            word_data["x0"],
                            word_data["top"],
                            word_data["x1"],
                            word_data["bottom"],
                        )

                        # Add some padding
                        x0 = max(0, x0 - 2)
                        y0 = max(0, y0 - 2)
                        x1 = min(width, x1 + 2)
                        y1 = min(height, y1 + 2)

                        # Apply the appropriate handling method
                        if handling_method == "redact":
                            # Draw a black rectangle over the text
                            can.setFillColorRGB(0, 0, 0)
                            can.rect(x0, height - y1, x1 - x0, y1 - y0, fill=1)

                            # Add [REDACTED] text
                            can.setFillColorRGB(1, 1, 1)  # White text
                            can.setFont("Helvetica", 8)
                            can.drawString(
                                x0 + 2, height - ((y0 + y1) / 2), "[REDACTED]"
                            )

                        elif handling_method == "tokenize":
                            # Generate a random token
                            token = generate_random_token(len(phi_instance))

                            # Draw white rectangle to cover original text
                            can.setFillColorRGB(1, 1, 1)
                            can.rect(x0, height - y1, x1 - x0, y1 - y0, fill=1)

                            # Draw tokenized text
                            can.setFillColorRGB(0, 0, 1)  # Blue text
                            can.setFont("Helvetica", 8)
                            can.drawString(x0 + 2, height - ((y0 + y1) / 2), token)

                        elif handling_method == "remove":
                            # Draw white rectangle to "erase" the text
                            can.setFillColorRGB(1, 1, 1)
                            can.rect(x0, height - y1, x1 - x0, y1 - y0, fill=1)

                        redaction_count += 1

            # Add a watermark indicating the document has been processed
            can.setFont("Helvetica", 8)
            can.setFillColorRGB(0.7, 0, 0)  # Dark red
            can.drawString(
                50,
                20,
                f"PHI {handling_method.upper()}ED - {redaction_count} instances processed",
            )

            # Close the overlay
            can.save()

            # Move to the beginning of the BytesIO buffer
            packet.seek(0)
            overlay = PdfReader(packet)

            # Merge the overlay with the original page
            page.merge_page(overlay.pages[0])

            # Add the processed page to the output PDF
            writer.add_page(page)

        # Save the output PDF
        with open(output_path, "wb") as output_file:
            writer.write(output_file)

        return output_path
    except Exception as e:
        print(f"Error creating processed PDF: {str(e)}")
        traceback.print_exc()
        raise


def process_file(file_path, handling_method, file_ext):
    """
    Process non-PDF files based on their type
    """
    base_name = os.path.splitext(os.path.basename(file_path))[0]

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
                with open(file_path, "r", encoding="utf-8", errors="replace") as file:
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

        return processed_file_path

    except Exception as e:
        print(f"Error processing file: {str(e)}")
        error_file_path = os.path.join(
            app.config["PROCESSED_FOLDER"], f"{base_name}_error.txt"
        )
        with open(error_file_path, "w", encoding="utf-8") as f:
            f.write(f"Error processing file: {str(e)}")
        return error_file_path


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
            random_token = generate_random_token(
                len(substring)
            )  # Generate a random token of same length
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
