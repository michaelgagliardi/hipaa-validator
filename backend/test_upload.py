import os
from PyPDF2 import PdfReader
from docx import Document
from main import detect_phi


def read_txt(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def read_pdf(path):
    reader = PdfReader(path)
    return "\n".join([page.extract_text() or "" for page in reader.pages])


def read_doc(path):
    doc = Document(path)
    return "\n".join([p.text for p in doc.paragraphs])


def run_test(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    print(f"\n🧪 Running PHI detection on: {file_path}")

    if ext == ".txt":
        content = read_txt(file_path)
    elif ext == ".pdf":
        content = read_pdf(file_path)
    elif ext == ".doc":
        # Technically this should be ".docx" but assuming your file is in that format
        try:
            content = read_doc(file_path)
        except Exception as e:
            print(f"⚠️ Error reading .doc file: {e}")
            return
    else:
        print(f"❌ Unsupported file type: {ext}")
        return

    results = detect_phi(content)
    if results:
        for r in results:
            print(f"🔍 {r['type']} found: {r['value']}")
    else:
        print("✅ No PHI detected.")


# List of test files
test_files = ["test_doc.txt", "test_doc.pdf", "test_doc.doc"]

for file_path in test_files:
    run_test(file_path)
