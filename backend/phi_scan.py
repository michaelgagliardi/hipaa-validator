import re
import spacy
from collections import defaultdict

# Load the spaCy model (en_core_web_sm or a model trained for PHI)
nlp = spacy.load(
    "en_core_web_sm"
)  # You may want to train or fine-tune a specialized model for PHI detection


def phi_scan(file_path):
    """
    Scan the file for potential PHI (Sensitive Information).
    Uses regex and NER (spaCy) to detect various forms of PHI.
    Returns a dictionary of detected PHI types and their corresponding values.
    """
    # Initialize dictionary to store PHI matches
    phi_data = defaultdict(list)

    # Step 1: Perform regex-based PHI detection
    regex_phi_data = regex_phi_scan(file_path)
    phi_data.update(regex_phi_data)

    # Step 2: Perform NER-based PHI detection using spaCy
    ner_phi_data = ner_phi_scan(file_path)
    phi_data.update(ner_phi_data)

    return phi_data


def regex_phi_scan(file_path):
    """
    Scan the file using regex patterns for known PHI types.
    Returns a dictionary of PHI types and their matching values.
    """
    # Regular expressions for detecting different forms of PHI
    patterns = {
        "PHI_SSN": r"\d{3}-\d{2}-\d{4}",  # Matches SSN in the format '000-00-0000'
        "PHI_EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Matches email addresses
        "PHI_PHONE": r"\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",  # Matches phone numbers with optional formatting
        "PHI_DOB": r"\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12][0-9]|3[01])[-/]\d{4}\b",  # Matches dates of birth (MM/DD/YYYY)
        "PHI_CREDIT_CARD": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",  # Matches credit card numbers (simplified format)
    }

    regex_results = defaultdict(list)

    # Read the file content
    with open(file_path, "r") as file:
        content = file.read()

    # Scan for each type of PHI using the regex patterns
    for phi_type, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            regex_results[phi_type].extend(matches)  # Add the matches to the dictionary

    return regex_results


def ner_phi_scan(file_path):
    """
    Use Named Entity Recognition (NER) to detect complex PHI entities like names and addresses.
    Returns a dictionary of detected PHI types (like 'PHI_NAME') and their matching values.
    """
    ner_results = defaultdict(list)

    # Read the file content
    with open(file_path, "r") as file:
        content = file.read()

    # Process the content using spaCy NER
    doc = nlp(content)

    # Extract entities identified by spaCy
    for ent in doc.ents:
        # We could refine this further by adding more specific conditions for PHI-related entities
        if ent.label_ in [
            "PERSON",
            "GPE",
            "ORG",
        ]:  # We focus on people, locations, organizations
            ner_results[f"PHI_{ent.label_}"].append(ent.text)

    return ner_results
