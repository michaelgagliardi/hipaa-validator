import re
import spacy
from collections import defaultdict
import os
import tempfile
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("phi_scanner")

# Load the spaCy model (en_core_web_sm or preferably a model fine-tuned for medical data)
try:
    nlp = spacy.load("en_core_web_sm")
    logger.info("Loaded spaCy model: en_core_web_sm")
except OSError:
    logger.warning("Default model not found. Downloading en_core_web_sm...")
    spacy.cli.download("en_core_web_sm")
    nlp = spacy.load("en_core_web_sm")


def phi_scan(file_path):
    """
    Comprehensive PHI scanner function.

    Scans the file for potential PHI (Protected Health Information) using:
    1. Regular expressions for structured PHI (SSN, DOB, etc.)
    2. NER for unstructured PHI (names, locations, etc.)
    3. Medical pattern recognition for healthcare-specific identifiers

    Args:
        file_path (str): Path to the file to scan

    Returns:
        dict: Dictionary with PHI types as keys and lists of found instances as values
    """
    logger.info(f"Starting PHI scan for file: {file_path}")

    # Initialize dictionary to store PHI matches
    phi_data = defaultdict(list)

    # Step 1: Perform regex-based PHI detection
    regex_phi_data = regex_phi_scan(file_path)
    for key, values in regex_phi_data.items():
        phi_data[key].extend(values)

    # Step 2: Perform NER-based PHI detection using spaCy
    ner_phi_data = ner_phi_scan(file_path)
    for key, values in ner_phi_data.items():
        phi_data[key].extend(values)

    # Step 3: Perform healthcare-specific pattern recognition
    medical_phi_data = medical_phi_scan(file_path)
    for key, values in medical_phi_data.items():
        phi_data[key].extend(values)

    # Step 4: Deduplicate results
    for key in phi_data:
        phi_data[key] = list(set(phi_data[key]))

    # Log summary of findings
    total_phi = sum(len(items) for items in phi_data.values())
    logger.info(
        f"PHI scan complete. Found {total_phi} potential PHI instances across {len(phi_data)} categories"
    )

    return dict(phi_data)  # Convert defaultdict to regular dict


def regex_phi_scan(file_path):
    """
    Scan a file for structured PHI using regular expressions.

    Args:
        file_path (str): Path to the file to scan

    Returns:
        defaultdict: Dictionary with PHI types as keys and lists of found instances as values
    """
    # Comprehensive set of regular expressions for PHI detection
    patterns = {
        # Basic identifiers
        "PHI_SSN": r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b",  # SSN with or without dashes
        "PHI_EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",  # Email addresses
        # Phone numbers with various formats
        "PHI_PHONE": [
            r"\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",  # (123) 456-7890, 123-456-7890
            r"\b\d{3}[-.\s]?\d{4}\b",  # 123-4567
        ],
        # Dates in various formats
        "PHI_DOB": [
            r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)?\d{2}\b",  # MM/DD/YYYY, M/D/YY
            r"\b(?:19|20)\d{2}[/-](?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])\b",  # YYYY/MM/DD
            r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?,?\s+(?:19|20)?\d{2}\b",  # January 1st, 2023
        ],
        # Financial information
        "PHI_CREDIT_CARD": [
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",  # Credit card without spaces
            r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|3(?:0[0-5]|[68][0-9])|6(?:011|5[0-9]{2})|(?:2131|1800|35\d{3}))[- ]?(?:[0-9]{4}[- ]?){3}[0-9]{4}\b",  # With spaces/dashes
        ],
        # Address components
        "PHI_ZIP": r"\b\d{5}(?:-\d{4})?\b",  # ZIP or ZIP+4
        "PHI_ADDRESS": r"\b\d+\s+[A-Za-z0-9\s,]+(St|Street|Rd|Road|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|Way|Pl|Place|Court|Ct)\b",
        # Medical record identifiers
        "PHI_MRN": [
            r"\bMRN\s*[:#]?\s*\d{5,10}\b",  # MRN: 12345
            r"\bMedical Record\s*[:#]?\s*\d{5,10}\b",  # Medical Record #12345
            r"\bPatient ID\s*[:#]?\s*\d{5,10}\b",  # Patient ID: 12345
        ],
        # Insurance information
        "PHI_INSURANCE": [
            r"\b(?:Medicare|Medicaid)\s*[:#]?\s*\d{4,12}\b",  # Medicare: 1234567890
            r"\bGroup\s*[:#]?\s*\d{5,12}\b",  # Group #: 12345
            r"\bPolicy\s*[:#]?\s*[A-Z0-9]{5,20}\b",  # Policy #: ABC12345
        ],
    }

    regex_results = defaultdict(list)

    # Read the file content
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                content = file.read()
        except Exception as e:
            logger.error(f"Error reading file for regex scan: {str(e)}")
            return regex_results

    # Scan for each type of PHI using the regex patterns
    for phi_type, pattern_list in patterns.items():
        if not isinstance(pattern_list, list):
            pattern_list = [pattern_list]

        for pattern in pattern_list:
            try:
                matches = re.findall(pattern, content)
                if matches:
                    regex_results[phi_type].extend(matches)
            except Exception as e:
                logger.error(f"Error with pattern {pattern} for {phi_type}: {str(e)}")

    logger.info(
        f"Regex scan complete - found {sum(len(v) for v in regex_results.values())} potential PHI instances"
    )
    return regex_results


def ner_phi_scan(file_path):
    """
    Use Named Entity Recognition (NER) to detect complex PHI entities.

    Args:
        file_path (str): Path to the file to scan

    Returns:
        defaultdict: Dictionary with PHI types as keys and lists of found instances as values
    """
    ner_results = defaultdict(list)

    # Mapping spaCy entity types to PHI categories
    entity_mapping = {
        "PERSON": "PHI_NAME",
        "GPE": "PHI_LOCATION",
        "LOC": "PHI_LOCATION",
        "ORG": "PHI_ORGANIZATION",
        "FAC": "PHI_FACILITY",
        "NORP": "PHI_DEMOGRAPHIC",  # Nationalities, religious or political groups
        "EVENT": "PHI_EVENT",
    }

    # Read the file content
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                content = file.read()
        except Exception as e:
            logger.error(f"Error reading file for NER scan: {str(e)}")
            return ner_results

    # Process the content in chunks to avoid memory issues with large files
    chunk_size = 100000  # Adjust based on available memory
    chunks = [content[i : i + chunk_size] for i in range(0, len(content), chunk_size)]

    for i, chunk in enumerate(chunks):
        logger.info(f"Processing NER chunk {i+1}/{len(chunks)}")

        try:
            # Process the chunk using spaCy NER
            doc = nlp(chunk)

            # Extract entities identified by spaCy
            for ent in doc.ents:
                if ent.label_ in entity_mapping:
                    phi_type = entity_mapping[ent.label_]
                    ner_results[phi_type].append(ent.text)

                # Add context analysis for potential PHI that spaCy might miss
                if ent.label_ == "PERSON" and len(ent.text.split()) == 1:
                    # Look for potential last names that follow titles or first names
                    context = chunk[
                        max(0, ent.start_char - 20) : min(len(chunk), ent.end_char + 20)
                    ]
                    name_context_pattern = r"\b(?:Dr|Mr|Mrs|Ms|Miss|Professor|Prof|MD|PhD)\.\s+([A-Z][a-z]+)\b"
                    name_matches = re.findall(name_context_pattern, context)
                    if name_matches:
                        ner_results["PHI_NAME"].extend(name_matches)

        except Exception as e:
            logger.error(f"Error in NER processing chunk {i+1}: {str(e)}")

    logger.info(
        f"NER scan complete - found {sum(len(v) for v in ner_results.values())} potential PHI instances"
    )
    return ner_results


def medical_phi_scan(file_path):
    """
    Detect healthcare-specific PHI using specialized patterns.

    Args:
        file_path (str): Path to the file to scan

    Returns:
        defaultdict: Dictionary with PHI types as keys and lists of found instances as values
    """
    medical_results = defaultdict(list)

    # Healthcare-specific patterns
    patterns = {
        "PHI_MEDICAL_CODE": [
            r"\bICD-(?:9|10)(?:-[A-Z]{2})?\s*:?\s*([A-Z0-9]{3,7}(?:\.[A-Z0-9]{1,4})?)\b",  # ICD-9/10 codes
            r"\bCPT\s*:?\s*([0-9]{5})\b",  # CPT codes
            r"\bHCPCS\s*:?\s*([A-Z0-9]{5})\b",  # HCPCS codes
        ],
        "PHI_DEVICE_ID": [
            r"\bDevice\s*ID\s*:?\s*([A-Z0-9\-]{5,30})\b",  # Medical device identifiers
            r"\bImplant\s*(?:Serial)?\s*(?:Number|No|#)\s*:?\s*([A-Z0-9\-]{5,30})\b",  # Implant serial numbers
        ],
        "PHI_ACCOUNT_NUMBER": [
            r"\bAcc(?:oun)?t\s*(?:Number|No|#)\s*:?\s*([A-Z0-9\-]{4,20})\b",  # Account numbers
            r"\bPatient\s*(?:Number|No|#)\s*:?\s*([A-Z0-9\-]{4,20})\b",  # Patient numbers
        ],
        "PHI_HEALTH_PLAN": [
            r"\bHealth\s*Plan\s*(?:ID|Number|No|#)\s*:?\s*([A-Z0-9\-]{4,20})\b",  # Health plan IDs
            r"\bBeneficiary\s*(?:Number|No|#)\s*:?\s*([A-Z0-9\-]{4,20})\b",  # Beneficiary numbers
        ],
        "PHI_BIOMETRIC": [
            r"\bBiometric\s*(?:ID|Identifier)\s*:?\s*([A-Z0-9\-]{4,30})\b",  # Biometric identifiers
        ],
        "PHI_VISIT_DATE": [
            r"\b(?:Visit|Admission|Discharge)\s+Date\s*:?\s*((?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)?\d{2})\b",  # Visit dates
            r"\b(?:Visit|Admission|Discharge)\s+(?:on|dated)\s+((?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)?\d{2})\b",
        ],
        "PHI_PROVIDER": [
            r"\b(?:Dr|Doctor|Provider|Physician)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b",  # Provider names
        ],
    }

    # Read the file content
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as file:
                content = file.read()
        except Exception as e:
            logger.error(f"Error reading file for medical scan: {str(e)}")
            return medical_results

    # Scan for healthcare-specific PHI
    for phi_type, pattern_list in patterns.items():
        for pattern in pattern_list:
            try:
                matches = re.findall(pattern, content)
                if matches:
                    medical_results[phi_type].extend(matches)
            except Exception as e:
                logger.error(f"Error with medical pattern {pattern}: {str(e)}")

    # Check for context-based medical PHI
    try:
        # Look for sections that often contain PHI
        sections = [
            (
                r"(?:PATIENT|CLIENT)\s+INFORMATION",
                300,
            ),  # Look 300 chars after "PATIENT INFORMATION"
            (r"DEMOGRAPHICS", 300),
            (r"PERSONAL\s+HISTORY", 400),
            (r"FAMILY\s+HISTORY", 400),
            (r"SOCIAL\s+HISTORY", 400),
            (r"CONTACT\s+INFORMATION", 300),
        ]

        for section_pattern, context_length in sections:
            section_matches = re.finditer(section_pattern, content)
            for match in section_matches:
                # Extract context around section headers
                start = match.end()
                section_context = content[start : start + context_length]

                # Run NER on this focused context for better results
                doc = nlp(section_context)
                for ent in doc.ents:
                    if ent.label_ in ["PERSON", "ORG", "GPE", "LOC"]:
                        medical_results[f"PHI_{ent.label_}"].append(ent.text)

    except Exception as e:
        logger.error(f"Error in context-based medical PHI detection: {str(e)}")

    logger.info(
        f"Medical scan complete - found {sum(len(v) for v in medical_results.values())} potential PHI instances"
    )
    return medical_results


# Function to detect PHI in PDF files specifically - can be integrated with main PDF processing
def detect_phi_in_pdf(pdf_path):
    """
    More advanced PHI detection specifically for PDFs.
    Uses both text extraction and positional analysis to identify potential PHI.

    Args:
        pdf_path: Path to the PDF file

    Returns:
        dict: Dictionary of PHI found with positions
    """
    import pdfplumber
    import re
    import spacy
    from collections import defaultdict
    import logging

    # Set up logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("phi_detector")

    # Load spaCy model
    try:
        nlp = spacy.load("en_core_web_sm")
    except:
        logger.info("Downloading spaCy model...")
        spacy.cli.download("en_core_web_sm")
        nlp = spacy.load("en_core_web_sm")

    # Initialize results
    phi_results = defaultdict(list)

    # Define regex patterns for common PHI types
    phi_patterns = {
        "PHI_SSN": r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b",
        "PHI_PHONE": r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
        "PHI_EMAIL": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
        "PHI_DOB": [
            r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)?\d{2}\b",
            r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+(?:0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?,?\s+(?:19|20)?\d{2}\b",
        ],
        "PHI_MRN": [
            r"\bMRN\s*[:#]?\s*\d{5,10}\b",
            r"\bPatient\s*(?:ID|Number|No|#)\s*[:#]?\s*\w{5,10}\b",
        ],
        "PHI_ADDRESS": r"\b\d+\s+[A-Za-z0-9\s,]+(Street|St|Road|Rd|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b",
        "PHI_ZIP": r"\b\d{5}(?:-\d{4})?\b",
    }

    # Define contextual triggers that indicate that nearby text might contain PHI
    context_triggers = {
        "NAME_CONTEXT": [
            r"\bname\s*:",
            r"\bpatient\s*:",
            r"\bpatient\s*name\s*:",
        ],
        "DOB_CONTEXT": [
            r"\bdob\s*:",
            r"\bdate\s+of\s+birth\s*:",
            r"\bbirthdate\s*:",
        ],
        "ADDRESS_CONTEXT": [
            r"\baddress\s*:",
            r"\bresidence\s*:",
            r"\bliving\s+at\s*:",
        ],
    }

    try:
        logger.info(f"Opening PDF file: {pdf_path}")
        with pdfplumber.open(pdf_path) as pdf:
            # Process each page in the PDF
            for page_num, page in enumerate(pdf.pages):
                logger.info(f"Processing page {page_num + 1} of {len(pdf.pages)}")

                # Extract text with position information
                page_text = page.extract_text()
                words_with_coords = page.extract_words(x_tolerance=3, y_tolerance=3)

                # 1. Regex detection on the full page text
                for phi_type, patterns in phi_patterns.items():
                    if not isinstance(patterns, list):
                        patterns = [patterns]

                    for pattern in patterns:
                        matches = re.finditer(pattern, page_text)
                        for match in matches:
                            phi_instance = match.group(0)
                            phi_results[phi_type].append(phi_instance)

                # 2. NER detection on the text
                doc = nlp(page_text)
                entity_mapping = {
                    "PERSON": "PHI_NAME",
                    "GPE": "PHI_LOCATION",
                    "ORG": "PHI_ORGANIZATION",
                    "DATE": "PHI_DATE",
                }

                for ent in doc.ents:
                    if ent.label_ in entity_mapping:
                        phi_type = entity_mapping[ent.label_]
                        phi_results[phi_type].append(ent.text)

                # 3. Context-based detection
                for context_type, triggers in context_triggers.items():
                    for trigger in triggers:
                        matches = re.finditer(trigger, page_text, re.IGNORECASE)
                        for match in matches:
                            # Get text after the trigger (up to 50 chars)
                            start_pos = match.end()
                            context_text = page_text[start_pos : start_pos + 50]

                            # If it's a name context, look for capitalized words
                            if context_type == "NAME_CONTEXT":
                                name_matches = re.findall(
                                    r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b", context_text
                                )
                                for name in name_matches:
                                    phi_results["PHI_NAME"].append(name)

                            # For DOB context, look for dates not already captured
                            elif context_type == "DOB_CONTEXT":
                                dob_matches = re.findall(
                                    r"\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b", context_text
                                )
                                for dob in dob_matches:
                                    phi_results["PHI_DOB"].append(dob)

                            # For address context, capture potential addresses
                            elif context_type == "ADDRESS_CONTEXT":
                                # Look for something that might be an address
                                addr_matches = re.findall(
                                    r"\b\d+\s+[A-Za-z0-9\s,.]+\b", context_text
                                )
                                for addr in addr_matches:
                                    if len(addr) > 10:  # Minimum length for an address
                                        phi_results["PHI_ADDRESS"].append(addr)

                # 4. Form field detection - look for potentially filled form fields
                # This uses a heuristic that form fields often have text aligned in specific ways
                if len(words_with_coords) > 0:
                    # Group words by their vertical position (y-coordinate)
                    y_positions = defaultdict(list)
                    for word in words_with_coords:
                        y_positions[round(word["top"])].append(word)

                    # Look for lines with few words that might be form fields
                    for y_pos, words in y_positions.items():
                        if 1 < len(words) < 5:  # Typical of form field entries
                            line_text = " ".join(word["text"] for word in words)

                            # Check if this looks like a filled form field
                            if ":" in line_text:
                                label, value = line_text.split(":", 1)
                                label = label.strip().lower()
                                value = value.strip()

                                # Categorize based on label
                                if "name" in label and len(value) > 0:
                                    phi_results["PHI_NAME"].append(value)
                                elif any(
                                    term in label for term in ["dob", "birth", "date"]
                                ):
                                    phi_results["PHI_DOB"].append(value)
                                elif any(
                                    term in label
                                    for term in ["address", "street", "residence"]
                                ):
                                    phi_results["PHI_ADDRESS"].append(value)
                                elif any(
                                    term in label for term in ["phone", "tel", "cell"]
                                ):
                                    phi_results["PHI_PHONE"].append(value)
                                elif any(term in label for term in ["mail", "email"]):
                                    phi_results["PHI_EMAIL"].append(value)
                                elif any(
                                    term in label
                                    for term in ["id", "record", "mrn", "patient"]
                                ):
                                    phi_results["PHI_MRN"].append(value)

        # 5. Deduplicate results
        for phi_type in phi_results:
            phi_results[phi_type] = list(set(phi_results[phi_type]))

        logger.info(
            f"PHI detection complete. Found {sum(len(items) for items in phi_results.values())} potential PHI instances."
        )
        return dict(phi_results)

    except Exception as e:
        logger.error(f"Error in PHI detection: {str(e)}")
        import traceback

        traceback.print_exc()
        return dict(phi_results)


# For standalone testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        test_file = sys.argv[1]
        print(f"Scanning {test_file} for PHI...")
        results = phi_scan(test_file)

        print("\nResults:")
        for category, items in results.items():
            print(f"\n{category}:")
            for item in items:
                print(f"  - {item}")

        print(
            f"\nTotal PHI instances found: {sum(len(items) for items in results.values())}"
        )
    else:
        print("Usage: python phi_scan.py <filename>")
