from decimal import Decimal
import logging
import re
import asyncio
import copy
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db, CVEModel  # Import database session and model

# Import processing functions
from cve_check_gpt import process_cve_exploitability_metrics
from get_cve import get_cve_by_id
from augmented_cve_gpt import process_cve_augmentation
from exploitation_context import process_cve_exploitation_context
from patch_and_mitigation import process_cve_patch_and_mitigation

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


# Helper function to convert Decimal to float or None
def convert_decimal(value):
    if isinstance(value, Decimal):
        return float(value)
    return value


async def analyze_cve(cve_id: str, db: AsyncSession):
    """Analyze and process a CVE and save it to the PostgreSQL database."""
    
    # Validate CVE ID format
    cve_pattern = r'^CVE-\d{4}-\d{4,7}$'
    if not re.match(cve_pattern, cve_id):
        logging.error(f"Invalid CVE ID format: {cve_id}")
        return None, "Invalid CVE ID format. Please enter a valid CVE ID in the format 'CVE-YYYY-NNNN'."

    # Fetch CVE data
    cve_entry = get_cve_by_id(cve_id)
    if not cve_entry:
        logging.error(f"No data found for CVE ID {cve_id}")
        return None, f"No data found for CVE ID {cve_id}."

    # Process CVE data concurrently
    cve_entry_copy1 = copy.deepcopy(cve_entry)
    cve_entry_copy2 = copy.deepcopy(cve_entry)
    cve_entry_copy3 = copy.deepcopy(cve_entry)
    cve_entry_copy4 = copy.deepcopy(cve_entry)
    
    results = await asyncio.gather(
        process_cve_augmentation(cve_entry_copy1),
        process_cve_exploitation_context(cve_entry_copy2),
        process_cve_exploitability_metrics(cve_entry_copy3),
        process_cve_patch_and_mitigation(cve_entry_copy4)
    )

    cve_entry_augmented, cve_entry_context, cve_entry_metrics, cve_entry_patch = results
    final_cve_entry = merge_cve_entries([cve_entry, cve_entry_augmented, cve_entry_context, cve_entry_metrics, cve_entry_patch])

    # Save the new CVE entry to the database
    def make_naive(dt):
        """Convert timezone-aware datetime to naive datetime."""
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    # Inside your analyze_cve function, when saving the CVE data:
    new_cve = CVEModel(
    cve_id=final_cve_entry["cve_id"],
    source_identifier=final_cve_entry.get("source_identifier"),

    # Convert to naive datetime
    published=make_naive(final_cve_entry["published"]) if isinstance(final_cve_entry["published"], datetime) else datetime.strptime(final_cve_entry["published"], "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=None),

    last_modified=make_naive(final_cve_entry["last_modified"]) if isinstance(final_cve_entry["last_modified"], datetime) else datetime.strptime(final_cve_entry["last_modified"], "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=None),
    
    vuln_status=final_cve_entry.get("vuln_status"),
    description=final_cve_entry.get("description"),
    
    # Convert Decimal values to floats
    cvss_score_v3=convert_decimal(final_cve_entry.get("cvss_score_v3")),
    cvss_vector_v3=final_cve_entry.get("cvss_vector_v3"),
    cvss_score_v2=convert_decimal(final_cve_entry.get("cvss_score_v2")),
    cvss_vector_v2=final_cve_entry.get("cvss_vector_v2"),

    weaknesses=final_cve_entry.get("weaknesses"),
    configurations=final_cve_entry.get("configurations"),
    references=final_cve_entry.get("references"),
    os_name=final_cve_entry.get("os_name"),
    os_version=final_cve_entry.get("os_version"),
    vendor_name=final_cve_entry.get("vendor_name"),
    Side = final_cve_entry.get("Side"),
    exploitability_metrics = final_cve_entry.get("exploitability_metrics"),
    exploitation_context=final_cve_entry.get("exploitation_context"),
    patch_available=final_cve_entry.get("patch_available"),
    patch=final_cve_entry.get("patch"),
    mitigation_measures=final_cve_entry.get("mitigation_measures"),
    latest_analysis_date=datetime.utcnow()  # Add the current time as the analysis date

    )

    
    db.add(new_cve)
    await db.commit()
    
    return final_cve_entry, None

def merge_cve_entries(entries):
    """Merge multiple CVE entry dictionaries into one."""
    merged_entry = {}
    for entry in entries:
        if entry is None:
            continue  # Skip if the entry is None due to an error in processing
        for key, value in entry.items():
            if key in merged_entry:
                # Handle conflicts or combine data appropriately
                if isinstance(merged_entry[key], dict) and isinstance(value, dict):
                    merged_entry[key] = {**merged_entry[key], **value}
                elif isinstance(merged_entry[key], list) and isinstance(value, list):
                    merged_entry[key] = merged_entry[key] + value
                else:
                    merged_entry[key] = value
            else:
                merged_entry[key] = value
    return merged_entry
