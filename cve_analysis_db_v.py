from decimal import Decimal
import json
import logging
import os
import re
import asyncio
import copy
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from augmented_cve_gpt_component import process_cve_augmentation_component

# Import processing functions
from cve_check_gpt import process_cve_exploitability_metrics
from get_cve import get_cve_by_id
from augmented_cve_gpt import process_cve_augmentation
from exploitation_context import process_cve_exploitation_context
from patch_and_mitigation import process_cve_patch_and_mitigation
import uuid



# Helper function to convert Decimal to float or None
def convert_decimal(value):
    if isinstance(value, Decimal):
        return float(value)
    return value


async def analyze_cve(cve_id: str, db: AsyncSession, last_modified_date_db=None):
    """Analyze and process a CVE and save it to the PostgreSQL database."""
    from database import CVEModel
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

    # Compare last_modified date with the one from the database
    if last_modified_date_db:
        # Convert both dates to naive datetime for comparison
        last_modified_cve = cve_entry.get("last_modified")
        if isinstance(last_modified_cve, str):
            last_modified_cve = datetime.strptime(last_modified_cve, "%Y-%m-%dT%H:%M:%S.%f%z").replace(tzinfo=None)
        else:
            last_modified_cve = last_modified_cve.astimezone(timezone.utc).replace(tzinfo=None)

        # If the last_modified date is the same, skip analysis
        if last_modified_cve.date() == last_modified_date_db.date():
            return {
                "message": f"CVE {cve_id} has already been analyzed with the latest version.",
                "last_modified": last_modified_date_db
            }, None

    # Process CVE data concurrently
    cve_entry_copy0 = copy.deepcopy(cve_entry)
    cve_entry_copy1 = copy.deepcopy(cve_entry)
    cve_entry_copy2 = copy.deepcopy(cve_entry)
    cve_entry_copy3 = copy.deepcopy(cve_entry)
    cve_entry_copy4 = copy.deepcopy(cve_entry)
    
    results = await asyncio.gather(
        process_cve_augmentation_component(cve_entry_copy0),
        process_cve_augmentation(cve_entry_copy1),
        process_cve_exploitation_context(cve_entry_copy2),
        process_cve_exploitability_metrics(cve_entry_copy3),
        process_cve_patch_and_mitigation(cve_entry_copy4)
    )

    cve_entry_augmented_component, cve_entry_augmented, cve_entry_context, cve_entry_metrics, cve_entry_patch = results
    final_cve_entry = merge_cve_entries([cve_entry, cve_entry_augmented_component, cve_entry_augmented, cve_entry_context, cve_entry_metrics, cve_entry_patch])

    # Save the new CVE entry to the database
    def make_naive(dt):
        """Convert timezone-aware datetime to naive datetime."""
        if dt.tzinfo is not None:
            return dt.astimezone(timezone.utc).replace(tzinfo=None)
        return dt

    vulnerability_component_name = final_cve_entry.get("vulnerability_component_name")
    if isinstance(vulnerability_component_name, list):
        vulnerability_component_name = json.dumps(vulnerability_component_name)

    vulnerability_component_type = final_cve_entry.get("vulnerability_component_type")
    if isinstance(vulnerability_component_type, list):
        vulnerability_component_type = json.dumps(vulnerability_component_type)

    # Inside your analyze_cve function, when saving the CVE data:
    new_cve = CVEModel(
    id=uuid.uuid4(),  # Use UUID for ID
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
    vulnerability_component_name=vulnerability_component_name,
    vulnerability_component_version=final_cve_entry.get("vulnerability_component_version"),
    vulnerability_component_type=vulnerability_component_type,
    Side = final_cve_entry.get("Side"),
    generated_cvss_vector=final_cve_entry.get("generated_cvss_vector"),
    generated_cvss_score=final_cve_entry.get("generated_cvss_score"),
    exploitability_metrics = final_cve_entry.get("exploitability_metrics"),
    exploitation_context=final_cve_entry.get("exploitation_context"),
    patch_available=final_cve_entry.get("patch_available"),
    patch=final_cve_entry.get("patch"),
    mitigation_measures=final_cve_entry.get("mitigation_measures"),
    latest_analysis_date=datetime.utcnow()  # Add the current time as the analysis date

    )

    
    db.add(new_cve)
    await db.commit()
    # Save the final_cve_entry to a JSON file
    json_file_path = 'cve_output_06_11.json'

    try:
        # If the file exists, load its content
        if os.path.exists(json_file_path):
            with open(json_file_path, 'r') as f:
                existing_data = json.load(f)
                if isinstance(existing_data, list):
                    cve_list = existing_data
                else:
                    # If the existing data is not a list, wrap it in a list
                    cve_list = [existing_data]
        else:
            cve_list = []

        # Append the new CVE entry to the list
        cve_list.append(final_cve_entry)

        # Save the updated data back to the file
        with open(json_file_path, 'w') as f:
            json.dump(cve_list, f, indent=4, default=str)
    except Exception as e:
        print(f"Error saving to JSON file: {e}")
    
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
