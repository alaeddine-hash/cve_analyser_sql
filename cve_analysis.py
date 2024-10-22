# cve_analysis.py

from decimal import Decimal
import json
import re
import logging
import os
from datetime import datetime
import asyncio
import copy

from cve_check_gpt import process_cve_exploitability_metrics
from get_cve import get_cve_by_id
from augmented_cve_gpt import process_cve_augmentation
from exploitation_context import process_cve_exploitation_context
from patch_and_mitigation import process_cve_patch_and_mitigation

# Configure logging
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def default_serializer(obj):
    """ Custom serializer to handle non-serializable objects like datetime and Decimal """
    if isinstance(obj, datetime):
        return obj.isoformat()  # Convert datetime to ISO format
    elif isinstance(obj, Decimal):
        return float(obj)  # Convert Decimal to float for JSON serialization
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")


def save_output_to_file(cve_entry, filename='output_2024_test_v4_latest.json'):
    # Check if the file exists
    if os.path.exists(filename):
        # Read existing data
        with open(filename, 'r') as f:
            try:
                data = json.load(f)
                if not isinstance(data, list):
                    data = [data]
            except json.JSONDecodeError:
                data = []
    else:
        data = []

    # Append new entry
    data.append(cve_entry)

    # Write back to the file with custom serializer
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4, default=default_serializer)
""" 
async def analyze_cve(cve_id):
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

    # Process CVE data
    cve_entry = await process_cve_augmentation(cve_entry)
    cve_entry = await process_cve_exploitation_context(cve_entry)
    cve_entry = await process_cve_exploitability_metrics(cve_entry)
    cve_entry = await process_cve_patch_and_mitigation(cve_entry)

    # Save output to file
    save_output_to_file(cve_entry)

    return cve_entry, None
 """

async def analyze_cve(cve_id):
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

    # Create copies of cve_entry for each processing function to avoid shared state issues
    cve_entry_copy1 = copy.deepcopy(cve_entry)
    cve_entry_copy2 = copy.deepcopy(cve_entry)
    cve_entry_copy3 = copy.deepcopy(cve_entry)
    cve_entry_copy4 = copy.deepcopy(cve_entry)

    # Run all processing functions concurrently
    results = await asyncio.gather(
        process_cve_augmentation(cve_entry_copy1),
        process_cve_exploitation_context(cve_entry_copy2),
        process_cve_exploitability_metrics(cve_entry_copy3),
        process_cve_patch_and_mitigation(cve_entry_copy4)
    )

    # Unpack the results
    cve_entry_augmented, cve_entry_context, cve_entry_metrics, cve_entry_patch = results

    # Merge the results into a single cve_entry
    final_cve_entry = merge_cve_entries([cve_entry, cve_entry_augmented, cve_entry_context, cve_entry_metrics, cve_entry_patch])

    # Save output to file
    save_output_to_file(final_cve_entry)

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
                    # Overwrite with the latest value (you can adjust this logic if needed)
                    merged_entry[key] = value
            else:
                merged_entry[key] = value
    return merged_entry