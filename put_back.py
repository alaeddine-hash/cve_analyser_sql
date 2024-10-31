import asyncio
import json
import uuid
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from database import CVEModel, init_db, get_db  # Adjust the import as needed based on your project structure
from datetime import datetime

# Function to load JSON data from the file
def load_json_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

# Function to convert and save JSON data to the database
async def save_cve_data(db: AsyncSession, cve_list):
    # Get the current max ID from the database

    for cve_item in cve_list:
        published = datetime.fromisoformat(cve_item.get("published")).replace(tzinfo=None)
        last_modified = datetime.fromisoformat(cve_item.get("last_modified")).replace(tzinfo=None)
        
        cve_record = CVEModel(
            id=uuid.uuid4(),  # Use UUID for ID
            cve_id=cve_item.get("cve_id"),
            source_identifier=cve_item.get("source_identifier"),
            published=published,  # Naive datetime
            last_modified=last_modified,  # Naive datetime
            vuln_status=cve_item.get("vuln_status"),
            description=cve_item.get("description"),
            cvss_score_v3=cve_item.get("cvss_score_v3"),
            cvss_vector_v3=cve_item.get("cvss_vector_v3"),
            cvss_score_v2=cve_item.get("cvss_score_v2"),
            cvss_vector_v2=cve_item.get("cvss_vector_v2"),
            weaknesses=cve_item.get("weaknesses"),
            configurations=cve_item.get("configurations"),
            references=cve_item.get("references"),
            os_name=cve_item.get("os_name"),
            os_version=cve_item.get("os_version"),
            vendor_name=cve_item.get("vendor_name"),
            Side=cve_item.get("Side"),
            exploitability_metrics=cve_item.get("exploitability_metrics"),
            exploitation_context=cve_item.get("exploitation_context"),
            patch_available=cve_item.get("patch_available"),
            patch=cve_item.get("patch"),
            mitigation_measures=cve_item.get("mitigation_measures"),
            latest_analysis_date=datetime(2024, 10, 20)  # Fixed to the date you specified
        )
        db.add(cve_record)
    await db.commit()

# Main function to handle the database connection and saving data
async def main():
    # Initialize the database (create tables if not already existing)
    await init_db()

    # Load data from the JSON file
    file_path = 'output_2024_test_v4_latest.json'
    json_data = load_json_data(file_path)

    # Get a database session
    async for session in get_db():
        # Save the data
        await save_cve_data(session, json_data)

# Run the script
if __name__ == "__main__":
    asyncio.run(main())
