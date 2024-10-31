from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db, init_db
from cve_analysis_db import analyze_cve
import asyncio
from sqlalchemy import select
from database import CVEModel  # Import your model here
from datetime import datetime
import csv
from fastapi.responses import FileResponse
from io import StringIO
from collections import defaultdict


app = FastAPI(
    title="CVE Analyst API",
    description="API backend for analyzing CVE IDs and retrieving detailed vulnerability information.",
    version="1.0.0",
)

class CVERequest(BaseModel):
    cve_id: str

# Endpoint to analyze a specific CVE and store it in the database
@app.post("/analyze")
async def analyze_cve_endpoint(request: CVERequest, db: AsyncSession = Depends(get_db)):
    try:
         # Check if the CVE with the same cve_id exists in the database and get the latest one based on latest_analysis_date
        existing_cve = await db.execute(
            select(CVEModel)
            .where(CVEModel.cve_id == request.cve_id)
            .order_by(CVEModel.latest_analysis_date.desc())
        )
        latest_cve = existing_cve.scalars().first()

        # Initialize last_modified_date to None by default
        last_modified_date = None

        # If CVE exists, extract the last_modified date
        if latest_cve:
            last_modified_date = latest_cve.last_modified
        # Analyze CVE and store it in the database
        cve_entry, error = await analyze_cve(request.cve_id, db, last_modified_date)
        if error:
            raise HTTPException(status_code=400, detail=error)
        return cve_entry
    except Exception as e:
        print(f"Exception in analyze_cve_endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Function to compare CVE fields and print the changes (comparing only the date part for 'published' and 'last_modified')
def compare_versions(prev_version, current_version):
    changes = {}
    fields_to_compare = [
        'source_identifier', 'published', 'last_modified', 'vuln_status',
        'description', 'cvss_score_v3', 'cvss_vector_v3',
        'weaknesses', 'configurations', 'references', 'patch_available'
    ]

    for field in fields_to_compare:
        prev_value = getattr(prev_version, field)
        current_value = getattr(current_version, field)

        # For 'published' and 'last_modified', compare only the date part
        if field in ['published', 'last_modified']:
            if prev_value.date() != current_value.date():  # Compare only the date part
                changes[field] = {
                    'old': str(prev_value.date()),  # Convert to string for JSON serialization
                    'new': str(current_value.date())  # Convert to string for JSON serialization
                }
        else:
            # For other fields, compare as is
            if prev_value != current_value:
                changes[field] = {
                    'old': prev_value,
                    'new': current_value
                }

    return changes

# Compare up to three versions of CVEs in the database
async def compare_cve_versions(cve_id, versions):
    changes = []

    # Compare the first version with the second
    if len(versions) > 1:
        changes.append({
            "from_date": versions[0].latest_analysis_date,
            "to_date": versions[1].latest_analysis_date,
            "differences": compare_versions(versions[0], versions[1])
        })

    # Compare the second version with the third (if available)
    if len(versions) > 2:
        changes.append({
            "from_date": versions[1].latest_analysis_date,
            "to_date": versions[2].latest_analysis_date,
            "differences": compare_versions(versions[1], versions[2])
        })

    return changes

# Compare all CVEs for the last three analyses
async def compare_all_cves(db: AsyncSession):
    # Fetch all CVE records from the database
    result = await db.execute(select(CVEModel).order_by(CVEModel.cve_id, CVEModel.latest_analysis_date.asc()))
    all_cve_records = result.scalars().all()

    # Dictionary to group CVEs by cve_id
    cve_dict = {}

    # Group CVEs by their cve_id
    for cve in all_cve_records:
        if cve.cve_id not in cve_dict:
            cve_dict[cve.cve_id] = []
        cve_dict[cve.cve_id].append(cve)

    # Compare up to three versions for each CVE
    all_changes = {}
    for cve_id, versions in cve_dict.items():
        if len(versions) >= 2:  # Ensure at least 2 versions to compare
            changes = await compare_cve_versions(cve_id, versions[:3])  # Compare only up to 3 versions
            if changes:
                all_changes[cve_id] = changes

    return all_changes

# New endpoint to compare CVEs over three analysis dates
@app.get("/compare")
async def compare_cves_endpoint(db: AsyncSession = Depends(get_db)):
    try:
        # Compare all CVEs in the database
        changes = await compare_all_cves(db)
        return changes
    except Exception as e:
        print(f"Exception in compare_cves_endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# New function to convert changes to CSV format
def convert_to_csv(changes):
    output = StringIO()  # Create a string buffer to hold CSV data
    writer = csv.writer(output)

    # Write header
    writer.writerow(["CVE ID", "Field", "From Date", "To Date", "Old Value", "New Value"])

    # Write the data for each CVE ID and its differences
    for cve_id, comparisons in changes.items():
        for comparison in comparisons:
            from_date = comparison["from_date"]
            to_date = comparison["to_date"]
            differences = comparison["differences"]

            for field, change in differences.items():
                writer.writerow([cve_id, field, from_date, to_date, change["old"], change["new"]])

    output.seek(0)  # Reset the StringIO pointer to the beginning
    return output

# New endpoint to compare CVEs and download the CSV file
@app.get("/export_csv")
async def export_csv_endpoint(db: AsyncSession = Depends(get_db)):
    try:
        # Compare all CVEs in the database
        changes = await compare_all_cves(db)

        # Convert the changes to CSV format
        csv_data = convert_to_csv(changes)

        # Save the CSV data to a file
        with open("cve_changes.csv", "w", newline='', encoding='utf-8') as csv_file:
            csv_file.write(csv_data.getvalue())

        # Return the CSV file as a response
        return FileResponse("cve_changes.csv", media_type="text/csv", filename="cve_changes.csv")

    except Exception as e:
        print(f"Exception in export_csv_endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    


# Function to calculate statistics and format them according to the requirements
def calculate_statistics_with_date_ranges(changes):
    stats_by_date_range = defaultdict(lambda: {"changed_cves": 0, "changed_fields": defaultdict(int)})

    # Loop through each CVE's changes
    for cve_id, comparisons in changes.items():
        for comparison in comparisons:
            from_date = comparison["from_date"].strftime("%Y-%m-%d")  # Format date as string (YYYY-MM-DD)
            to_date = comparison["to_date"].strftime("%Y-%m-%d")      # Format date as string (YYYY-MM-DD)
            date_range = f"{from_date} :: {to_date}"

            differences = comparison["differences"]

            # Increment the count of changed CVEs for this date range
            stats_by_date_range[date_range]["changed_cves"] += 1

            # For each changed field, increment the count per date range
            for field in differences.keys():
                stats_by_date_range[date_range]["changed_fields"][field] += 1

    # Prepare the statistics in the desired format
    formatted_stats = []
    for date_range, stats in stats_by_date_range.items():
        formatted_stats.append({
            "date_range": date_range,
            "total_changed_cves": stats["changed_cves"],
            "changed_fields": dict(stats["changed_fields"])  # Convert defaultdict to regular dict
        })

    return formatted_stats

# New endpoint to get statistics based on date ranges
@app.get("/statistics")
async def cve_statistics_endpoint(db: AsyncSession = Depends(get_db)):
    try:
        # Compare all CVEs in the database
        changes = await compare_all_cves(db)

        # Calculate statistics based on the changes
        statistics = calculate_statistics_with_date_ranges(changes)

        return statistics
    except Exception as e:
        print(f"Exception in cve_statistics_endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))



if __name__ == "__main__":
    import uvicorn
    asyncio.run(init_db())  # Initialize the database
    uvicorn.run(app, host="0.0.0.0", port=8001)
