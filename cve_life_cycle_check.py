from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

# Function to compare CVE fields and print the changes
def compare_versions(cve_id, prev_version, current_version):
    print(f"Comparing CVE {cve_id} from {prev_version.latest_analysis_date} to {current_version.latest_analysis_date}:\n")

    fields_to_compare = [
        'source_identifier', 'published', 'last_modified', 'vuln_status',
        'description', 'cvss_score_v3', 'cvss_vector_v3',
        'weaknesses', 'configurations', 'references', 'patch_available'
    ]

    for field in fields_to_compare:
        prev_value = getattr(prev_version, field)
        current_value = getattr(current_version, field)

        if prev_value != current_value:
            print(f"{field} changed from {prev_value} to {current_value}")
    
    print("\n")


# Main function to get all CVEs and compare the versions
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

    # Compare versions for each CVE
    for cve_id, versions in cve_dict.items():
        for i in range(1, len(versions)):
            prev_version = versions[i - 1]
            current_version = versions[i]
            compare_versions(cve_id, prev_version, current_version)

# Example usage:
# await compare_all_cves(session)
