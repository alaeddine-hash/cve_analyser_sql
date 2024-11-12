import pandas as pd
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
import asyncio
from database import CVEModel, get_db, DATABASE_URL  

# Create the async engine and session maker
engine = create_async_engine(DATABASE_URL, echo=True)
async_session = sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

async def export_to_csv(file_name='octobre_cve_data_export.csv'):
    async with async_session() as session:
        async with session.begin():
            # Query all data from CVEModel
            result = await session.execute(select(CVEModel))
            records = result.scalars().all()

            # Convert the queried data to a list of dictionaries
            data = [
                {
                    'id': str(record.id),
                    'cve_id': record.cve_id,
                    'source_identifier': record.source_identifier,
                    'published': record.published,
                    'last_modified': record.last_modified,
                    'vuln_status': record.vuln_status,
                    'description': record.description,
                    'cvss_score_v3': record.cvss_score_v3,
                    'cvss_vector_v3': record.cvss_vector_v3,
                    'cvss_score_v2': record.cvss_score_v2,
                    'cvss_vector_v2': record.cvss_vector_v2,
                    'weaknesses': record.weaknesses,
                    'configurations': record.configurations,
                    'references': record.references,
                    'os_name': record.os_name,
                    'os_version': record.os_version,
                    'vendor_name': record.vendor_name,
                    'Side': record.Side,
                    'exploitability_metrics': record.exploitability_metrics,
                    'exploitation_context': record.exploitation_context,
                    'patch_available': record.patch_available,
                    'patch': record.patch,
                    'mitigation_measures': record.mitigation_measures,
                    'latest_analysis_date': record.latest_analysis_date
                } for record in records
            ]

            # Create a DataFrame and export to CSV
            df = pd.DataFrame(data)
            df.to_csv(file_name, index=False)
            print(f"Data exported to {file_name}")

# Run the export
if __name__ == "__main__":
    asyncio.run(export_to_csv())
