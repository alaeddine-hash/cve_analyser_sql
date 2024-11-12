import pandas as pd
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import sessionmaker
import asyncio
from datetime import datetime
from database import CVEModel, get_db, DATABASE_URL  

# Create the async engine and session maker
engine = create_async_engine(DATABASE_URL, echo=True)
async_session = sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

async def export_to_csv():
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

            # Create a DataFrame
            df = pd.DataFrame(data)

            if not df.empty:
                # Convert 'latest_analysis_date' to datetime to extract day and month
                df['latest_analysis_date'] = pd.to_datetime(df['latest_analysis_date'], errors='coerce')

                # Group by 'latest_analysis_date' and export each group to a separate CSV
                for analysis_date, group in df.groupby(df['latest_analysis_date'].dt.strftime('%d_%m')):
                    if pd.notnull(analysis_date):  # Ensure the date is valid
                        file_name = f'cve_data_{analysis_date}.csv'
                        group.to_csv(file_name, index=False)
                        print(f"Data for {analysis_date} exported to {file_name}")
            else:
                print("No data found.")

# Run the export
if __name__ == "__main__":
    asyncio.run(export_to_csv())
