from sqlalchemy import Column, Float, Integer, String, Text, DateTime, Boolean, JSON
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
import uuid


# Database URL (customize as needed)
DATABASE_URL = "postgresql+asyncpg://postgres:admin@localhost/cve_db"

# Create the async engine
engine = create_async_engine(DATABASE_URL, echo=True)

# Create the async session maker
async_session = sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

# Base class for ORM models
Base = declarative_base()

# Define the CVEModel class (this is your CVE data model)
class CVEModel(Base):
    __tablename__ = 'cve_data'

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)  # Use UUID for ID
    cve_id = Column(String, index=True)  # Removed unique constraint
    source_identifier = Column(String)
    published = Column(DateTime)
    last_modified = Column(DateTime)
    vuln_status = Column(String)
    description = Column(Text)
    
    # Change to Float for the CVSS scores
    cvss_score_v3 = Column(Float)
    cvss_vector_v3 = Column(String)
    cvss_score_v2 = Column(Float)
    cvss_vector_v2 = Column(String)
    
    weaknesses = Column(JSON)
    configurations = Column(JSON)
    references = Column(JSON)
    os_name = Column(JSON)
    os_version = Column(JSON)
    vendor_name = Column(String)
    Side = Column(String)
    exploitability_metrics = Column(JSON)
    exploitation_context = Column(JSON)
    patch_available = Column(Boolean, default=False)
    patch = Column(JSON)
    mitigation_measures = Column(JSON)

    # New field to track the analysis date
    latest_analysis_date = Column(DateTime, default=datetime.utcnow)

# Function to initialize the database
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# Dependency to get a new session
async def get_db():
    async with async_session() as session:
        yield session
