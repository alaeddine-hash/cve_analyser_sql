from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from database import get_db, init_db
from cve_analysis_db import analyze_cve
import asyncio

app = FastAPI(
    title="CVE Analyst API",
    description="API backend for analyzing CVE IDs and retrieving detailed vulnerability information.",
    version="1.0.0",
)

class CVERequest(BaseModel):
    cve_id: str

@app.post("/analyze")
async def analyze_cve_endpoint(request: CVERequest, db: AsyncSession = Depends(get_db)):
    try:
        # Analyze CVE and store it in the database
        cve_entry, error = await analyze_cve(request.cve_id, db)
        if error:
            raise HTTPException(status_code=400, detail=error)
        return cve_entry
    except Exception as e:
        print(f"Exception in analyze_cve_endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    asyncio.run(init_db())  # Initialize the database
    uvicorn.run(app, host="0.0.0.0", port=8000)
