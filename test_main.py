# test_main.py

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from main import app

client = TestClient(app)

@pytest.mark.asyncio
async def test_analyze_cve_endpoint_valid_cve():
    # Mock analyze_cve to return a sample result
    sample_cve_entry = {
        "cve_id": "CVE-2021-34527",
        "description": "Sample description",
        # Add other fields as needed
    }
    sample_error = None

    with patch('main.analyze_cve', new_callable=AsyncMock) as mock_analyze_cve:
        mock_analyze_cve.return_value = (sample_cve_entry, sample_error)

        response = client.post("/analyze", json={"cve_id": "CVE-2021-34527"})
        assert response.status_code == 200
        assert response.json() == sample_cve_entry

@pytest.mark.asyncio
async def test_analyze_cve_endpoint_invalid_format():
    # Mock analyze_cve to return an error message
    sample_cve_entry = None
    sample_error = "Invalid CVE ID format. Please enter a valid CVE ID in the format 'CVE-YYYY-NNNN'."

    with patch('main.analyze_cve', new_callable=AsyncMock) as mock_analyze_cve:
        mock_analyze_cve.return_value = (sample_cve_entry, sample_error)

        response = client.post("/analyze", json={"cve_id": "INVALID-CVE-ID"})
        assert response.status_code == 400
        assert response.json() == {"detail": sample_error}

@pytest.mark.asyncio
async def test_analyze_cve_endpoint_nonexistent_cve():
    # Mock analyze_cve to return an error message
    cve_id = "CVE-9999-9999"
    sample_cve_entry = None
    sample_error = f"No data found for CVE ID {cve_id}."

    with patch('main.analyze_cve', new_callable=AsyncMock) as mock_analyze_cve:
        mock_analyze_cve.return_value = (sample_cve_entry, sample_error)

        response = client.post("/analyze", json={"cve_id": cve_id})
        assert response.status_code == 400
        assert response.json() == {"detail": sample_error}
