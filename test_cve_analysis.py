# test_cve_analysis.py

import pytest
import asyncio
from unittest.mock import patch, MagicMock
from cve_analysis import analyze_cve

@pytest.mark.asyncio
async def test_analyze_cve_invalid_format():
    # Test with an invalid CVE ID format
    cve_id = "INVALID-CVE-ID"
    result, error = await analyze_cve(cve_id)
    assert result is None
    assert error == "Invalid CVE ID format. Please enter a valid CVE ID in the format 'CVE-YYYY-NNNN'."

@pytest.mark.asyncio
async def test_analyze_cve_nonexistent_cve():
    # Mock get_cve_by_id to return None for a non-existent CVE ID
    with patch('cve_analysis.get_cve_by_id', return_value=None):
        cve_id = "CVE-9999-9999"
        result, error = await analyze_cve(cve_id)
        assert result is None
        assert error == f"No data found for CVE ID {cve_id}."

@pytest.mark.asyncio
async def test_analyze_cve_valid_cve():
    # Mock the external functions to return predictable results
    cve_id = "CVE-2021-34527"
    cve_entry = {
        'cve_id': cve_id,
        'description': 'Test CVE description.',
        # Add other necessary fields that your code relies on
    }

    # Mock get_cve_by_id to return a sample cve_entry
    with patch('cve_analysis.get_cve_by_id', return_value=cve_entry):

        # Mock the processing functions
        async def mock_process_cve_augmentation(entry):
            entry['augmented'] = True
            return entry

        async def mock_process_cve_exploitation_context(entry):
            entry['exploitation_context'] = {'context': 'test'}
            return entry

        async def mock_process_cve_exploitability_metrics(entry):
            entry['exploitability_metrics'] = {'metrics': 'test'}
            return entry

        async def mock_process_cve_patch_and_mitigation(entry):
            entry['patch_available'] = True
            return entry

        with patch('cve_analysis.process_cve_augmentation', side_effect=mock_process_cve_augmentation), \
             patch('cve_analysis.process_cve_exploitation_context', side_effect=mock_process_cve_exploitation_context), \
             patch('cve_analysis.process_cve_exploitability_metrics', side_effect=mock_process_cve_exploitability_metrics), \
             patch('cve_analysis.process_cve_patch_and_mitigation', side_effect=mock_process_cve_patch_and_mitigation), \
             patch('cve_analysis.save_output_to_file', return_value=None):

            result, error = await analyze_cve(cve_id)
            assert error is None
            assert result is not None
            assert result['cve_id'] == cve_id
            assert result['augmented'] is True
            assert result['exploitation_context'] == {'context': 'test'}
            assert result['exploitability_metrics'] == {'metrics': 'test'}
            assert result['patch_available'] is True
