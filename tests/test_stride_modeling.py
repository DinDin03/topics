import pytest
from src.stride_threat_modeling import StrideModel

def test_run_stride_analysis():
    model = StrideModel()
    results = model.run_stride_analysis()
    assert isinstance(results, dict)
    assert "analysis_timestamp" in results
    assert "system_summary" in results
    assert "stride_breakdown" in results
    assert "risk_distribution" in results
    assert "top_threats" in results
    assert isinstance(results["top_threats"], list)
