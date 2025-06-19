import pytest
from src.economic_impact import EconomicImpactCalculator

def test_run_comprehensive_economic_analysis():
    calculator = EconomicImpactCalculator()
    results = calculator.run_comprehensive_economic_analysis()
    assert isinstance(results, dict)
    assert "scenario_analysis" in results
    assert "aggregated_metrics" in results
    assert "recommendations" in results
    assert isinstance(results["recommendations"], list)
