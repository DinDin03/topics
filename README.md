# Solar Inverter Cybersecurity Analysis Platform

## Overview

This project implements a comprehensive cybersecurity analysis framework for internet-connected solar inverters in South Australia's distributed energy systems. The platform integrates multiple established security frameworks to provide systematic vulnerability assessment, threat modeling, risk analysis, and economic impact evaluation.

## Key Features

- **Multi-Framework Analysis**: CVE vulnerability analysis, STRIDE threat modeling, DREAD risk assessment, regulatory compliance evaluation, and economic impact modeling
- **Automated Report Generation**: Professional HTML reports with embedded visualizations
- **Modular Architecture**: Clean separation of concerns with independent analysis engines
- **Comprehensive Data Processing**: Real-time market data integration and synthetic data generation
- **Enterprise-Grade Logging**: Structured logging with configurable levels

## Architecture Overview

The platform follows modern backend design patterns:

- **Service Layer Architecture**: Each analysis framework operates as an independent service
- **Data Access Layer**: Centralized configuration management with JSON schema validation
- **Repository Pattern**: Structured data persistence with caching strategies
- **Factory Pattern**: Component-specific threat template generation
- **Observer Pattern**: Progress tracking and event-driven analysis updates

## Prerequisites

- **Python**: 3.8 or higher
- **Operating System**: macOS, Linux, or Windows
- **Memory**: Minimum 4GB RAM (8GB recommended for large analyses)
- **Storage**: 500MB free space for data and outputs

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/DinDin03/topics.git
cd topics
```

### 2. Set Up Python Environment

#### Using Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

#### Using Conda (Alternative)
```bash
conda create -n solar-security python=3.11
conda activate solar-security
```

### 3. Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt

# Verify installation
python -c "import pandas, numpy, matplotlib; print('Dependencies installed successfully')"
```

### 4. Initialize Project Structure

```python
# Run this in Python to create necessary directories
from src import initialize_project_structure
initialize_project_structure()
```

Or manually create directories:
```bash
mkdir -p data/vulnerabilities data/regulatory data/simulation
mkdir -p outputs config tests docs
```

### 5. Configuration Setup

The system uses the default configuration file `config/system_components.json`. This file contains the Adelaide Solar Inverter Network specification used in the research.

**No additional configuration required** - the system will automatically create default configurations if none exist.

## Quick Start Guide

### 1. Run Complete Analysis

Execute the comprehensive analysis across all frameworks:

```bash
# Run all analysis components
python -m src.vulnerability_analysis
python -m src.stride_threat_modeling  
python -m src.dread_assessment
python -m src.regulatory_analysis
python -m src.economic_impact
```

### 2. Generate Comprehensive Report

```bash
# Generate all reports and visualizations
python -m src.report_generator
```

### 3. View Results

After running the analysis, check the `outputs/` directory:

- `vulnerability_report.json` - CVE and vulnerability analysis
- `threat_model_results.json` - STRIDE threat modeling results
- `dread_assessment.json` - Quantitative risk assessment
- `regulatory_compliance_report.json` - Compliance analysis
- `economic_impact_analysis.json` - Economic impact modeling
- `economic_impact_summary.csv` - Summary spreadsheet

## Testing the System

### 1. Unit Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test modules
pytest tests/test_vulnerability_analysis.py -v
pytest tests/test_stride_modeling.py -v
pytest tests/test_economic_impact.py -v
```

### 2. Integration Testing

```bash
# Test complete analysis workflow
python -c "
from src.vulnerability_analysis import VulnerabilityAnalyzer
from src.stride_threat_modeling import StrideModel
from src.economic_impact import EconomicImpactCalculator

# Test each component
va = VulnerabilityAnalyzer()
va_results = va.run_comprehensive_analysis()
print(f'Vulnerability Analysis: {len(va_results)} results')

sm = StrideModel()
sm_results = sm.run_stride_analysis()
print(f'STRIDE Analysis: {sm_results[\"system_summary\"][\"total_threats\"]} threats identified')

eic = EconomicImpactCalculator()
eic_results = eic.run_comprehensive_economic_analysis()
print(f'Economic Analysis: ${eic_results[\"aggregated_metrics\"][\"total_potential_impact_aud\"]:,.0f} total potential impact')

print('All components working correctly!')
"
```

### 3. Validate Outputs

```bash
# Check that all expected output files are generated
ls -la outputs/
# Should show: vulnerability_report.json, threat_model_results.json, 
# dread_assessment.json, regulatory_compliance_report.json, 
# economic_impact_analysis.json, economic_impact_summary.csv
```

## Advanced Usage

### Custom System Configuration

To analyze a different solar inverter system:

1. Copy `config/system_components.json` to `config/custom_system.json`
2. Modify the configuration with your system specifications
3. Run analysis with custom config:

```python
from src.vulnerability_analysis import VulnerabilityAnalyzer

# Use custom configuration
analyzer = VulnerabilityAnalyzer(config_path="config/custom_system.json")
results = analyzer.run_comprehensive_analysis()
```

### Modifying Analysis Parameters

```python
# Example: Custom DREAD assessment
from src.dread_assessment import DreadAssessment

dread = DreadAssessment()
custom_threats = [
    {
        "id": "custom_threat_001",
        "description": "Your custom threat description",
        "stride_category": "SPOOFING",
        "affected_component": "inverter_001"
    }
]

scores = dread.assess_multiple_threats(custom_threats)
report = dread.generate_comprehensive_report()
```

### Economic Analysis Customization

```python
# Example: Custom attack scenario analysis
from src.economic_impact import EconomicImpactCalculator, AttackScenario

calculator = EconomicImpactCalculator()

# Analyze specific scenario with custom duration
impact = calculator.calculate_attack_scenario_impact(
    scenario=AttackScenario.FIRMWARE_INJECTION,
    duration_hours=48.0  # Custom duration
)

print(f"Economic impact: ${impact.total_economic_impact:,.2f}")
```

## Troubleshooting

### Common Issues

1. **Import Errors**
   ```bash
   # Ensure you're in the project root directory and virtual environment is activated
   pwd  # Should show solar-inverter-cybersecurity directory
   which python  # Should show virtual environment path
   ```

2. **Missing Dependencies**
   ```bash
   # Reinstall requirements
   pip install -r requirements.txt --force-reinstall
   ```

3. **Permission Errors**
   ```bash
   # Ensure output directories are writable
   chmod -R 755 outputs/ data/ config/
   ```

4. **Memory Issues**
   ```bash
   # Reduce analysis scope by modifying configuration
   # Or increase virtual memory if running on limited hardware
   ```

### Logging Configuration

Enable detailed logging for debugging:

```python
from src import setup_logging
import logging

# Enable debug logging
setup_logging(log_level=logging.DEBUG, log_file="debug.log")
```

### Performance Optimization

For faster analysis on large systems:

```python
# Example: Parallel processing for multiple components
import concurrent.futures
from src.vulnerability_analysis import VulnerabilityAnalyzer

analyzer = VulnerabilityAnalyzer()
# The system automatically optimizes for available CPU cores
```

## Understanding the Results

### Vulnerability Analysis Output
- **CVE Database**: Known vulnerabilities with CVSS scores
- **Protocol Analysis**: Security assessment of communication protocols
- **Risk Assessment**: Overall system risk scoring (0-10 scale)

### STRIDE Threat Modeling Output
- **Threat Inventory**: Systematic threats across 6 categories
- **Risk Distribution**: Threats classified by risk level
- **Component Analysis**: Vulnerability summary per component

### Economic Impact Analysis Output
- **Scenario Analysis**: 7 different attack scenarios with financial impact
- **Risk-Weighted Assessment**: Probability-adjusted economic exposure
- **ROI Analysis**: Cost-benefit analysis for security investments

### Regulatory Compliance Output
- **Framework Assessment**: Compliance scores for AEMO VPP, AS4777
- **Gap Analysis**: Specific non-compliance areas identified
- **Remediation Plans**: Prioritized recommendations

## Research Context

This platform implements the methodology described in "Security of Solar Inverters in Distributed Energy Systems" research project. The analysis focuses on South Australia's unique regulatory environment where mandatory API-based remote access creates additional cybersecurity challenges.

### Key Research Findings
- **Overall Risk Score**: 4.96/10 (Medium risk)
- **Total Economic Impact**: $930,267 AUD potential exposure
- **Regulatory Compliance**: 74.17% average compliance
- **Critical Vulnerabilities**: 2 CVEs identified affecting system components

## Contributing

This is a research project conducted by;

- **Student**: Dineth Katanwala
- **Supervisor**: Dr. Marian Mihailescu
