"""
Solar Inverter Cybersecurity Research Project

This package contains modules for analyzing cybersecurity vulnerabilities
in distributed energy systems, specifically focusing on solar inverters
in South Australia's regulatory environment.

Modules:
    vulnerability_analysis: Core vulnerability assessment tools
    stride_threat_modeling: STRIDE-based threat modeling implementation
    dread_assessment: DREAD risk assessment framework
    regulatory_analysis: South Australian regulatory compliance analysis
    economic_impact: Economic impact calculations and modeling
    report_generator: Automated report generation utilities

Author: Dineth Katanwala
Supervisor: Dr. Marian Mihailescu
"""

__version__ = "1.0.0"
__author__ = "Dineth Katanwala"
__email__ = "dineth.katanwala@student.university.edu.au"

# Import main classes and functions for easy access
from .vulnerability_analysis import VulnerabilityAnalyzer, CVEDatabase
from .stride_threat_modeling import StrideModel, ThreatComponent
from .dread_assessment import DreadAssessment, RiskCalculator
from .regulatory_analysis import RegulatoryCompliance, AEMORequirements
from .economic_impact import EconomicImpactCalculator, SpotPriceAnalyzer
from .report_generator import ReportGenerator, HTMLReportBuilder

# Define public API
__all__ = [
    # Core analysis classes
    'VulnerabilityAnalyzer',
    'CVEDatabase',
    'StrideModel',
    'ThreatComponent',
    'DreadAssessment',
    'RiskCalculator',
    
    # Regulatory and compliance
    'RegulatoryCompliance',
    'AEMORequirements',
    
    # Economic analysis
    'EconomicImpactCalculator',
    'SpotPriceAnalyzer',
    
    # Reporting
    'ReportGenerator',
    'HTMLReportBuilder',
]

# Package-level constants
DEFAULT_CONFIG_PATH = "config/system_components.json"
DEFAULT_OUTPUT_PATH = "outputs/"
DEFAULT_DATA_PATH = "data/"

# Logging configuration
import logging
from pathlib import Path

def setup_logging(log_level=logging.INFO, log_file=None):
    """
    Configure logging for the package.
    
    Args:
        log_level: Logging level (default: INFO)
        log_file: Optional log file path
    """
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    if log_file:
        logging.basicConfig(
            level=log_level,
            format=log_format,
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    else:
        logging.basicConfig(level=log_level, format=log_format)

# Version compatibility check
import sys
if sys.version_info < (3, 8):
    raise RuntimeError("This package requires Python 3.8 or higher")

# Package initialization
def initialize_project_structure():
    """
    Initialize the project directory structure if it doesn't exist.
    This is useful for first-time setup.
    """
    directories = [
        "data/vulnerabilities",
        "data/regulatory", 
        "data/simulation",
        "outputs",
        "config",
        "tests",
        "docs"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
    
    print("Project structure initialized successfully!")

# Error handling classes
class SolarInverterSecurityError(Exception):
    """Base exception class for the solar inverter security package."""
    pass

class VulnerabilityAnalysisError(SolarInverterSecurityError):
    """Raised when vulnerability analysis encounters an error."""
    pass

class ThreatModelingError(SolarInverterSecurityError):
    """Raised when threat modeling encounters an error."""
    pass

class RegulatoryComplianceError(SolarInverterSecurityError):
    """Raised when regulatory analysis encounters an error."""
    pass

class EconomicAnalysisError(SolarInverterSecurityError):
    """Raised when economic impact analysis encounters an error."""
    pass