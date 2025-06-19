__version__ = "1.0.0"
__author__ = "Dineth Katanwala"
__email__ = "dineth.katanwala@student.university.edu.au"

from .vulnerability_analysis import VulnerabilityAnalyzer, CVEDatabase
from .stride_threat_modeling import StrideModel, ThreatComponent
from .dread_assessment import DreadAssessment, RiskCalculator
from .regulatory_analysis import RegulatoryCompliance, AEMORequirements
from .economic_impact import EconomicImpactCalculator, SpotPriceAnalyzer
from .report_generator import ReportGenerator, HTMLReportBuilder

__all__ = [
    'VulnerabilityAnalyzer',
    'CVEDatabase',
    'StrideModel',
    'ThreatComponent',
    'DreadAssessment',
    'RiskCalculator',
    
    'RegulatoryCompliance',
    'AEMORequirements',
    
    'EconomicImpactCalculator',
    'SpotPriceAnalyzer',
    
    'ReportGenerator',
    'HTMLReportBuilder',
]

DEFAULT_CONFIG_PATH = "config/system_components.json"
DEFAULT_OUTPUT_PATH = "outputs/"
DEFAULT_DATA_PATH = "data/"

import logging
from pathlib import Path

def setup_logging(log_level=logging.INFO, log_file=None):
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

import sys
if sys.version_info < (3, 8):
    raise RuntimeError("This package requires Python 3.8 or higher")

# Package initialization
def initialize_project_structure():
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
    pass

class VulnerabilityAnalysisError(SolarInverterSecurityError):
    pass

class ThreatModelingError(SolarInverterSecurityError):
    pass

class RegulatoryComplianceError(SolarInverterSecurityError):
    pass

class EconomicAnalysisError(SolarInverterSecurityError):
    pass