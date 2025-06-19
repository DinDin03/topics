"""
Regulatory Analysis Module

This module analyzes compliance with South Australian energy regulations,
particularly focusing on the cybersecurity implications of mandatory
remote inverter access requirements.

Key Components:
- RegulatoryCompliance: Main compliance analysis engine
- AEMORequirements: AEMO VPP specific requirement analysis
- AS4777Analysis: Australian Standard 4777 compliance
- ComplianceReporter: Generate compliance reports and gap analysis

This module demonstrates how backend systems can handle regulatory
compliance requirements, which is crucial for enterprise applications.
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

# Configure logging
logger = logging.getLogger(__name__)

class ComplianceStatus(Enum):
    """Compliance status levels."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING_REVIEW = "PENDING_REVIEW"

class RegulatoryFramework(Enum):
    """Regulatory frameworks applicable to solar inverters in SA."""
    AEMO_VPP = "AEMO_VPP"                    # AEMO Virtual Power Plant requirements
    AS4777 = "AS4777"                        # Australian Standard for Grid Connection
    NER = "NER"                              # National Electricity Rules
    SA_SOLAR_POLICY = "SA_SOLAR_POLICY"      # South Australia Solar Policy
    CYBERSECURITY_ACT = "CYBERSECURITY_ACT"  # Cybersecurity legislation

@dataclass
class ComplianceRequirement:
    """
    Represents a single regulatory compliance requirement.
    
    This dataclass demonstrates how to model regulatory requirements
    in backend systems, which is important for compliance management.
    """
    requirement_id: str
    framework: RegulatoryFramework
    title: str
    description: str
    mandatory: bool
    implementation_deadline: Optional[datetime]
    compliance_criteria: List[str]
    verification_method: str
    penalty_for_non_compliance: str
    related_security_controls: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert requirement to dictionary."""
        data = {
            "requirement_id": self.requirement_id,
            "framework": self.framework.value,
            "title": self.title,
            "description": self.description,
            "mandatory": self.mandatory,
            "compliance_criteria": self.compliance_criteria,
            "verification_method": self.verification_method,
            "penalty_for_non_compliance": self.penalty_for_non_compliance,
            "related_security_controls": self.related_security_controls,
            "affected_components": self.affected_components
        }
        if self.implementation_deadline:
            data["implementation_deadline"] = self.implementation_deadline.isoformat()
        return data

@dataclass 
class ComplianceAssessment:
    """Assessment results for a specific requirement."""
    requirement_id: str
    status: ComplianceStatus
    compliance_score: float  # 0-100 percentage
    assessment_date: datetime
    evidence: List[str]
    gaps_identified: List[str]
    recommendations: List[str]
    assessor_notes: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment to dictionary."""
        return {
            "requirement_id": self.requirement_id,
            "status": self.status.value,
            "compliance_score": self.compliance_score,
            "assessment_date": self.assessment_date.isoformat(),
            "evidence": self.evidence,
            "gaps_identified": self.gaps_identified,
            "recommendations": self.recommendations,
            "assessor_notes": self.assessor_notes
        }

class AEMORequirements:
    """
    Analyzes compliance with AEMO Virtual Power Plant requirements.
    
    This class demonstrates how to implement specific regulatory
    analysis logic for complex compliance frameworks.
    """
    
    def __init__(self):
        self.requirements = self._load_aemo_requirements()
    
    def _load_aemo_requirements(self) -> List[ComplianceRequirement]:
        """Load AEMO VPP compliance requirements."""
        requirements = [
            ComplianceRequirement(
                requirement_id="AEMO_VPP_001",
                framework=RegulatoryFramework.AEMO_VPP,
                title="Mandatory Remote Access for Grid Management",
                description="Solar inverters must provide remote access capability to AEMO for grid stability management",
                mandatory=True,
                implementation_deadline=datetime(2024, 12, 31),
                compliance_criteria=[
                    "API endpoint available for AEMO access",
                    "Real-time status reporting implemented",
                    "Remote control capability enabled",
                    "Response time under 5 seconds for control commands"
                ],
                verification_method="Technical audit and testing",
                penalty_for_non_compliance="Disconnection from grid, financial penalties up to $10,000",
                related_security_controls=["api_authentication", "secure_communications", "access_logging"],
                affected_components=["api_endpoint", "communication_gateway", "solar_inverter"]
            ),
            ComplianceRequirement(
                requirement_id="AEMO_VPP_002", 
                framework=RegulatoryFramework.AEMO_VPP,
                title="Real-time Telemetry Data Provision",
                description="Continuous provision of operational telemetry data to AEMO systems",
                mandatory=True,
                implementation_deadline=datetime(2024, 12, 31),
                compliance_criteria=[
                    "Telemetry data transmitted every 5 minutes maximum",
                    "Data accuracy within ±2% tolerance",
                    "99.5% uptime requirement for data transmission",
                    "Standardized data format compliance"
                ],
                verification_method="Automated monitoring and periodic audits",
                penalty_for_non_compliance="Warning notices, potential grid disconnection",
                related_security_controls=["data_encryption", "integrity_checking", "availability_monitoring"],
                affected_components=["monitoring_system", "communication_gateway"]
            ),
            ComplianceRequirement(
                requirement_id="AEMO_VPP_003",
                framework=RegulatoryFramework.AEMO_VPP,
                title="Cybersecurity Standards Implementation",
                description="Implementation of cybersecurity controls to protect grid-connected systems",
                mandatory=False,  # Currently recommended, not mandatory
                implementation_deadline=datetime(2025, 6, 30),
                compliance_criteria=[
                    "Encryption of all remote communications",
                    "Multi-factor authentication for administrative access",
                    "Regular security assessments conducted",
                    "Incident response procedures documented"
                ],
                verification_method="Security audit and documentation review", 
                penalty_for_non_compliance="Future regulatory action possible",
                related_security_controls=["encryption", "authentication", "incident_response", "security_monitoring"],
                affected_components=["all_components"]
            ),
            ComplianceRequirement(
                requirement_id="AEMO_VPP_004",
                framework=RegulatoryFramework.AEMO_VPP,
                title="Emergency Response Capability",
                description="Ability to respond to emergency grid management commands within specified timeframes",
                mandatory=True,
                implementation_deadline=datetime(2024, 12, 31),
                compliance_criteria=[
                    "Emergency shutdown capability within 2 seconds",
                    "Power output limitation response within 5 seconds",
                    "Status confirmation transmitted within 10 seconds",
                    "Manual override capability maintained"
                ],
                verification_method="Emergency response testing and drills",
                penalty_for_non_compliance="Immediate grid disconnection, regulatory investigation",
                related_security_controls=["command_validation", "emergency_procedures", "system_monitoring"],
                affected_components=["solar_inverter", "api_endpoint", "communication_gateway"]
            )
        ]
        
        return requirements
    
    def assess_aemo_compliance(self, system_config: Dict[str, Any]) -> List[ComplianceAssessment]:
        """
        Assess system compliance with AEMO VPP requirements.
        
        Args:
            system_config: System configuration data
            
        Returns:
            List of compliance assessments
        """
        assessments = []
        
        for requirement in self.requirements:
            assessment = self._assess_single_requirement(requirement, system_config)
            assessments.append(assessment)
        
        return assessments
    
    def _assess_single_requirement(self, requirement: ComplianceRequirement, 
                                 system_config: Dict[str, Any]) -> ComplianceAssessment:
        """Assess compliance with a single AEMO requirement."""
        
        if requirement.requirement_id == "AEMO_VPP_001":
            return self._assess_remote_access_requirement(requirement, system_config)
        elif requirement.requirement_id == "AEMO_VPP_002":
            return self._assess_telemetry_requirement(requirement, system_config)
        elif requirement.requirement_id == "AEMO_VPP_003":
            return self._assess_cybersecurity_requirement(requirement, system_config)
        elif requirement.requirement_id == "AEMO_VPP_004":
            return self._assess_emergency_response_requirement(requirement, system_config)
        else:
            # Generic assessment for unknown requirements
            return ComplianceAssessment(
                requirement_id=requirement.requirement_id,
                status=ComplianceStatus.PENDING_REVIEW,
                compliance_score=0.0,
                assessment_date=datetime.now(),
                evidence=[],
                gaps_identified=["Manual assessment required"],
                recommendations=["Conduct detailed compliance review"]
            )
    
    def _assess_remote_access_requirement(self, requirement: ComplianceRequirement,
                                        system_config: Dict[str, Any]) -> ComplianceAssessment:
        """Assess AEMO remote access requirement."""
        score = 0.0
        evidence = []
        gaps = []
        recommendations = []
        
        # Check for API endpoints
        api_components = [comp for comp in system_config.get("components", []) 
                         if comp.get("type") == "api"]
        
        if api_components:
            score += 25
            evidence.append("API endpoint components found")
            
            # Check for AEMO-specific endpoints
            aemo_endpoints = [comp for comp in api_components 
                            if "aemo" in comp.get("name", "").lower() or 
                               "vpp" in comp.get("name", "").lower()]
            
            if aemo_endpoints:
                score += 25
                evidence.append("AEMO VPP API endpoint identified")
            else:
                gaps.append("No AEMO-specific API endpoint found")
                recommendations.append("Implement dedicated AEMO VPP API endpoint")
        else:
            gaps.append("No API endpoint components found")
            recommendations.append("Implement API endpoint for AEMO access")
        
        # Check for remote control capability
        control_endpoints = []
        for comp in api_components:
            endpoints = comp.get("api_endpoints", [])
            if any("control" in ep.lower() for ep in endpoints):
                control_endpoints.extend(endpoints)
        
        if control_endpoints:
            score += 25
            evidence.append("Remote control endpoints available")
        else:
            gaps.append("No remote control capability found")
            recommendations.append("Implement remote control API endpoints")
        
        # Check for real-time status reporting
        status_endpoints = []
        for comp in api_components:
            endpoints = comp.get("api_endpoints", [])
            if any("status" in ep.lower() for ep in endpoints):
                status_endpoints.extend(endpoints)
        
        if status_endpoints:
            score += 25
            evidence.append("Status reporting endpoints available")
        else:
            gaps.append("No status reporting capability found")
            recommendations.append("Implement real-time status reporting")
        
        # Determine compliance status
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
        elif score >= 50:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceAssessment(
            requirement_id=requirement.requirement_id,
            status=status,
            compliance_score=score,
            assessment_date=datetime.now(),
            evidence=evidence,
            gaps_identified=gaps,
            recommendations=recommendations,
            assessor_notes="Automated assessment based on system configuration"
        )
    
    def _assess_telemetry_requirement(self, requirement: ComplianceRequirement,
                                    system_config: Dict[str, Any]) -> ComplianceAssessment:
        """Assess telemetry data provision requirement."""
        score = 0.0
        evidence = []
        gaps = []
        recommendations = []
        
        # Check for monitoring components
        monitoring_components = [comp for comp in system_config.get("components", [])
                               if comp.get("type") in ["monitoring_system", "gateway"]]
        
        if monitoring_components:
            score += 30
            evidence.append("Monitoring system components found")
        else:
            gaps.append("No monitoring system found")
            recommendations.append("Implement monitoring system for telemetry collection")
        
        # Check for data flows to external systems
        data_flows = system_config.get("data_flows", [])
        external_flows = [flow for flow in data_flows 
                         if flow.get("crosses_trust_boundary", False)]
        
        if external_flows:
            score += 30
            evidence.append("External data transmission capabilities found")
        else:
            gaps.append("No external data transmission found")
            recommendations.append("Implement data transmission to AEMO systems")
        
        # Check for appropriate data types
        telemetry_data_types = ["power_output", "voltage_measurements", "status_information"]
        found_data_types = []
        
        for flow in data_flows:
            data_types = flow.get("data_types", [])
            for dt in data_types:
                if any(tel_type in dt.lower() for tel_type in 
                      ["power", "voltage", "current", "status"]):
                    found_data_types.append(dt)
        
        if found_data_types:
            score += 40
            evidence.append(f"Relevant telemetry data types found: {found_data_types}")
        else:
            gaps.append("No relevant telemetry data types identified")
            recommendations.append("Configure telemetry data collection for required parameters")
        
        # Determine compliance status
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
        elif score >= 50:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceAssessment(
            requirement_id=requirement.requirement_id,
            status=status,
            compliance_score=score,
            assessment_date=datetime.now(),
            evidence=evidence,
            gaps_identified=gaps,
            recommendations=recommendations
        )
    
    def _assess_cybersecurity_requirement(self, requirement: ComplianceRequirement,
                                        system_config: Dict[str, Any]) -> ComplianceAssessment:
        """Assess cybersecurity standards requirement."""
        score = 0.0
        evidence = []
        gaps = []
        recommendations = []
        
        # Check for encryption implementation
        encryption_count = 0
        for comp in system_config.get("components", []):
            security_controls = comp.get("security_controls", [])
            if any("encryption" in ctrl.lower() or "https" in ctrl.lower() or "tls" in ctrl.lower() 
                  for ctrl in security_controls):
                encryption_count += 1
        
        if encryption_count > 0:
            score += 25
            evidence.append(f"Encryption implemented on {encryption_count} components")
        else:
            gaps.append("No encryption implementation found")
            recommendations.append("Implement encryption for all communications")
        
        # Check for authentication mechanisms
        auth_count = 0
        for comp in system_config.get("components", []):
            security_controls = comp.get("security_controls", [])
            if any("auth" in ctrl.lower() for ctrl in security_controls):
                auth_count += 1
        
        if auth_count > 0:
            score += 25
            evidence.append(f"Authentication implemented on {auth_count} components")
        else:
            gaps.append("No authentication mechanisms found")
            recommendations.append("Implement strong authentication mechanisms")
        
        # Check for logging and monitoring
        logging_count = 0
        for comp in system_config.get("components", []):
            security_controls = comp.get("security_controls", [])
            if any("log" in ctrl.lower() or "monitor" in ctrl.lower() for ctrl in security_controls):
                logging_count += 1
        
        if logging_count > 0:
            score += 25
            evidence.append(f"Logging/monitoring implemented on {logging_count} components")
        else:
            gaps.append("No logging or monitoring found")
            recommendations.append("Implement comprehensive logging and monitoring")
        
        # Check network security
        network_config = system_config.get("network_topology", {})
        network_score = 0
        
        if network_config.get("firewall_enabled", False):
            network_score += 8
            evidence.append("Firewall protection enabled")
        else:
            gaps.append("No firewall protection")
            recommendations.append("Enable firewall protection")
        
        if network_config.get("network_segmentation", False):
            network_score += 8
            evidence.append("Network segmentation implemented")
        else:
            gaps.append("No network segmentation")
            recommendations.append("Implement network segmentation")
        
        if network_config.get("intrusion_detection", False):
            network_score += 9
            evidence.append("Intrusion detection system deployed")
        else:
            gaps.append("No intrusion detection system")
            recommendations.append("Deploy intrusion detection system")
        
        score += network_score
        
        # Determine compliance status
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
        elif score >= 50:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceAssessment(
            requirement_id=requirement.requirement_id,
            status=status,
            compliance_score=score,
            assessment_date=datetime.now(),
            evidence=evidence,
            gaps_identified=gaps,
            recommendations=recommendations
        )
    
    def _assess_emergency_response_requirement(self, requirement: ComplianceRequirement,
                                             system_config: Dict[str, Any]) -> ComplianceAssessment:
        """Assess emergency response capability requirement."""
        score = 0.0
        evidence = []
        gaps = []
        recommendations = []
        
        # Check for emergency control endpoints
        emergency_endpoints = []
        for comp in system_config.get("components", []):
            if comp.get("type") in ["solar_inverter", "api"]:
                endpoints = comp.get("api_endpoints", [])
                emergency_endpoints.extend([ep for ep in endpoints 
                                          if any(term in ep.lower() for term in 
                                               ["emergency", "shutdown", "control"])])
        
        if emergency_endpoints:
            score += 40
            evidence.append("Emergency control endpoints available")
        else:
            gaps.append("No emergency control endpoints found")
            recommendations.append("Implement emergency shutdown and control capabilities")
        
        # Check for real-time response capability
        data_flows = system_config.get("data_flows", [])
        realtime_flows = [flow for flow in data_flows 
                         if flow.get("frequency") in ["on_demand", "real_time", "1_second"]]
        
        if realtime_flows:
            score += 30
            evidence.append("Real-time communication capabilities found")
        else:
            gaps.append("No real-time communication capability")
            recommendations.append("Implement real-time response capability")
        
        # Check for manual override capability
        manual_override_found = False
        for comp in system_config.get("components", []):
            if comp.get("type") == "solar_inverter":
                features = comp.get("features", [])
                if any("manual" in feature.lower() or "override" in feature.lower() 
                      for feature in features):
                    manual_override_found = True
                    break
        
        if manual_override_found:
            score += 30
            evidence.append("Manual override capability available")
        else:
            gaps.append("No manual override capability found")
            recommendations.append("Implement manual override mechanisms")
        
        # Determine compliance status
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
        elif score >= 50:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceAssessment(
            requirement_id=requirement.requirement_id,
            status=status,
            compliance_score=score,
            assessment_date=datetime.now(),
            evidence=evidence,
            gaps_identified=gaps,
            recommendations=recommendations
        )

class AS4777Analysis:
    """
    Analyzes compliance with Australian Standard AS4777 for grid connection.
    
    AS4777 specifies requirements for connecting distributed energy resources
    to the electricity network.
    """
    
    def __init__(self):
        self.requirements = self._load_as4777_requirements()
    
    def _load_as4777_requirements(self) -> List[ComplianceRequirement]:
        """Load AS4777 compliance requirements."""
        requirements = [
            ComplianceRequirement(
                requirement_id="AS4777_001",
                framework=RegulatoryFramework.AS4777,
                title="Voltage Response Requirements",
                description="Inverter must respond appropriately to voltage variations",
                mandatory=True,
                implementation_deadline=datetime(2024, 12, 31),
                compliance_criteria=[
                    "Voltage ride-through capability implemented",
                    "Voltage regulation response within specified timeframes",
                    "Over/under voltage protection mechanisms",
                    "Voltage monitoring and reporting capability"
                ],
                verification_method="Laboratory testing and field verification",
                penalty_for_non_compliance="Grid connection refusal or disconnection",
                related_security_controls=["voltage_monitoring", "protection_systems"],
                affected_components=["solar_inverter"]
            ),
            ComplianceRequirement(
                requirement_id="AS4777_002",
                framework=RegulatoryFramework.AS4777,
                title="Frequency Response Requirements", 
                description="Inverter must respond to frequency variations to support grid stability",
                mandatory=True,
                implementation_deadline=datetime(2024, 12, 31),
                compliance_criteria=[
                    "Frequency ride-through capability",
                    "Over/under frequency protection",
                    "Frequency response within 2 seconds",
                    "Frequency monitoring accuracy ±0.01 Hz"
                ],
                verification_method="Type testing and commissioning verification",
                penalty_for_non_compliance="Grid connection rejection",
                related_security_controls=["frequency_monitoring", "response_systems"],
                affected_components=["solar_inverter"]
            )
        ]
        
        return requirements
    
    def assess_as4777_compliance(self, system_config: Dict[str, Any]) -> List[ComplianceAssessment]:
        """Assess AS4777 compliance."""
        assessments = []
        
        for requirement in self.requirements:
            # For AS4777, we'll do a basic assessment based on inverter capabilities
            assessment = self._assess_as4777_requirement(requirement, system_config)
            assessments.append(assessment)
        
        return assessments
    
    def _assess_as4777_requirement(self, requirement: ComplianceRequirement,
                                 system_config: Dict[str, Any]) -> ComplianceAssessment:
        """Assess individual AS4777 requirement."""
        # Basic assessment - in practice this would involve detailed technical testing
        inverters = [comp for comp in system_config.get("components", [])
                    if comp.get("type") == "solar_inverter"]
        
        score = 50.0  # Assume partial compliance pending technical verification
        evidence = ["System configuration reviewed"]
        gaps = ["Technical testing required for full verification"]
        recommendations = ["Conduct AS4777 compliance testing"]
        
        if inverters:
            evidence.append(f"Found {len(inverters)} solar inverter(s)")
            
            # Check for compliance indicators in configuration
            compliance_found = False
            for inverter in inverters:
                compliance_reqs = inverter.get("compliance_requirements", {})
                if compliance_reqs.get("as4777", False):
                    compliance_found = True
                    break
            
            if compliance_found:
                score = 90.0
                evidence.append("AS4777 compliance indicated in configuration")
                gaps = ["Verification testing recommended"]
            
        return ComplianceAssessment(
            requirement_id=requirement.requirement_id,
            status=ComplianceStatus.PARTIALLY_COMPLIANT if score >= 50 else ComplianceStatus.NON_COMPLIANT,
            compliance_score=score,
            assessment_date=datetime.now(),
            evidence=evidence,
            gaps_identified=gaps,
            recommendations=recommendations
        )

class RegulatoryCompliance:
    """
    Main regulatory compliance analysis engine.
    
    This class orchestrates compliance analysis across multiple regulatory
    frameworks and generates comprehensive compliance reports.
    """
    
    def __init__(self, config_path: str = "config/system_components.json"):
        self.config_path = Path(config_path)
        self.aemo_analyzer = AEMORequirements()
        self.as4777_analyzer = AS4777Analysis()
        self.system_config = self._load_system_config()
        self.compliance_results: Dict[str, List[ComplianceAssessment]] = {}
    
    def _load_system_config(self) -> Dict[str, Any]:
        """Load system configuration for compliance analysis."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Configuration file not found: {self.config_path}")
                return {}
        except Exception as e:
            logger.error(f"Error loading system configuration: {e}")
            return {}
    
    def run_comprehensive_compliance_analysis(self) -> Dict[str, Any]:
        """
        Run comprehensive compliance analysis across all frameworks.
        
        Returns:
            Complete compliance analysis results
        """
        logger.info("Starting comprehensive regulatory compliance analysis")
        
        # Analyze AEMO VPP compliance
        logger.info("Analyzing AEMO VPP compliance...")
        aemo_assessments = self.aemo_analyzer.assess_aemo_compliance(self.system_config)
        self.compliance_results["AEMO_VPP"] = aemo_assessments
        
        # Analyze AS4777 compliance
        logger.info("Analyzing AS4777 compliance...")
        as4777_assessments = self.as4777_analyzer.assess_as4777_compliance(self.system_config)
        self.compliance_results["AS4777"] = as4777_assessments
        
        # Generate summary analysis
        summary = self._generate_compliance_summary()
        
        # Generate recommendations
        recommendations = self._generate_compliance_recommendations()
        
        # Compile comprehensive results
        results = {
            "analysis_timestamp": datetime.now().isoformat(),
            "system_info": {
                "name": self.system_config.get("system_name", "Unknown"),
                "location": self.system_config.get("location", "Unknown"),
                "components_count": len(self.system_config.get("components", []))
            },
            "compliance_summary": summary,
            "framework_results": {
                framework: [assessment.to_dict() for assessment in assessments]
                for framework, assessments in self.compliance_results.items()
            },
            "recommendations": recommendations,
            "regulatory_context": self._analyze_regulatory_context()
        }
        
        logger.info("Regulatory compliance analysis completed")
        return results
    
    def _generate_compliance_summary(self) -> Dict[str, Any]:
        """Generate high-level compliance summary."""
        summary = {
            "overall_status": ComplianceStatus.NON_COMPLIANT.value,
            "frameworks_analyzed": len(self.compliance_results),
            "total_requirements": 0,
            "compliant_requirements": 0,
            "non_compliant_requirements": 0,
            "partially_compliant_requirements": 0,
            "average_compliance_score": 0.0,
            "framework_summaries": {}
        }
        
        all_scores = []
        total_requirements = 0
        status_counts = {status: 0 for status in ComplianceStatus}
        
        for framework, assessments in self.compliance_results.items():
            framework_scores = [assessment.compliance_score for assessment in assessments]
            framework_avg = sum(framework_scores) / len(framework_scores) if framework_scores else 0
            
            framework_status_counts = {status: 0 for status in ComplianceStatus}
            for assessment in assessments:
                framework_status_counts[assessment.status] += 1
                status_counts[assessment.status] += 1
            
            summary["framework_summaries"][framework] = {
                "requirements_count": len(assessments),
                "average_score": round(framework_avg, 2),
                "status_distribution": {status.value: count 
                                     for status, count in framework_status_counts.items()}
            }
            
            all_scores.extend(framework_scores)
            total_requirements += len(assessments)
        
        # Calculate overall metrics
        summary["total_requirements"] = total_requirements
        summary["compliant_requirements"] = status_counts[ComplianceStatus.COMPLIANT]
        summary["non_compliant_requirements"] = status_counts[ComplianceStatus.NON_COMPLIANT]
        summary["partially_compliant_requirements"] = status_counts[ComplianceStatus.PARTIALLY_COMPLIANT]
        
        if all_scores:
            summary["average_compliance_score"] = round(sum(all_scores) / len(all_scores), 2)
        
        # Determine overall status
        if status_counts[ComplianceStatus.NON_COMPLIANT] == 0:
            if status_counts[ComplianceStatus.PARTIALLY_COMPLIANT] == 0:
                summary["overall_status"] = ComplianceStatus.COMPLIANT.value
            else:
                summary["overall_status"] = ComplianceStatus.PARTIALLY_COMPLIANT.value
        else:
            summary["overall_status"] = ComplianceStatus.NON_COMPLIANT.value
        
        return summary
    
    def _generate_compliance_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized compliance recommendations."""
        recommendations = []
        
        # Collect all gaps and recommendations
        all_gaps = []
        all_recommendations = []
        
        for framework, assessments in self.compliance_results.items():
            for assessment in assessments:
                for gap in assessment.gaps_identified:
                    all_gaps.append({
                        "framework": framework,
                        "requirement": assessment.requirement_id,
                        "gap": gap,
                        "compliance_score": assessment.compliance_score
                    })
                
                for rec in assessment.recommendations:
                    all_recommendations.append({
                        "framework": framework,
                        "requirement": assessment.requirement_id,
                        "recommendation": rec,
                        "compliance_score": assessment.compliance_score
                    })
        
        # Prioritize recommendations based on compliance scores (lowest first)
        all_recommendations.sort(key=lambda x: x["compliance_score"])
        
        # Generate high-level recommendations
        if all_recommendations:
            priority_recommendations = [
                {
                    "priority": "HIGH",
                    "category": "Immediate Compliance Actions",
                    "description": "Address critical compliance gaps to avoid penalties",
                    "actions": [rec["recommendation"] for rec in all_recommendations[:5]]
                },
                {
                    "priority": "MEDIUM", 
                    "category": "Security Implementation",
                    "description": "Implement cybersecurity controls for regulatory compliance",
                    "actions": [
                        "Implement encryption for all communications",
                        "Deploy multi-factor authentication",
                        "Establish security monitoring and logging",
                        "Conduct regular security assessments"
                    ]
                },
                {
                    "priority": "LOW",
                    "category": "Continuous Improvement",
                    "description": "Ongoing compliance monitoring and improvement",
                    "actions": [
                        "Establish compliance monitoring processes",
                        "Regular compliance audits and assessments",
                        "Staff training on regulatory requirements",
                        "Compliance management system implementation"
                    ]
                }
            ]
            
            recommendations.extend(priority_recommendations)
        
        return recommendations
    
    def _analyze_regulatory_context(self) -> Dict[str, Any]:
        """Analyze regulatory context specific to South Australia."""
        context = {
            "south_australia_specifics": {
                "mandatory_remote_access": True,
                "aemo_vpp_participation_required": True,
                "cybersecurity_standards_recommended": True,
                "grid_support_functions_mandatory": True
            },
            "regulatory_timeline": {
                "current_phase": "Implementation Period",
                "key_deadlines": [
                    {
                        "date": "2024-12-31",
                        "requirement": "AEMO VPP compliance mandatory",
                        "status": "Pending"
                    },
                    {
                        "date": "2025-06-30", 
                        "requirement": "Cybersecurity standards recommended implementation",
                        "status": "Future"
                    }
                ]
            },
            "compliance_risks": [
                {
                    "risk": "Grid disconnection",
                    "trigger": "Non-compliance with AEMO VPP requirements",
                    "impact": "Loss of revenue, regulatory penalties"
                },
                {
                    "risk": "Cybersecurity incident",
                    "trigger": "Inadequate security controls",
                    "impact": "Grid instability, financial penalties, reputation damage"
                }
            ]
        }
        
        return context
    
    def export_compliance_report(self, output_path: str = "outputs/regulatory_compliance_report.json") -> None:
        """Export compliance analysis report."""
        results = self.run_comprehensive_compliance_analysis()
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Regulatory compliance report exported to {output_path}")

# Example usage and testing functions
def main():
    """Main function for testing the regulatory analysis module."""
    # Initialize regulatory compliance analyzer
    compliance_analyzer = RegulatoryCompliance()
    
    # Run comprehensive analysis
    results = compliance_analyzer.run_comprehensive_compliance_analysis()
    
    # Export results
    compliance_analyzer.export_compliance_report()
    
    # Print summary
    summary = results["compliance_summary"]
    print(f"Regulatory Compliance Analysis Results:")
    print(f"Overall Status: {summary['overall_status']}")
    print(f"Average Compliance Score: {summary['average_compliance_score']}%")
    print(f"Compliant Requirements: {summary['compliant_requirements']}/{summary['total_requirements']}")

if __name__ == "__main__":
    main()