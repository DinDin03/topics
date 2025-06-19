"""
STRIDE Threat Modeling Module

This module implements the STRIDE (Spoofing, Tampering, Repudiation, 
Information Disclosure, Denial of Service, Elevation of Privilege) 
threat modeling methodology for solar inverter systems.

STRIDE is a widely-used framework in cybersecurity for systematic 
threat identification and analysis. This implementation demonstrates:
- Object-oriented design patterns
- Security analysis frameworks
- Data flow diagram analysis
- Risk assessment methodologies

Key Components:
- StrideModel: Main threat modeling engine
- ThreatComponent: Represents system components and their threats
- DataFlow: Models data movement between components
- ThreatAnalyzer: Analyzes threats using STRIDE methodology
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import networkx as nx  # For modeling system architecture graphs

# Configure logging
logger = logging.getLogger(__name__)

class StrideCategory(Enum):
    """
    STRIDE threat categories.
    Each category represents a different type of security threat.
    """
    SPOOFING = "SPOOFING"                    # Identity spoofing attacks
    TAMPERING = "TAMPERING"                  # Data/system modification
    REPUDIATION = "REPUDIATION"              # Denial of actions performed
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"  # Unauthorized data access
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"  # Service availability attacks
    ELEVATION_OF_PRIVILEGE = "ELEVATION_OF_PRIVILEGE"  # Unauthorized access escalation

class ComponentType(Enum):
    """Types of components in the solar inverter system."""
    SOLAR_INVERTER = "SOLAR_INVERTER"
    COMMUNICATION_GATEWAY = "COMMUNICATION_GATEWAY"
    MONITORING_SYSTEM = "MONITORING_SYSTEM"
    API_ENDPOINT = "API_ENDPOINT"
    DATABASE = "DATABASE"
    WEB_INTERFACE = "WEB_INTERFACE"
    NETWORK_INFRASTRUCTURE = "NETWORK_INFRASTRUCTURE"
    EXTERNAL_SERVICE = "EXTERNAL_SERVICE"

class TrustBoundary(Enum):
    """Trust boundaries in the system architecture."""
    INTERNET = "INTERNET"                    # Public internet
    DMZ = "DMZ"                             # Demilitarized zone
    INTERNAL_NETWORK = "INTERNAL_NETWORK"    # Internal corporate network
    DEVICE_NETWORK = "DEVICE_NETWORK"        # IoT device network
    MANAGEMENT_NETWORK = "MANAGEMENT_NETWORK" # Network management zone

@dataclass
class Threat:
    """
    Represents a single security threat identified through STRIDE analysis.
    
    This dataclass demonstrates proper data modeling for security analysis,
    which is important for backend systems handling security data.
    """
    id: str
    title: str
    description: str
    stride_category: StrideCategory
    affected_component: str
    attack_vector: str
    impact_description: str
    likelihood: int  # 1-5 scale (1=very low, 5=very high)
    impact: int      # 1-5 scale (1=minimal, 5=catastrophic)
    risk_score: int = field(init=False)  # Calculated automatically
    mitigation_strategies: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        """Calculate risk score after object initialization."""
        self.risk_score = self.likelihood * self.impact
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert threat to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "stride_category": self.stride_category.value,
            "affected_component": self.affected_component,
            "attack_vector": self.attack_vector,
            "impact_description": self.impact_description,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "mitigation_strategies": self.mitigation_strategies,
            "references": self.references
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Threat':
        """Create threat object from dictionary."""
        data['stride_category'] = StrideCategory(data['stride_category'])
        return cls(**data)

@dataclass
class DataFlow:
    """
    Represents data flow between system components.
    
    Data flows are critical in threat modeling as they represent
    potential attack paths and trust boundary crossings.
    """
    id: str
    source_component: str
    destination_component: str
    data_description: str
    protocol: str
    encryption_in_transit: bool
    authentication_required: bool
    crosses_trust_boundary: bool
    trust_boundary_crossed: Optional[TrustBoundary] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert data flow to dictionary."""
        data = {
            "id": self.id,
            "source_component": self.source_component,
            "destination_component": self.destination_component,
            "data_description": self.data_description,
            "protocol": self.protocol,
            "encryption_in_transit": self.encryption_in_transit,
            "authentication_required": self.authentication_required,
            "crosses_trust_boundary": self.crosses_trust_boundary,
        }
        if self.trust_boundary_crossed:
            data["trust_boundary_crossed"] = self.trust_boundary_crossed.value
        return data

@dataclass
class ThreatComponent:
    """
    Represents a component in the system architecture.
    
    Each component can have multiple threats associated with it
    and participates in various data flows.
    """
    id: str
    name: str
    component_type: ComponentType
    description: str
    trust_boundary: TrustBoundary
    processes_data: List[str] = field(default_factory=list)
    stores_data: List[str] = field(default_factory=list)
    external_dependencies: List[str] = field(default_factory=list)
    security_controls: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert component to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "component_type": self.component_type.value,
            "description": self.description,
            "trust_boundary": self.trust_boundary.value,
            "processes_data": self.processes_data,
            "stores_data": self.stores_data,
            "external_dependencies": self.external_dependencies,
            "security_controls": self.security_controls
        }

class ThreatAnalyzer:
    """
    Analyzes system components for STRIDE threats.
    
    This class implements the core STRIDE analysis logic,
    demonstrating security analysis patterns and methodologies.
    """
    
    def __init__(self):
        self.threat_templates = self._load_threat_templates()
    
    def _load_threat_templates(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Load threat templates for different component types.
        
        In a real implementation, these would be loaded from a database
        or configuration file. This demonstrates how backend systems
        can use template patterns for scalable threat analysis.
        """
        return {
            ComponentType.SOLAR_INVERTER.value: [
                {
                    "stride_category": StrideCategory.SPOOFING,
                    "title": "Inverter Identity Spoofing",
                    "description": "Attacker impersonates legitimate inverter to inject malicious commands",
                    "attack_vector": "Network protocol manipulation",
                    "impact_description": "Unauthorized control of power generation",
                    "likelihood": 3,
                    "impact": 4,
                    "mitigation_strategies": [
                        "Implement device certificates",
                        "Use cryptographic device authentication",
                        "Monitor for unusual device behavior"
                    ]
                },
                {
                    "stride_category": StrideCategory.TAMPERING,
                    "title": "Firmware Tampering",
                    "description": "Malicious modification of inverter firmware",
                    "attack_vector": "Insecure firmware update mechanism",
                    "impact_description": "Complete device compromise",
                    "likelihood": 2,
                    "impact": 5,
                    "mitigation_strategies": [
                        "Implement code signing for firmware",
                        "Secure boot process",
                        "Firmware integrity checks"
                    ]
                },
                {
                    "stride_category": StrideCategory.DENIAL_OF_SERVICE,
                    "title": "Inverter Service Disruption",
                    "description": "Flooding inverter with requests to cause service disruption",
                    "attack_vector": "Network flooding attacks",
                    "impact_description": "Loss of power generation capacity",
                    "likelihood": 4,
                    "impact": 3,
                    "mitigation_strategies": [
                        "Implement rate limiting",
                        "Network traffic filtering",
                        "DDoS protection mechanisms"
                    ]
                },
                {
                    "stride_category": StrideCategory.INFORMATION_DISCLOSURE,
                    "title": "Power Generation Data Exposure",
                    "description": "Unauthorized access to sensitive power generation data",
                    "attack_vector": "Insecure data transmission",
                    "impact_description": "Competitive intelligence theft",
                    "likelihood": 3,
                    "impact": 2,
                    "mitigation_strategies": [
                        "Encrypt all data transmissions",
                        "Implement access controls",
                        "Data classification and handling procedures"
                    ]
                }
            ],
            ComponentType.API_ENDPOINT.value: [
                {
                    "stride_category": StrideCategory.SPOOFING,
                    "title": "API Authentication Bypass",
                    "description": "Attacker bypasses API authentication mechanisms",
                    "attack_vector": "Weak authentication implementation",
                    "impact_description": "Unauthorized API access",
                    "likelihood": 3,
                    "impact": 4,
                    "mitigation_strategies": [
                        "Implement strong authentication (OAuth 2.0, JWT)",
                        "Multi-factor authentication",
                        "Regular security audits"
                    ]
                },
                {
                    "stride_category": StrideCategory.TAMPERING,
                    "title": "API Request Manipulation",
                    "description": "Modification of API requests to perform unauthorized actions",
                    "attack_vector": "Man-in-the-middle attacks",
                    "impact_description": "Unauthorized system control",
                    "likelihood": 2,
                    "impact": 4,
                    "mitigation_strategies": [
                        "Use HTTPS for all API communications",
                        "Implement request signing",
                        "Input validation and sanitization"
                    ]
                },
                {
                    "stride_category": StrideCategory.ELEVATION_OF_PRIVILEGE,
                    "title": "API Privilege Escalation",
                    "description": "Attacker gains higher privileges than intended",
                    "attack_vector": "Authorization bypass vulnerabilities",
                    "impact_description": "Administrative access to system",
                    "likelihood": 2,
                    "impact": 5,
                    "mitigation_strategies": [
                        "Implement proper authorization checks",
                        "Principle of least privilege",
                        "Regular access reviews"
                    ]
                }
            ],
            ComponentType.COMMUNICATION_GATEWAY.value: [
                {
                    "stride_category": StrideCategory.SPOOFING,
                    "title": "Gateway Impersonation",
                    "description": "Attacker impersonates communication gateway",
                    "attack_vector": "Network protocol vulnerabilities",
                    "impact_description": "Unauthorized network access",
                    "likelihood": 3,
                    "impact": 4,
                    "mitigation_strategies": [
                        "Device certificates and PKI",
                        "Network access control",
                        "Regular device authentication"
                    ]
                },
                {
                    "stride_category": StrideCategory.DENIAL_OF_SERVICE,
                    "title": "Gateway Resource Exhaustion",
                    "description": "Overwhelming gateway with traffic to cause failure",
                    "attack_vector": "Resource exhaustion attacks",
                    "impact_description": "Communication network disruption",
                    "likelihood": 3,
                    "impact": 4,
                    "mitigation_strategies": [
                        "Implement quality of service controls",
                        "Resource monitoring and alerting",
                        "Traffic shaping and prioritization"
                    ]
                }
            ]
        }
    
    def analyze_component_threats(self, component: ThreatComponent) -> List[Threat]:
        """
        Analyze a specific component for STRIDE threats.
        
        Args:
            component: The component to analyze
            
        Returns:
            List of identified threats for the component
        """
        threats = []
        component_templates = self.threat_templates.get(component.component_type.value, [])
        
        for template in component_templates:
            threat_id = f"{component.id}_{template['stride_category'].value}_{len(threats)+1}"
            
            threat = Threat(
                id=threat_id,
                title=template["title"],
                description=template["description"],
                stride_category=template["stride_category"],
                affected_component=component.id,
                attack_vector=template["attack_vector"],
                impact_description=template["impact_description"],
                likelihood=template["likelihood"],
                impact=template["impact"],
                mitigation_strategies=template["mitigation_strategies"].copy()
            )
            
            # Adjust threat likelihood based on component security controls
            threat.likelihood = self._adjust_likelihood_for_controls(
                threat, component.security_controls
            )
            
            threats.append(threat)
        
        return threats
    
    def _adjust_likelihood_for_controls(self, threat: Threat, security_controls: List[str]) -> int:
        """
        Adjust threat likelihood based on existing security controls.
        
        This demonstrates how security controls can reduce threat likelihood,
        which is important for risk-based security management.
        """
        likelihood = threat.likelihood
        
        # Define control effectiveness mappings
        control_reductions = {
            "encryption": {StrideCategory.INFORMATION_DISCLOSURE: 2, StrideCategory.TAMPERING: 1},
            "authentication": {StrideCategory.SPOOFING: 2, StrideCategory.ELEVATION_OF_PRIVILEGE: 1},
            "access_control": {StrideCategory.ELEVATION_OF_PRIVILEGE: 2, StrideCategory.SPOOFING: 1},
            "rate_limiting": {StrideCategory.DENIAL_OF_SERVICE: 2},
            "input_validation": {StrideCategory.TAMPERING: 1},
            "logging": {StrideCategory.REPUDIATION: 2},
            "monitoring": {StrideCategory.DENIAL_OF_SERVICE: 1, StrideCategory.SPOOFING: 1}
        }
        
        for control in security_controls:
            control_lower = control.lower()
            for control_name, reductions in control_reductions.items():
                if control_name in control_lower:
                    reduction = reductions.get(threat.stride_category, 0)
                    likelihood = max(1, likelihood - reduction)
        
        return likelihood

class StrideModel:
    """
    Main STRIDE threat modeling engine for solar inverter systems.
    
    This class orchestrates the entire threat modeling process,
    demonstrating enterprise-level security analysis capabilities
    that would be valuable in backend security systems.
    """
    
    def __init__(self, config_path: str = "config/system_components.json"):
        self.config_path = Path(config_path)
        self.components: List[ThreatComponent] = []
        self.data_flows: List[DataFlow] = []
        self.threats: List[Threat] = []
        self.threat_analyzer = ThreatAnalyzer()
        self.system_graph = nx.DiGraph()  # NetworkX graph for system modeling
        
        # Load system configuration
        self._load_system_configuration()
    
    def _load_system_configuration(self) -> None:
        """Load system configuration and build threat model."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                self._build_components_from_config(config)
                self._build_data_flows_from_config(config)
            else:
                logger.warning(f"Configuration file not found: {self.config_path}")
                self._create_default_model()
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            self._create_default_model()
    
    def _build_components_from_config(self, config: Dict[str, Any]) -> None:
        """Build threat model components from configuration."""
        self.components = []
        
        for comp_config in config.get("components", []):
            # Map component types
            comp_type_map = {
                "solar_inverter": ComponentType.SOLAR_INVERTER,
                "gateway": ComponentType.COMMUNICATION_GATEWAY,
                "api": ComponentType.API_ENDPOINT,
                "database": ComponentType.DATABASE,
                "web_interface": ComponentType.WEB_INTERFACE
            }
            
            component_type = comp_type_map.get(
                comp_config.get("type", ""), 
                ComponentType.SOLAR_INVERTER
            )
            
            # Determine trust boundary based on component type and network exposure
            trust_boundary = self._determine_trust_boundary(comp_config)
            
            component = ThreatComponent(
                id=comp_config["id"],
                name=comp_config.get("name", comp_config["id"]),
                component_type=component_type,
                description=comp_config.get("description", ""),
                trust_boundary=trust_boundary,
                processes_data=comp_config.get("processes_data", []),
                stores_data=comp_config.get("stores_data", []),
                external_dependencies=comp_config.get("external_dependencies", []),
                security_controls=comp_config.get("security_controls", [])
            )
            
            self.components.append(component)
            self.system_graph.add_node(component.id, component=component)
    
    def _determine_trust_boundary(self, comp_config: Dict[str, Any]) -> TrustBoundary:
        """Determine appropriate trust boundary for component."""
        if comp_config.get("internet_facing", False):
            return TrustBoundary.INTERNET
        elif comp_config.get("type") == "api":
            return TrustBoundary.DMZ
        elif comp_config.get("type") in ["solar_inverter", "gateway"]:
            return TrustBoundary.DEVICE_NETWORK
        else:
            return TrustBoundary.INTERNAL_NETWORK
    
    def _build_data_flows_from_config(self, config: Dict[str, Any]) -> None:
        """Build data flows from configuration."""
        self.data_flows = []
        
        # Generate data flows based on component relationships
        for comp_config in config.get("components", []):
            comp_id = comp_config["id"]
            
            # API endpoints
            for endpoint in comp_config.get("api_endpoints", []):
                data_flow = DataFlow(
                    id=f"flow_{comp_id}_api_{len(self.data_flows)}",
                    source_component="external_client",
                    destination_component=comp_id,
                    data_description=f"API requests to {endpoint}",
                    protocol="HTTPS",
                    encryption_in_transit=True,
                    authentication_required=True,
                    crosses_trust_boundary=True,
                    trust_boundary_crossed=TrustBoundary.INTERNET
                )
                self.data_flows.append(data_flow)
                self.system_graph.add_edge("external_client", comp_id, data_flow=data_flow)
            
            # Protocol communications
            for protocol in comp_config.get("protocols", []):
                if protocol.lower() in ["modbus", "mqtt"]:
                    data_flow = DataFlow(
                        id=f"flow_{comp_id}_{protocol}_{len(self.data_flows)}",
                        source_component=comp_id,
                        destination_component="monitoring_system",
                        data_description=f"{protocol.upper()} telemetry data",
                        protocol=protocol.upper(),
                        encryption_in_transit=protocol.lower() == "mqtt",
                        authentication_required=False,
                        crosses_trust_boundary=False
                    )
                    self.data_flows.append(data_flow)
                    self.system_graph.add_edge(comp_id, "monitoring_system", data_flow=data_flow)
    
    def _create_default_model(self) -> None:
        """Create a default threat model for demonstration."""
        # Default solar inverter component
        inverter = ThreatComponent(
            id="inverter_001",
            name="Solar Inverter SG5KTL",
            component_type=ComponentType.SOLAR_INVERTER,
            description="Primary solar inverter converting DC to AC power",
            trust_boundary=TrustBoundary.DEVICE_NETWORK,
            processes_data=["power_generation_data", "control_commands"],
            stores_data=["configuration_data", "operational_logs"],
            security_controls=["basic_authentication"]
        )
        
        # Communication gateway
        gateway = ThreatComponent(
            id="gateway_001",
            name="IoT Communication Gateway",
            component_type=ComponentType.COMMUNICATION_GATEWAY,
            description="Gateway for aggregating and forwarding inverter data",
            trust_boundary=TrustBoundary.DEVICE_NETWORK,
            processes_data=["aggregated_telemetry", "control_commands"],
            security_controls=["encryption", "authentication"]
        )
        
        # API endpoint
        api = ThreatComponent(
            id="api_001",
            name="AEMO VPP API Endpoint",
            component_type=ComponentType.API_ENDPOINT,
            description="API endpoint for AEMO Virtual Power Plant integration",
            trust_boundary=TrustBoundary.DMZ,
            processes_data=["control_commands", "status_data"],
            security_controls=["https", "api_authentication", "rate_limiting"]
        )
        
        self.components = [inverter, gateway, api]
        
        # Build system graph
        for component in self.components:
            self.system_graph.add_node(component.id, component=component)
    
    def run_stride_analysis(self) -> Dict[str, Any]:
        """
        Run complete STRIDE analysis on the system.
        
        Returns:
            Comprehensive threat analysis results
        """
        logger.info("Starting STRIDE threat analysis")
        
        # Clear previous threats
        self.threats = []
        
        # Analyze each component
        for component in self.components:
            logger.info(f"Analyzing component: {component.name}")
            component_threats = self.threat_analyzer.analyze_component_threats(component)
            self.threats.extend(component_threats)
        
        # Analyze data flows for additional threats
        data_flow_threats = self._analyze_data_flow_threats()
        self.threats.extend(data_flow_threats)
        
        # Generate analysis results
        results = self._generate_analysis_results()
        
        logger.info(f"STRIDE analysis completed. Found {len(self.threats)} threats")
        return results
    
    def _analyze_data_flow_threats(self) -> List[Threat]:
        """Analyze data flows for crossing trust boundaries and other risks."""
        threats = []
        
        for data_flow in self.data_flows:
            if data_flow.crosses_trust_boundary and not data_flow.encryption_in_transit:
                threat = Threat(
                    id=f"dataflow_{data_flow.id}_encryption",
                    title="Unencrypted Trust Boundary Crossing",
                    description=f"Data flow {data_flow.id} crosses trust boundary without encryption",
                    stride_category=StrideCategory.INFORMATION_DISCLOSURE,
                    affected_component=data_flow.destination_component,
                    attack_vector="Network interception",
                    impact_description="Sensitive data exposure",
                    likelihood=4,
                    impact=3,
                    mitigation_strategies=[
                        "Implement TLS/SSL encryption",
                        "Use VPN for sensitive communications",
                        "Implement end-to-end encryption"
                    ]
                )
                threats.append(threat)
            
            if not data_flow.authentication_required and data_flow.crosses_trust_boundary:
                threat = Threat(
                    id=f"dataflow_{data_flow.id}_auth",
                    title="Unauthenticated Trust Boundary Access",
                    description=f"Data flow {data_flow.id} allows unauthenticated access across trust boundary",
                    stride_category=StrideCategory.SPOOFING,
                    affected_component=data_flow.destination_component,
                    attack_vector="Identity spoofing",
                    impact_description="Unauthorized system access",
                    likelihood=3,
                    impact=4,
                    mitigation_strategies=[
                        "Implement strong authentication",
                        "Use mutual TLS authentication",
                        "Deploy certificate-based authentication"
                    ]
                )
                threats.append(threat)
        
        return threats
    
    def _generate_analysis_results(self) -> Dict[str, Any]:
        """Generate comprehensive analysis results."""
        # Categorize threats by STRIDE category
        stride_breakdown = {}
        for category in StrideCategory:
            stride_breakdown[category.value] = [
                threat for threat in self.threats 
                if threat.stride_category == category
            ]
        
        # Risk distribution
        risk_distribution = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
        for threat in self.threats:
            if threat.risk_score <= 5:
                risk_distribution["LOW"] += 1
            elif threat.risk_score <= 10:
                risk_distribution["MEDIUM"] += 1
            elif threat.risk_score <= 15:
                risk_distribution["HIGH"] += 1
            else:
                risk_distribution["CRITICAL"] += 1
        
        # Component vulnerability summary
        component_summary = {}
        for component in self.components:
            component_threats = [t for t in self.threats if t.affected_component == component.id]
            avg_risk = sum(t.risk_score for t in component_threats) / len(component_threats) if component_threats else 0
            
            component_summary[component.id] = {
                "name": component.name,
                "type": component.component_type.value,
                "threat_count": len(component_threats),
                "average_risk_score": round(avg_risk, 2),
                "highest_risk_threat": max(component_threats, key=lambda t: t.risk_score).title if component_threats else None
            }
        
        # Top threats by risk score
        top_threats = sorted(self.threats, key=lambda t: t.risk_score, reverse=True)[:10]
        
        return {
            "analysis_timestamp": datetime.now().isoformat(),
            "system_summary": {
                "total_components": len(self.components),
                "total_data_flows": len(self.data_flows),
                "total_threats": len(self.threats)
            },
            "stride_breakdown": {
                category: len(threats) for category, threats in stride_breakdown.items()
            },
            "risk_distribution": risk_distribution,
            "component_summary": component_summary,
            "top_threats": [threat.to_dict() for threat in top_threats],
            "all_threats": [threat.to_dict() for threat in self.threats],
            "mitigation_recommendations": self._generate_mitigation_recommendations()
        }
    
    def _generate_mitigation_recommendations(self) -> List[Dict[str, Any]]:
        """Generate prioritized mitigation recommendations."""
        # Collect all mitigation strategies and their frequency
        mitigation_counts = {}
        for threat in self.threats:
            for mitigation in threat.mitigation_strategies:
                if mitigation not in mitigation_counts:
                    mitigation_counts[mitigation] = {
                        "count": 0,
                        "total_risk": 0,
                        "threat_ids": []
                    }
                mitigation_counts[mitigation]["count"] += 1
                mitigation_counts[mitigation]["total_risk"] += threat.risk_score
                mitigation_counts[mitigation]["threat_ids"].append(threat.id)
        
        # Sort by impact (count * average risk)
        recommendations = []
        for mitigation, data in mitigation_counts.items():
            avg_risk = data["total_risk"] / data["count"]
            impact_score = data["count"] * avg_risk
            
            recommendations.append({
                "mitigation": mitigation,
                "threat_count": data["count"],
                "average_risk_reduction": round(avg_risk, 2),
                "impact_score": round(impact_score, 2),
                "affected_threats": data["threat_ids"]
            })
        
        # Sort by impact score (highest first)
        recommendations.sort(key=lambda x: x["impact_score"], reverse=True)
        
        return recommendations[:15]  # Return top 15 recommendations
    
    def export_threat_model(self, output_path: str = "outputs/threat_model_results.json") -> None:
        """Export threat model results to JSON file."""
        results = self.run_stride_analysis()
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Threat model exported to {output_path}")
    
    def generate_data_flow_diagram(self) -> Dict[str, Any]:
        """
        Generate data flow diagram representation.
        
        Returns:
            Dictionary representation of the system architecture
            suitable for visualization tools
        """
        nodes = []
        edges = []
        
        # Add components as nodes
        for component in self.components:
            nodes.append({
                "id": component.id,
                "label": component.name,
                "type": component.component_type.value,
                "trust_boundary": component.trust_boundary.value,
                "threat_count": len([t for t in self.threats if t.affected_component == component.id])
            })
        
        # Add data flows as edges
        for data_flow in self.data_flows:
            edges.append({
                "source": data_flow.source_component,
                "target": data_flow.destination_component,
                "label": data_flow.data_description,
                "protocol": data_flow.protocol,
                "encrypted": data_flow.encryption_in_transit,
                "crosses_trust_boundary": data_flow.crosses_trust_boundary
            })
        
        return {
            "nodes": nodes,
            "edges": edges,
            "trust_boundaries": [boundary.value for boundary in TrustBoundary]
        }

# Example usage and testing functions
def main():
    """Main function for testing the STRIDE threat modeling module."""
    # Initialize STRIDE model
    stride_model = StrideModel()
    
    # Run analysis
    results = stride_model.run_stride_analysis()
    
    # Export results
    stride_model.export_threat_model()
    
    # Print summary
    print(f"STRIDE Analysis Results:")
    print(f"Total threats identified: {results['system_summary']['total_threats']}")
    print(f"High/Critical risk threats: {results['risk_distribution']['HIGH'] + results['risk_distribution']['CRITICAL']}")
    
    # Print top 3 threats
    print("\nTop 3 Threats:")
    for i, threat in enumerate(results['top_threats'][:3], 1):
        print(f"{i}. {threat['title']} (Risk Score: {threat['risk_score']})")

if __name__ == "__main__":
    main()