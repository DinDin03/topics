import json
import logging
import statistics
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

class DreadComponent(Enum):
    DAMAGE = "DAMAGE"                      
    REPRODUCIBILITY = "REPRODUCIBILITY"   
    EXPLOITABILITY = "EXPLOITABILITY"    
    AFFECTED_USERS = "AFFECTED_USERS"    
    DISCOVERABILITY = "DISCOVERABILITY"     

@dataclass
class DreadScore:
    threat_id: str
    damage: int            
    reproducibility: int   
    exploitability: int      
    affected_users: int
    discoverability: int     
    
    total_score: float = field(init=False)
    average_score: float = field(init=False)
    risk_level: str = field(init=False)
    
    def __post_init__(self):
        self.total_score = (
            self.damage + self.reproducibility + self.exploitability + 
            self.affected_users + self.discoverability
        )
        self.average_score = self.total_score / 5
        self.risk_level = self._calculate_risk_level()
    
    def _calculate_risk_level(self) -> str:
        if self.average_score >= 8:
            return "CRITICAL"
        elif self.average_score >= 6:
            return "HIGH" 
        elif self.average_score >= 4:
            return "MEDIUM"
        elif self.average_score >= 2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "damage": self.damage,
            "reproducibility": self.reproducibility,
            "exploitability": self.exploitability,
            "affected_users": self.affected_users,
            "discoverability": self.discoverability,
            "total_score": self.total_score,
            "average_score": round(self.average_score, 2),
            "risk_level": self.risk_level
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DreadScore':
        return cls(
            threat_id=data["threat_id"],
            damage=data["damage"],
            reproducibility=data["reproducibility"],
            exploitability=data["exploitability"],
            affected_users=data["affected_users"],
            discoverability=data["discoverability"]
        )

class RiskCalculator:
    @staticmethod
    def calculate_weighted_dread_score(dread_score: DreadScore, 
                                     weights: Dict[str, float] = None) -> float:
        if weights is None:
            weights = {
                "damage": 0.2,
                "reproducibility": 0.2,
                "exploitability": 0.2,
                "affected_users": 0.2,
                "discoverability": 0.2
            }
        
        weighted_score = (
            dread_score.damage * weights.get("damage", 0.2) +
            dread_score.reproducibility * weights.get("reproducibility", 0.2) +
            dread_score.exploitability * weights.get("exploitability", 0.2) +
            dread_score.affected_users * weights.get("affected_users", 0.2) +
            dread_score.discoverability * weights.get("discoverability", 0.2)
        )
        
        return round(weighted_score, 2)
    
    @staticmethod
    def calculate_risk_metrics(dread_scores: List[DreadScore]) -> Dict[str, Any]:
        if not dread_scores:
            return {"error": "No DREAD scores provided"}
        
        total_scores = [score.total_score for score in dread_scores]
        average_scores = [score.average_score for score in dread_scores]
        damage_scores = [score.damage for score in dread_scores]
        
        metrics = {
            "count": len(dread_scores),
            "total_score_stats": {
                "mean": round(statistics.mean(total_scores), 2),
                "median": round(statistics.median(total_scores), 2),
                "std_dev": round(statistics.stdev(total_scores) if len(total_scores) > 1 else 0, 2),
                "min": min(total_scores),
                "max": max(total_scores)
            },
            "average_score_stats": {
                "mean": round(statistics.mean(average_scores), 2),
                "median": round(statistics.median(average_scores), 2),
                "std_dev": round(statistics.stdev(average_scores) if len(average_scores) > 1 else 0, 2)
            },
            "risk_level_distribution": RiskCalculator._calculate_risk_distribution(dread_scores),
            "component_analysis": RiskCalculator._analyze_dread_components(dread_scores)
        }
        
        return metrics
    
    @staticmethod
    def _calculate_risk_distribution(dread_scores: List[DreadScore]) -> Dict[str, int]:
        """Calculate distribution of risk levels."""
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
        
        for score in dread_scores:
            distribution[score.risk_level] += 1
        
        return distribution
    
    @staticmethod
    def _analyze_dread_components(dread_scores: List[DreadScore]) -> Dict[str, Dict[str, float]]:
        components = {
            "damage": [score.damage for score in dread_scores],
            "reproducibility": [score.reproducibility for score in dread_scores],
            "exploitability": [score.exploitability for score in dread_scores],
            "affected_users": [score.affected_users for score in dread_scores],
            "discoverability": [score.discoverability for score in dread_scores]
        }
        
        analysis = {}
        for component_name, scores in components.items():
            analysis[component_name] = {
                "mean": round(statistics.mean(scores), 2),
                "median": round(statistics.median(scores), 2),
                "max": max(scores),
                "min": min(scores)
            }
        
        return analysis

class ThreatPrioritizer:
    def __init__(self, custom_weights: Dict[str, float] = None):
        self.custom_weights = custom_weights or {
            "damage": 0.3,          # Higher weight for damage potential
            "reproducibility": 0.15,
            "exploitability": 0.25,  # Higher weight for ease of exploitation
            "affected_users": 0.2,   # Important for impact assessment
            "discoverability": 0.1   # Lower weight for discoverability
        }
    
    def prioritize_threats(self, dread_scores: List[DreadScore], 
                          limit: int = None) -> List[Tuple[str, float, str]]:
        weighted_threats = []
        for dread_score in dread_scores:
            weighted_score = RiskCalculator.calculate_weighted_dread_score(
                dread_score, self.custom_weights
            )
            weighted_threats.append((
                dread_score.threat_id, 
                weighted_score, 
                dread_score.risk_level
            ))
        
        weighted_threats.sort(key=lambda x: x[1], reverse=True)
        
        if limit:
            weighted_threats = weighted_threats[:limit]
        
        return weighted_threats
    
    def generate_priority_matrix(self, dread_scores: List[DreadScore]) -> Dict[str, List[str]]:
        matrix = {
            "high_risk_high_exploitability": [],    # Immediate attention
            "high_risk_low_exploitability": [],     # Important but less urgent
            "low_risk_high_exploitability": [],     # Monitor closely
            "low_risk_low_exploitability": []       # Lower priority
        }
        
        for dread_score in dread_scores:
            risk_score = (dread_score.damage + dread_score.affected_users) / 2
            high_risk = risk_score >= 6
            
            exploit_score = (dread_score.reproducibility + dread_score.exploitability) / 2
            high_exploitability = exploit_score >= 6
            
            if high_risk and high_exploitability:
                matrix["high_risk_high_exploitability"].append(dread_score.threat_id)
            elif high_risk and not high_exploitability:
                matrix["high_risk_low_exploitability"].append(dread_score.threat_id)
            elif not high_risk and high_exploitability:
                matrix["low_risk_high_exploitability"].append(dread_score.threat_id)
            else:
                matrix["low_risk_low_exploitability"].append(dread_score.threat_id)
        
        return matrix

class DreadAssessment:
    def __init__(self, threats_data_path: str = None):
        self.threats_data_path = threats_data_path
        self.dread_scores: List[DreadScore] = []
        self.risk_calculator = RiskCalculator()
        self.threat_prioritizer = ThreatPrioritizer()
        self.assessment_rules = self._load_assessment_rules()
    
    def _load_assessment_rules(self) -> Dict[str, Any]:
        return {
            "damage_scoring": {
                "1-2": "Minimal impact, no data loss, brief service interruption",
                "3-4": "Minor impact, limited data exposure, short-term service disruption", 
                "5-6": "Moderate impact, some sensitive data compromised, extended downtime",
                "7-8": "Significant impact, major data breach, long-term service disruption",
                "9-10": "Catastrophic impact, complete system compromise, permanent damage"
            },
            "reproducibility_scoring": {
                "1-2": "Very difficult to reproduce, requires specific conditions",
                "3-4": "Somewhat difficult, requires some technical knowledge",
                "5-6": "Moderately easy, standard attack tools available",
                "7-8": "Easy to reproduce, well-documented exploit methods",
                "9-10": "Trivial to reproduce, automated tools available"
            },
            "exploitability_scoring": {
                "1-2": "Very difficult, requires extensive expertise and resources",
                "3-4": "Difficult, requires significant technical skills",
                "5-6": "Moderate difficulty, requires some technical knowledge",
                "7-8": "Easy, basic technical skills sufficient",
                "9-10": "Trivial, no technical skills required"
            },
            "affected_users_scoring": {
                "1-2": "Individual users or single device",
                "3-4": "Small group of users or few devices", 
                "5-6": "Department or moderate number of devices",
                "7-8": "Organization-wide or large device network",
                "9-10": "Multi-organisation or entire grid infrastructure"
            },
            "discoverability_scoring": {
                "1-2": "Very difficult to find, requires insider knowledge",
                "3-4": "Difficult to find, requires detailed system knowledge",
                "5-6": "Moderate, visible to security researchers",
                "7-8": "Easy to find, visible in security scans",
                "9-10": "Obvious, visible to any observer"
            }
        }
    
    def assess_threat(self, threat_id: str, threat_description: str, 
                     threat_type: str = "", affected_component: str = "") -> DreadScore:
        damage_score = self._assess_damage(threat_description, threat_type, affected_component)
        reproducibility_score = self._assess_reproducibility(threat_description, threat_type)
        exploitability_score = self._assess_exploitability(threat_description, threat_type)
        affected_users_score = self._assess_affected_users(threat_description, affected_component)
        discoverability_score = self._assess_discoverability(threat_description, threat_type)
        
        dread_score = DreadScore(
            threat_id=threat_id,
            damage=damage_score,
            reproducibility=reproducibility_score,
            exploitability=exploitability_score,
            affected_users=affected_users_score,
            discoverability=discoverability_score
        )
        
        logger.info(f"DREAD assessment completed for threat {threat_id}: {dread_score.average_score}")
        return dread_score
    
    def _assess_damage(self, description: str, threat_type: str, component: str) -> int:
        damage_score = 5 
        
        description_lower = description.lower()
        
        if any(keyword in description_lower for keyword in [
            "complete system", "total control", "grid disruption", "power outage"
        ]):
            damage_score = min(10, damage_score + 4)
        
        elif any(keyword in description_lower for keyword in [
            "unauthorized control", "data manipulation", "service disruption"
        ]):
            damage_score = min(8, damage_score + 2)
        
        if "inverter" in component.lower():
            damage_score = min(10, damage_score + 1)
        elif "api" in component.lower():
            damage_score = min(9, damage_score + 2) 
        
        if threat_type.upper() in ["DENIAL_OF_SERVICE", "TAMPERING"]:
            damage_score = min(10, damage_score + 1)
        
        return max(1, min(10, damage_score))
    
    def _assess_reproducibility(self, description: str, threat_type: str) -> int:
        """Assess reproducibility score based on threat characteristics."""
        reproducibility_score = 5
        
        description_lower = description.lower()
        
        if any(keyword in description_lower for keyword in [
            "default credentials", "plaintext", "unencrypted", "automated"
        ]):
            reproducibility_score = min(10, reproducibility_score + 3)
        
        elif any(keyword in description_lower for keyword in [
            "race condition", "timing", "specific configuration"
        ]):
            reproducibility_score = max(1, reproducibility_score - 2)
        
        if any(protocol in description_lower for protocol in ["modbus", "mqtt", "http"]):
            reproducibility_score = min(10, reproducibility_score + 1)
        
        return max(1, min(10, reproducibility_score))
    
    def _assess_exploitability(self, description: str, threat_type: str) -> int:
        exploitability_score = 5
        
        description_lower = description.lower()
        
        if any(keyword in description_lower for keyword in [
            "no authentication", "default password", "public exploit", "simple attack"
        ]):
            exploitability_score = min(10, exploitability_score + 3)
        
        elif any(keyword in description_lower for keyword in [
            "weak authentication", "known vulnerability", "basic tools"
        ]):
            exploitability_score = min(8, exploitability_score + 1)
        
        elif any(keyword in description_lower for keyword in [
            "complex attack", "requires expertise", "advanced knowledge"
        ]):
            exploitability_score = max(1, exploitability_score - 2)
        
        return max(1, min(10, exploitability_score))
    
    def _assess_affected_users(self, description: str, component: str) -> int:
        """Assess number of affected users/systems."""
        affected_score = 5 
        
        description_lower = description.lower()
        component_lower = component.lower()
        
        if any(keyword in description_lower for keyword in [
            "grid-wide", "multiple systems", "cascading", "network-wide"
        ]):
            affected_score = min(10, affected_score + 4)
        
        if "gateway" in component_lower or "api" in component_lower:
            affected_score = min(10, affected_score + 2) 
        elif "inverter" in component_lower:
            affected_score = min(7, affected_score + 1)
        
        return max(1, min(10, affected_score))
    
    def _assess_discoverability(self, description: str, threat_type: str) -> int:
        discoverability_score = 5  
        
        description_lower = description.lower()
        
        if any(keyword in description_lower for keyword in [
            "public interface", "web interface", "default settings", "obvious"
        ]):
            discoverability_score = min(10, discoverability_score + 3)
        
        elif any(keyword in description_lower for keyword in [
            "internal", "hidden", "undocumented", "requires access"
        ]):
            discoverability_score = max(1, discoverability_score - 2)
        
        return max(1, min(10, discoverability_score))
    
    def assess_multiple_threats(self, threats_data: List[Dict[str, Any]]) -> List[DreadScore]:
        self.dread_scores = []
        
        for threat_data in threats_data:
            try:
                dread_score = self.assess_threat(
                    threat_id=threat_data.get("id", ""),
                    threat_description=threat_data.get("description", ""),
                    threat_type=threat_data.get("stride_category", ""),
                    affected_component=threat_data.get("affected_component", "")
                )
                self.dread_scores.append(dread_score)
            except Exception as e:
                logger.error(f"Error assessing threat {threat_data.get('id', 'unknown')}: {e}")
        
        logger.info(f"Completed DREAD assessment for {len(self.dread_scores)} threats")
        return self.dread_scores
    
    def generate_comprehensive_report(self) -> Dict[str, Any]:
        if not self.dread_scores:
            return {"error": "No DREAD scores available. Run assessment first."}
        
        risk_metrics = self.risk_calculator.calculate_risk_metrics(self.dread_scores)
        
        prioritized_threats = self.threat_prioritizer.prioritize_threats(self.dread_scores)
        
        priority_matrix = self.threat_prioritizer.generate_priority_matrix(self.dread_scores)
        
        recommendations = self._generate_dread_recommendations()
        
        report = {
            "assessment_timestamp": datetime.now().isoformat(),
            "summary": {
                "total_threats_assessed": len(self.dread_scores),
                "average_risk_score": risk_metrics["average_score_stats"]["mean"],
                "highest_risk_threat": prioritized_threats[0][0] if prioritized_threats else None,
                "critical_threats_count": risk_metrics["risk_level_distribution"]["CRITICAL"]
            },
            "risk_metrics": risk_metrics,
            "prioritized_threats": [
                {
                    "threat_id": threat_id,
                    "weighted_score": weighted_score,
                    "risk_level": risk_level
                }
                for threat_id, weighted_score, risk_level in prioritized_threats[:20]
            ],
            "priority_matrix": priority_matrix,
            "component_analysis": self._analyze_threats_by_component(),
            "recommendations": recommendations,
            "detailed_scores": [score.to_dict() for score in self.dread_scores]
        }
        
        return report
    
    def _analyze_threats_by_component(self) -> Dict[str, Any]:
        component_analysis = {}
        
        for dread_score in self.dread_scores:
            component = dread_score.threat_id.split('_')[0] if '_' in dread_score.threat_id else "unknown"
            
            if component not in component_analysis:
                component_analysis[component] = {
                    "threat_count": 0,
                    "total_risk_score": 0,
                    "average_risk_score": 0,
                    "max_risk_score": 0,
                    "risk_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
                }
            
            comp_data = component_analysis[component]
            comp_data["threat_count"] += 1
            comp_data["total_risk_score"] += dread_score.average_score
            comp_data["max_risk_score"] = max(comp_data["max_risk_score"], dread_score.average_score)
            comp_data["risk_distribution"][dread_score.risk_level] += 1
        
        for component, data in component_analysis.items():
            if data["threat_count"] > 0:
                data["average_risk_score"] = round(data["total_risk_score"] / data["threat_count"], 2)
        
        return component_analysis
    
    def _generate_dread_recommendations(self) -> List[Dict[str, Any]]:
        recommendations = []
        
        critical_count = sum(1 for score in self.dread_scores if score.risk_level == "CRITICAL")
        high_count = sum(1 for score in self.dread_scores if score.risk_level == "HIGH")
        
        if critical_count > 0:
            recommendations.append({
                "priority": "IMMEDIATE",
                "category": "Critical Risk Mitigation",
                "recommendation": f"Address {critical_count} critical risk threats immediately",
                "action_items": [
                    "Establish incident response team",
                    "Implement emergency security controls",
                    "Conduct detailed risk assessment for critical threats"
                ]
            })
        
        if high_count > 3:
            recommendations.append({
                "priority": "HIGH",
                "category": "High Risk Management",
                "recommendation": f"Develop mitigation plan for {high_count} high-risk threats",
                "action_items": [
                    "Prioritize high-risk threats by business impact",
                    "Allocate security resources accordingly",
                    "Implement risk monitoring and reporting"
                ]
            })
        
        component_analysis = self._analyze_threats_by_component()
        for component, data in component_analysis.items():
            if data["average_risk_score"] >= 7:
                recommendations.append({
                    "priority": "HIGH",
                    "category": f"Component Security - {component}",
                    "recommendation": f"Enhance security controls for {component} component",
                    "action_items": [
                        f"Review {component} security configuration",
                        f"Implement additional monitoring for {component}",
                        f"Consider security architecture changes for {component}"
                    ]
                })
        
        avg_scores = self.risk_calculator.calculate_risk_metrics(self.dread_scores)
        component_scores = avg_scores.get("component_analysis", {})
        
        for component_name, scores in component_scores.items():
            if scores["mean"] >= 7:
                if component_name == "damage":
                    recommendations.append({
                        "priority": "HIGH",
                        "category": "Impact Reduction",
                        "recommendation": "Implement damage limitation controls",
                        "action_items": [
                            "Deploy backup and recovery systems",
                            "Implement fault tolerance mechanisms",
                            "Establish business continuity procedures"
                        ]
                    })
                elif component_name == "exploitability":
                    recommendations.append({
                        "priority": "HIGH", 
                        "category": "Exploit Prevention",
                        "recommendation": "Reduce attack surface and exploitability",
                        "action_items": [
                            "Implement defense in depth",
                            "Enhance access controls",
                            "Deploy intrusion detection systems"
                        ]
                    })
        
        return recommendations
    
    def export_assessment(self, output_path: str = "outputs/dread_assessment.json") -> None:
        report = self.generate_comprehensive_report()
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"DREAD assessment exported to {output_path}")
    
    def load_threats_from_stride(self, stride_results_path: str) -> None:
        try:
            with open(stride_results_path, 'r') as f:
                stride_data = json.load(f)
            
            threats_data = stride_data.get("all_threats", [])
            self.assess_multiple_threats(threats_data)
            
            logger.info(f"Loaded {len(threats_data)} threats from STRIDE analysis")
        except Exception as e:
            logger.error(f"Error loading STRIDE results: {e}")

def main():
    dread_assessment = DreadAssessment()
    
    sample_threats = [
        {
            "id": "inverter_001_SPOOFING_1",
            "title": "Inverter Identity Spoofing",
            "description": "Attacker impersonates legitimate inverter using default credentials",
            "stride_category": "SPOOFING",
            "affected_component": "inverter_001"
        },
        {
            "id": "api_001_TAMPERING_1", 
            "title": "API Request Manipulation",
            "description": "Modification of API requests over unencrypted HTTP connection",
            "stride_category": "TAMPERING",
            "affected_component": "api_001"
        }
    ]
    
    dread_scores = dread_assessment.assess_multiple_threats(sample_threats)
    
    report = dread_assessment.generate_comprehensive_report()
    dread_assessment.export_assessment()
    
    print(f"DREAD Assessment Results:")
    print(f"Threats assessed: {report['summary']['total_threats_assessed']}")
    print(f"Average risk score: {report['summary']['average_risk_score']}")
    print(f"Critical threats: {report['summary']['critical_threats_count']}")

if __name__ == "__main__":
    main()