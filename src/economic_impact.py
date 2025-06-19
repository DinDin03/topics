import json
import logging
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import statistics

logger = logging.getLogger(__name__)

class AttackScenario(Enum):
    SINGLE_INVERTER_COMPROMISE = "SINGLE_INVERTER_COMPROMISE"
    MULTIPLE_INVERTER_ATTACK = "MULTIPLE_INVERTER_ATTACK"
    GATEWAY_COMPROMISE = "GATEWAY_COMPROMISE"
    API_ENDPOINT_ATTACK = "API_ENDPOINT_ATTACK"
    COORDINATED_GRID_ATTACK = "COORDINATED_GRID_ATTACK"
    FIRMWARE_INJECTION = "FIRMWARE_INJECTION"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"

class EconomicSector(Enum):
    RESIDENTIAL = "RESIDENTIAL"
    COMMERCIAL = "COMMERCIAL"
    INDUSTRIAL = "INDUSTRIAL"
    GRID_OPERATOR = "GRID_OPERATOR"
    ENERGY_RETAILER = "ENERGY_RETAILER"
    GOVERNMENT = "GOVERNMENT"

@dataclass
class EconomicImpact:
    scenario: AttackScenario
    duration_hours: float
    affected_capacity_mw: float
    direct_costs: Dict[str, float]  # Direct financial costs
    indirect_costs: Dict[str, float]  # Indirect economic impacts
    spot_price_impact: Dict[str, float]  # Electricity price effects
    sector_impacts: Dict[EconomicSector, float]  # Impact by sector
    recovery_costs: Dict[str, float]  # Costs to restore systems
    total_economic_impact: float = field(init=False)
    impact_timestamp: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        self.total_economic_impact = (
            sum(self.direct_costs.values()) +
            sum(self.indirect_costs.values()) +
            sum(self.spot_price_impact.values()) +
            sum(self.recovery_costs.values())
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario.value,
            "duration_hours": self.duration_hours,
            "affected_capacity_mw": self.affected_capacity_mw,
            "direct_costs": self.direct_costs,
            "indirect_costs": self.indirect_costs,
            "spot_price_impact": self.spot_price_impact,
            "sector_impacts": {sector.value: impact for sector, impact in self.sector_impacts.items()},
            "recovery_costs": self.recovery_costs,
            "total_economic_impact": self.total_economic_impact,
            "impact_timestamp": self.impact_timestamp.isoformat()
        }

@dataclass
class SpotPriceData:
    timestamp: datetime
    price_aud_per_mwh: float
    demand_mw: float
    renewable_generation_mw: float
    region: str = "SA1"  # South Australia region code
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "price_aud_per_mwh": self.price_aud_per_mwh,
            "demand_mw": self.demand_mw,
            "renewable_generation_mw": self.renewable_generation_mw,
            "region": self.region
        }

class SpotPriceAnalyzer:
    def __init__(self, historical_data_path: Optional[str] = None):
        self.historical_data: List[SpotPriceData] = []
        self.price_volatility_metrics = {}
        
        if historical_data_path:
            self._load_historical_data(historical_data_path)
        else:
            self._generate_synthetic_data()
    
    def _load_historical_data(self, data_path: str) -> None:
        try:
            with open(data_path, 'r') as f:
                data = json.load(f)
            
            for record in data:
                spot_data = SpotPriceData(
                    timestamp=datetime.fromisoformat(record["timestamp"]),
                    price_aud_per_mwh=record["price_aud_per_mwh"],
                    demand_mw=record["demand_mw"],
                    renewable_generation_mw=record["renewable_generation_mw"],
                    region=record.get("region", "SA1")
                )
                self.historical_data.append(spot_data)
            
            logger.info(f"Loaded {len(self.historical_data)} historical price records")
        except Exception as e:
            logger.error(f"Error loading historical data: {e}")
            self._generate_synthetic_data()
    
    def _generate_synthetic_data(self) -> None:
        logger.info("Generating synthetic spot price data for SA market")
        
        start_date = datetime.now() - timedelta(days=365)
        
        for i in range(365 * 24):
            timestamp = start_date + timedelta(hours=i)
            
            base_price = self._calculate_base_price(timestamp)
            volatility_factor = self._calculate_volatility_factor(timestamp)
            renewable_factor = self._calculate_renewable_factor(timestamp)
            
            price = base_price * volatility_factor * renewable_factor
            demand = self._calculate_demand(timestamp)
            renewable_gen = self._calculate_renewable_generation(timestamp, demand)
            
            spot_data = SpotPriceData(
                timestamp=timestamp,
                price_aud_per_mwh=max(0, price), 
                demand_mw=demand,
                renewable_generation_mw=renewable_gen
            )
            
            self.historical_data.append(spot_data)
        
        logger.info(f"Generated {len(self.historical_data)} synthetic price records")
    
    def _calculate_base_price(self, timestamp: datetime) -> float:
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        month = timestamp.month
        
        if 6 <= hour <= 9 or 17 <= hour <= 21:  
            base_price = 150
        elif 10 <= hour <= 16:  
            base_price = 80
        else:
            base_price = 45
        
        if day_of_week >= 5:
            base_price *= 0.8
        
    
        if month in [12, 1, 2]:  
            base_price *= 1.3
        elif month in [6, 7, 8]: 
            base_price *= 1.1
        
        return base_price
    
    def _calculate_volatility_factor(self, timestamp: datetime) -> float:
        import random
        
        hour = timestamp.hour
        if 6 <= hour <= 9 or 17 <= hour <= 21:
            # Peak hours have higher volatility
            return random.uniform(0.7, 2.5)
        else:
            return random.uniform(0.8, 1.3)
    
    def _calculate_renewable_factor(self, timestamp: datetime) -> float:
        """Calculate renewable generation impact on prices."""
        hour = timestamp.hour
        month = timestamp.month
        
        # High solar generation during day reduces prices
        if 10 <= hour <= 15:  # High solar hours
            if month in [10, 11, 12, 1, 2, 3]:  # High solar months
                return 0.4  # Significant price reduction
            else:
                return 0.7
        elif 7 <= hour <= 9 or 16 <= hour <= 18:  # Moderate solar
            return 0.8
        else:  # No solar generation
            return 1.2  # Higher prices due to conventional generation
    
    def _calculate_demand(self, timestamp: datetime) -> float:
        """Calculate electricity demand based on time patterns."""
        hour = timestamp.hour
        day_of_week = timestamp.weekday()
        month = timestamp.month
        
        # Base demand patterns (MW)
        if 6 <= hour <= 9 or 17 <= hour <= 21:  # Peak hours
            base_demand = 2800
        elif 10 <= hour <= 16:  # Day hours
            base_demand = 2200
        else:  # Off-peak hours
            base_demand = 1600
        
        # Weekend adjustments
        if day_of_week >= 5:
            base_demand *= 0.85
        
        # Seasonal adjustments
        if month in [12, 1, 2]:  # Summer
            base_demand *= 1.25
        elif month in [6, 7, 8]:  # Winter
            base_demand *= 1.15
        
        # Add some randomness
        import random
        return base_demand * random.uniform(0.9, 1.1)
    
    def _calculate_renewable_generation(self, timestamp: datetime, demand: float) -> float:
        """Calculate renewable generation based on time and demand."""
        hour = timestamp.hour
        month = timestamp.month
        
        # Solar generation pattern
        if 6 <= hour <= 18:  # Daylight hours
            peak_factor = np.sin(np.pi * (hour - 6) / 12)  # Sine curve for solar
            if month in [10, 11, 12, 1, 2, 3]:  # High solar months
                max_solar = demand * 0.6  # High renewable penetration
            else:
                max_solar = demand * 0.4
            solar_gen = max_solar * peak_factor
        else:
            solar_gen = 0
        
        # Wind generation (more consistent)
        import random
        wind_gen = demand * 0.3 * random.uniform(0.1, 0.8)
        
        return solar_gen + wind_gen
    
    def analyze_price_volatility(self) -> Dict[str, float]:
        """Analyze price volatility metrics from historical data."""
        prices = [data.price_aud_per_mwh for data in self.historical_data]
        
        self.price_volatility_metrics = {
            "mean_price": statistics.mean(prices),
            "median_price": statistics.median(prices),
            "std_deviation": statistics.stdev(prices),
            "min_price": min(prices),
            "max_price": max(prices),
            "volatility_coefficient": statistics.stdev(prices) / statistics.mean(prices),
            "percentile_95": np.percentile(prices, 95),
            "percentile_99": np.percentile(prices, 99)
        }
        
        logger.info(f"Price volatility analysis completed. CV: {self.price_volatility_metrics['volatility_coefficient']:.2f}")
        return self.price_volatility_metrics
    
    def model_supply_disruption_impact(self, disrupted_capacity_mw: float, 
                                     duration_hours: float) -> Dict[str, float]:
        """
        Model the impact of solar generation disruption on spot prices.
        
        Args:
            disrupted_capacity_mw: Amount of solar capacity disrupted
            duration_hours: Duration of the disruption
            
        Returns:
            Dictionary with price impact analysis
        """
        if not self.price_volatility_metrics:
            self.analyze_price_volatility()
        
        # Calculate supply elasticity effects
        baseline_price = self.price_volatility_metrics["mean_price"]
        total_renewable_capacity = 2000  # Approximate SA solar capacity (MW)
        
        # Percentage of renewable capacity disrupted
        capacity_percentage = disrupted_capacity_mw / total_renewable_capacity
        
        # Price elasticity modeling (SA has inelastic supply)
        # Price increases exponentially with supply reduction
        price_multiplier = 1 + (capacity_percentage * 3.5)  # High elasticity due to market concentration
        
        # Time-of-day impact factors
        current_time = datetime.now()
        hour = current_time.hour
        
        if 10 <= hour <= 15:  # High solar generation hours
            impact_factor = 2.0  # Maximum impact during solar peak
        elif 7 <= hour <= 9 or 16 <= hour <= 18:
            impact_factor = 1.5  # Moderate impact during ramp periods
        else:
            impact_factor = 0.3  # Minimal impact during non-solar hours
        
        # Calculate economic impacts
        increased_price = baseline_price * (price_multiplier - 1) * impact_factor
        total_additional_cost = increased_price * disrupted_capacity_mw * duration_hours
        
        # Cascading effects
        market_volatility_increase = capacity_percentage * 0.2  # 20% volatility increase per 1% capacity
        ancillary_services_cost = disrupted_capacity_mw * 15 * duration_hours  # Additional reserves
        
        return {
            "baseline_price_aud_mwh": baseline_price,
            "disrupted_capacity_mw": disrupted_capacity_mw,
            "duration_hours": duration_hours,
            "capacity_percentage_disrupted": capacity_percentage * 100,
            "price_increase_aud_mwh": increased_price,
            "price_multiplier": price_multiplier,
            "impact_factor": impact_factor,
            "total_additional_generation_cost": total_additional_cost,
            "ancillary_services_cost": ancillary_services_cost,
            "market_volatility_increase_percent": market_volatility_increase * 100,
            "total_market_impact": total_additional_cost + ancillary_services_cost
        }

class OutageImpactAnalyzer:
    """
    Analyzes the economic impact of solar inverter outages
    on different economic sectors and stakeholders.
    """
    
    def __init__(self):
        self.sector_impact_factors = self._define_sector_impact_factors()
    
    def _define_sector_impact_factors(self) -> Dict[EconomicSector, Dict[str, float]]:
        """Define impact factors for different economic sectors."""
        return {
            EconomicSector.RESIDENTIAL: {
                "energy_cost_increase_factor": 1.2,  # 20% increase in energy costs
                "lost_revenue_per_mw_hour": 0,  # No direct revenue loss
                "backup_generation_cost_per_mw": 200,  # Cost of backup power
                "inconvenience_cost_per_hour": 50  # Economic value of convenience loss
            },
            EconomicSector.COMMERCIAL: {
                "energy_cost_increase_factor": 1.3,
                "lost_revenue_per_mw_hour": 1500,  # Lost business revenue
                "backup_generation_cost_per_mw": 300,
                "inconvenience_cost_per_hour": 200
            },
            EconomicSector.INDUSTRIAL: {
                "energy_cost_increase_factor": 1.4,
                "lost_revenue_per_mw_hour": 5000,  # High industrial revenue loss
                "backup_generation_cost_per_mw": 500,
                "inconvenience_cost_per_hour": 1000
            },
            EconomicSector.GRID_OPERATOR: {
                "energy_cost_increase_factor": 1.5,
                "lost_revenue_per_mw_hour": 100,  # Grid services revenue
                "backup_generation_cost_per_mw": 400,  # Emergency generation
                "inconvenience_cost_per_hour": 500  # Operational complexity
            },
            EconomicSector.ENERGY_RETAILER: {
                "energy_cost_increase_factor": 1.6,
                "lost_revenue_per_mw_hour": 80,  # Retail margin loss
                "backup_generation_cost_per_mw": 350,
                "inconvenience_cost_per_hour": 300
            }
        }
    
    def calculate_sector_impact(self, sector: EconomicSector, 
                              disrupted_capacity_mw: float,
                              duration_hours: float,
                              baseline_price_aud_mwh: float) -> Dict[str, float]:
        """Calculate economic impact for a specific sector."""
        
        if sector not in self.sector_impact_factors:
            logger.warning(f"Unknown sector: {sector}")
            return {}
        
        factors = self.sector_impact_factors[sector]
        
        # Calculate different cost components
        energy_cost_increase = (
            disrupted_capacity_mw * duration_hours * baseline_price_aud_mwh * 
            (factors["energy_cost_increase_factor"] - 1)
        )
        
        lost_revenue = (
            factors["lost_revenue_per_mw_hour"] * disrupted_capacity_mw * duration_hours
        )
        
        backup_generation_cost = (
            factors["backup_generation_cost_per_mw"] * disrupted_capacity_mw * duration_hours
        )
        
        inconvenience_cost = (
            factors["inconvenience_cost_per_hour"] * duration_hours
        )
        
        total_impact = (
            energy_cost_increase + lost_revenue + 
            backup_generation_cost + inconvenience_cost
        )
        
        return {
            "sector": sector.value,
            "energy_cost_increase": energy_cost_increase,
            "lost_revenue": lost_revenue,
            "backup_generation_cost": backup_generation_cost,
            "inconvenience_cost": inconvenience_cost,
            "total_sector_impact": total_impact,
            "impact_per_mw": total_impact / disrupted_capacity_mw if disrupted_capacity_mw > 0 else 0
        }

class EconomicImpactCalculator:
    """
    Main economic impact calculator for solar inverter cybersecurity incidents.
    
    This class orchestrates the comprehensive economic analysis of
    cybersecurity threats to solar inverter systems.
    """
    
    def __init__(self, config_path: str = "config/system_components.json"):
        self.config_path = Path(config_path)
        self.spot_price_analyzer = SpotPriceAnalyzer()
        self.outage_analyzer = OutageImpactAnalyzer()
        self.system_config = self._load_system_config()
        self.economic_scenarios = self._define_economic_scenarios()
    
    def _load_system_config(self) -> Dict[str, Any]:
        """Load system configuration for economic analysis."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            else:
                logger.warning(f"Configuration file not found: {self.config_path}")
                return self._get_default_config()
        except Exception as e:
            logger.error(f"Error loading system configuration: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default system configuration for economic analysis."""
        return {
            "system_name": "Adelaide Solar Network",
            "total_capacity_kw": 8.0,  # 8kW total capacity
            "components": [
                {"id": "inverter_001", "capacity_kw": 5.0},
                {"id": "inverter_002", "capacity_kw": 3.0}
            ]
        }
    
    def _define_economic_scenarios(self) -> Dict[AttackScenario, Dict[str, Any]]:
        """Define economic impact scenarios for different attack types."""
        return {
            AttackScenario.SINGLE_INVERTER_COMPROMISE: {
                "description": "Single inverter compromised, capacity reduced",
                "capacity_impact_percentage": 0.6,  # 60% of single inverter capacity affected
                "duration_range_hours": (2, 24),
                "detection_time_hours": 4,
                "recovery_complexity": "low"
            },
            AttackScenario.MULTIPLE_INVERTER_ATTACK: {
                "description": "Multiple inverters attacked simultaneously",
                "capacity_impact_percentage": 0.8,  # 80% of total capacity affected
                "duration_range_hours": (6, 72),
                "detection_time_hours": 8,
                "recovery_complexity": "high"
            },
            AttackScenario.GATEWAY_COMPROMISE: {
                "description": "Communication gateway compromised",
                "capacity_impact_percentage": 1.0,  # All connected inverters affected
                "duration_range_hours": (4, 48),
                "detection_time_hours": 6,
                "recovery_complexity": "medium"
            },
            AttackScenario.API_ENDPOINT_ATTACK: {
                "description": "AEMO API endpoint attack disrupts remote control",
                "capacity_impact_percentage": 0.3,  # Limited operational impact
                "duration_range_hours": (1, 12),
                "detection_time_hours": 2,
                "recovery_complexity": "low"
            },
            AttackScenario.COORDINATED_GRID_ATTACK: {
                "description": "Large-scale coordinated attack on multiple sites",
                "capacity_impact_percentage": 1.0,  # Complete system compromise
                "duration_range_hours": (12, 168),  # Up to 1 week
                "detection_time_hours": 12,
                "recovery_complexity": "very_high"
            },
            AttackScenario.FIRMWARE_INJECTION: {
                "description": "Malicious firmware injection attack",
                "capacity_impact_percentage": 0.9,  # Near-complete compromise
                "duration_range_hours": (24, 240),  # Up to 10 days for full recovery
                "detection_time_hours": 48,  # Hard to detect
                "recovery_complexity": "very_high"
            },
            AttackScenario.DENIAL_OF_SERVICE: {
                "description": "DDoS attack on communication infrastructure",
                "capacity_impact_percentage": 0.4,  # Monitoring/control affected
                "duration_range_hours": (1, 8),
                "detection_time_hours": 1,
                "recovery_complexity": "low"
            }
        }
    
    def calculate_attack_scenario_impact(self, scenario: AttackScenario,
                                       duration_hours: Optional[float] = None) -> EconomicImpact:
        """
        Calculate comprehensive economic impact for a specific attack scenario.
        
        Args:
            scenario: Type of cyberattack scenario
            duration_hours: Duration of attack (if None, uses scenario default)
            
        Returns:
            EconomicImpact object with comprehensive analysis
        """
        scenario_config = self.economic_scenarios[scenario]
        
        # Determine attack duration
        if duration_hours is None:
            duration_range = scenario_config["duration_range_hours"]
            duration_hours = (duration_range[0] + duration_range[1]) / 2  # Use average
        
        # Calculate affected capacity
        total_capacity_kw = sum(comp["capacity_kw"] for comp in self.system_config["components"])
        capacity_impact_pct = scenario_config["capacity_impact_percentage"]
        affected_capacity_kw = total_capacity_kw * capacity_impact_pct
        affected_capacity_mw = affected_capacity_kw / 1000  # Convert to MW
        
        # Analyze spot price impacts
        spot_impact = self.spot_price_analyzer.model_supply_disruption_impact(
            affected_capacity_mw, duration_hours
        )
        
        # Calculate direct costs
        direct_costs = self._calculate_direct_costs(scenario, duration_hours, affected_capacity_mw)
        
        # Calculate indirect costs
        indirect_costs = self._calculate_indirect_costs(scenario, duration_hours, affected_capacity_mw)
        
        # Calculate sector impacts
        sector_impacts = {}
        baseline_price = spot_impact["baseline_price_aud_mwh"]
        
        for sector in EconomicSector:
            sector_impact = self.outage_analyzer.calculate_sector_impact(
                sector, affected_capacity_mw, duration_hours, baseline_price
            )
            if sector_impact:
                sector_impacts[sector] = sector_impact["total_sector_impact"]
        
        # Calculate recovery costs
        recovery_costs = self._calculate_recovery_costs(scenario, affected_capacity_mw)
        
        return EconomicImpact(
            scenario=scenario,
            duration_hours=duration_hours,
            affected_capacity_mw=affected_capacity_mw,
            direct_costs=direct_costs,
            indirect_costs=indirect_costs,
            spot_price_impact={
                "total_market_impact": spot_impact["total_market_impact"],
                "price_increase": spot_impact["price_increase_aud_mwh"],
                "additional_generation_cost": spot_impact["total_additional_generation_cost"]
            },
            sector_impacts=sector_impacts,
            recovery_costs=recovery_costs
        )
    
    def _calculate_direct_costs(self, scenario: AttackScenario, 
                              duration_hours: float, affected_capacity_mw: float) -> Dict[str, float]:
        """Calculate direct costs of the cybersecurity incident."""
        scenario_config = self.economic_scenarios[scenario]
        
        # Lost generation revenue
        average_generation_revenue_per_mwh = 80  # AUD/MWh average
        lost_generation_revenue = (
            affected_capacity_mw * duration_hours * average_generation_revenue_per_mwh * 0.3
        )  # Assume 30% capacity factor
        
        # Emergency response costs
        detection_time = scenario_config["detection_time_hours"]
        emergency_response_cost = detection_time * 500  # $500/hour for emergency response
        
        # System replacement costs (for severe attacks)
        if scenario in [AttackScenario.FIRMWARE_INJECTION, AttackScenario.COORDINATED_GRID_ATTACK]:
            equipment_replacement_cost = affected_capacity_mw * 1000 * 1500  # $1500/kW
        else:
            equipment_replacement_cost = 0
        
        return {
            "lost_generation_revenue": lost_generation_revenue,
            "emergency_response_cost": emergency_response_cost,
            "equipment_replacement_cost": equipment_replacement_cost,
            "forensic_investigation_cost": 15000,  # Fixed cost for investigation
            "legal_consultation_cost": 8000  # Legal costs
        }
    
    def _calculate_indirect_costs(self, scenario: AttackScenario,
                                duration_hours: float, affected_capacity_mw: float) -> Dict[str, float]:
        """Calculate indirect costs of the cybersecurity incident."""
        
        # Reputation damage (estimated)
        reputation_damage = affected_capacity_mw * 10000  # $10k per MW affected
        
        # Regulatory penalties
        if scenario in [AttackScenario.COORDINATED_GRID_ATTACK, AttackScenario.FIRMWARE_INJECTION]:
            regulatory_penalties = 50000  # Severe penalties for major incidents
        else:
            regulatory_penalties = 5000   # Minor penalties
        
        # Insurance premium increases
        insurance_increase = affected_capacity_mw * 2000  # $2k per MW annual increase
        
        # Productivity losses
        productivity_loss = duration_hours * 200  # $200/hour productivity impact
        
        # Customer confidence impact
        customer_impact = affected_capacity_mw * 5000  # $5k per MW customer impact
        
        return {
            "reputation_damage": reputation_damage,
            "regulatory_penalties": regulatory_penalties,
            "insurance_premium_increase": insurance_increase,
            "productivity_losses": productivity_loss,
            "customer_confidence_impact": customer_impact
        }
    
    def _calculate_recovery_costs(self, scenario: AttackScenario, 
                                affected_capacity_mw: float) -> Dict[str, float]:
        """Calculate costs associated with system recovery."""
        scenario_config = self.economic_scenarios[scenario]
        complexity = scenario_config["recovery_complexity"]
        
        # Base recovery costs by complexity
        complexity_multipliers = {
            "low": 1.0,
            "medium": 2.0,
            "high": 4.0,
            "very_high": 8.0
        }
        
        base_recovery_cost = 5000  # Base cost for recovery
        multiplier = complexity_multipliers.get(complexity, 1.0)
        
        # Technical recovery costs
        technical_recovery = base_recovery_cost * multiplier
        
        # Security improvements (mandatory after incident)
        security_improvements = affected_capacity_mw * 1000 * 200  # $200/kW security upgrade
        
        # Staff training and awareness
        training_costs = 10000  # Fixed training cost
        
        # Monitoring and detection system upgrades
        monitoring_upgrades = 25000  # Fixed monitoring upgrade cost
        
        return {
            "technical_recovery": technical_recovery,
            "security_improvements": security_improvements,
            "staff_training": training_costs,
            "monitoring_upgrades": monitoring_upgrades,
            "consultant_fees": 20000  # Security consultant fees
        }
    
    def run_comprehensive_economic_analysis(self) -> Dict[str, Any]:
        """
        Run comprehensive economic analysis across all attack scenarios.
        
        Returns:
            Comprehensive economic impact analysis results
        """
        logger.info("Starting comprehensive economic impact analysis")
        
        # Analyze each attack scenario
        scenario_results = {}
        total_potential_impact = 0
        
        for scenario in AttackScenario:
            logger.info(f"Analyzing economic impact for scenario: {scenario.value}")
            
            # Calculate impact for average duration
            impact = self.calculate_attack_scenario_impact(scenario)
            scenario_results[scenario.value] = impact.to_dict()
            total_potential_impact += impact.total_economic_impact
        
        # Analyze spot price volatility
        price_volatility = self.spot_price_analyzer.analyze_price_volatility()
        
        # Generate risk-weighted analysis
        risk_weighted_analysis = self._calculate_risk_weighted_impacts(scenario_results)
        
        # Generate mitigation cost-benefit analysis
        mitigation_analysis = self._analyze_mitigation_economics()
        
        # Compile comprehensive results
        results = {
            "analysis_timestamp": datetime.now().isoformat(),
            "system_summary": {
                "total_capacity_kw": sum(comp["capacity_kw"] for comp in self.system_config["components"]),
                "location": self.system_config.get("location", "Adelaide, SA"),
                "analysis_scope": "Cybersecurity economic impact assessment"
            },
            "scenario_analysis": scenario_results,
            "aggregated_metrics": {
                "total_potential_impact_aud": total_potential_impact,
                "average_impact_per_scenario": total_potential_impact / len(AttackScenario),
                "highest_impact_scenario": max(scenario_results.items(), 
                                             key=lambda x: x[1]["total_economic_impact"]),
                "lowest_impact_scenario": min(scenario_results.items(),
                                            key=lambda x: x[1]["total_economic_impact"])
            },
            "market_analysis": {
                "spot_price_volatility": price_volatility,
                "market_characteristics": {
                    "high_renewable_penetration": True,
                    "price_volatility_high": price_volatility.get("volatility_coefficient", 0) > 0.5,
                    "supply_elasticity": "low",
                    "demand_elasticity": "low"
                }
            },
            "risk_weighted_analysis": risk_weighted_analysis,
            "mitigation_economics": mitigation_analysis,
            "regulatory_context": self._analyze_regulatory_economics(),
            "recommendations": self._generate_economic_recommendations(scenario_results)
        }
        
        logger.info("Economic impact analysis completed")
        return results
    
    def _calculate_risk_weighted_impacts(self, scenario_results: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate risk-weighted economic impacts based on likelihood."""
        
        # Define likelihood estimates for each scenario (0-1 probability)
        scenario_likelihoods = {
            AttackScenario.SINGLE_INVERTER_COMPROMISE.value: 0.15,  # 15% annual probability
            AttackScenario.MULTIPLE_INVERTER_ATTACK.value: 0.05,   # 5% annual probability
            AttackScenario.GATEWAY_COMPROMISE.value: 0.08,         # 8% annual probability
            AttackScenario.API_ENDPOINT_ATTACK.value: 0.12,        # 12% annual probability
            AttackScenario.COORDINATED_GRID_ATTACK.value: 0.01,    # 1% annual probability
            AttackScenario.FIRMWARE_INJECTION.value: 0.03,         # 3% annual probability
            AttackScenario.DENIAL_OF_SERVICE.value: 0.20          # 20% annual probability
        }
        
        risk_weighted_impacts = {}
        total_expected_annual_loss = 0
        
        for scenario_name, scenario_data in scenario_results.items():
            likelihood = scenario_likelihoods.get(scenario_name, 0.05)
            impact = scenario_data["total_economic_impact"]
            expected_annual_loss = likelihood * impact
            
            risk_weighted_impacts[scenario_name] = {
                "annual_likelihood": likelihood,
                "potential_impact": impact,
                "expected_annual_loss": expected_annual_loss,
                "risk_priority": self._calculate_risk_priority(likelihood, impact)
            }
            
            total_expected_annual_loss += expected_annual_loss
        
        # Sort by expected annual loss
        sorted_risks = sorted(risk_weighted_impacts.items(), 
                            key=lambda x: x[1]["expected_annual_loss"], reverse=True)
        
        return {
            "total_expected_annual_loss": total_expected_annual_loss,
            "risk_scenarios": risk_weighted_impacts,
            "top_risk_scenarios": dict(sorted_risks[:3]),
            "risk_concentration": {
                "top_3_scenarios_percentage": sum(item[1]["expected_annual_loss"] 
                                                for item in sorted_risks[:3]) / total_expected_annual_loss * 100
            }
        }
    
    def _calculate_risk_priority(self, likelihood: float, impact: float) -> str:
        """Calculate risk priority based on likelihood and impact."""
        risk_score = likelihood * impact / 100000  # Normalize impact
        
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.4:
            return "HIGH"
        elif risk_score >= 0.1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _analyze_mitigation_economics(self) -> Dict[str, Any]:
        """Analyze cost-benefit economics of cybersecurity mitigation measures."""
        
        # Define cybersecurity mitigation measures and their costs
        mitigation_measures = {
            "basic_security_package": {
                "description": "Basic cybersecurity controls (encryption, authentication)",
                "implementation_cost": 15000,
                "annual_maintenance_cost": 3000,
                "risk_reduction_factor": 0.4,  # 40% risk reduction
                "affected_scenarios": [
                    AttackScenario.SINGLE_INVERTER_COMPROMISE.value,
                    AttackScenario.API_ENDPOINT_ATTACK.value,
                    AttackScenario.DENIAL_OF_SERVICE.value
                ]
            },
            "advanced_security_package": {
                "description": "Advanced security (IDS, SIEM, advanced monitoring)",
                "implementation_cost": 45000,
                "annual_maintenance_cost": 8000,
                "risk_reduction_factor": 0.7,  # 70% risk reduction
                "affected_scenarios": [
                    AttackScenario.MULTIPLE_INVERTER_ATTACK.value,
                    AttackScenario.GATEWAY_COMPROMISE.value,
                    AttackScenario.FIRMWARE_INJECTION.value
                ]
            },
            "comprehensive_security_program": {
                "description": "Full cybersecurity program with 24/7 monitoring",
                "implementation_cost": 85000,
                "annual_maintenance_cost": 15000,
                "risk_reduction_factor": 0.85,  # 85% risk reduction
                "affected_scenarios": list(scenario.value for scenario in AttackScenario)
            },
            "network_segmentation": {
                "description": "Network segmentation and microsegmentation",
                "implementation_cost": 25000,
                "annual_maintenance_cost": 4000,
                "risk_reduction_factor": 0.6,  # 60% risk reduction
                "affected_scenarios": [
                    AttackScenario.COORDINATED_GRID_ATTACK.value,
                    AttackScenario.GATEWAY_COMPROMISE.value
                ]
            }
        }
        
        # Calculate ROI for each mitigation measure
        mitigation_analysis = {}
        
        for measure_name, measure_config in mitigation_measures.items():
            # Calculate total cost over 5 years
            total_cost_5_years = (
                measure_config["implementation_cost"] + 
                measure_config["annual_maintenance_cost"] * 5
            )
            
            # Calculate risk reduction benefit
            annual_risk_reduction = 0
            affected_scenarios = measure_config["affected_scenarios"]
            risk_reduction_factor = measure_config["risk_reduction_factor"]
            
            # This would use the risk-weighted analysis results
            # For now, estimate based on typical values
            if measure_name == "comprehensive_security_program":
                annual_risk_reduction = 85000  # High reduction for comprehensive program
            elif measure_name == "advanced_security_package":
                annual_risk_reduction = 45000  # Moderate reduction
            elif measure_name == "basic_security_package":
                annual_risk_reduction = 25000  # Basic reduction
            elif measure_name == "network_segmentation":
                annual_risk_reduction = 35000  # Good reduction for specific threats
            
            risk_reduction_5_years = annual_risk_reduction * 5
            
            # Calculate ROI
            net_benefit = risk_reduction_5_years - total_cost_5_years
            roi_percentage = (net_benefit / total_cost_5_years) * 100 if total_cost_5_years > 0 else 0
            
            mitigation_analysis[measure_name] = {
                "description": measure_config["description"],
                "implementation_cost": measure_config["implementation_cost"],
                "annual_maintenance_cost": measure_config["annual_maintenance_cost"],
                "total_cost_5_years": total_cost_5_years,
                "annual_risk_reduction": annual_risk_reduction,
                "risk_reduction_5_years": risk_reduction_5_years,
                "net_benefit_5_years": net_benefit,
                "roi_percentage": round(roi_percentage, 2),
                "payback_period_years": round(total_cost_5_years / annual_risk_reduction, 2) if annual_risk_reduction > 0 else float('inf'),
                "cost_effectiveness": round(annual_risk_reduction / measure_config["implementation_cost"], 2)
            }
        
        # Rank mitigation measures by ROI
        sorted_measures = sorted(mitigation_analysis.items(), 
                               key=lambda x: x[1]["roi_percentage"], reverse=True)
        
        return {
            "mitigation_measures": mitigation_analysis,
            "recommended_priority": [measure[0] for measure in sorted_measures],
            "summary": {
                "best_roi_measure": sorted_measures[0][0] if sorted_measures else None,
                "total_mitigation_cost_range": {
                    "minimum": min(m["implementation_cost"] for m in mitigation_measures.values()),
                    "maximum": sum(m["implementation_cost"] for m in mitigation_measures.values())
                }
            }
        }
    
    def _analyze_regulatory_economics(self) -> Dict[str, Any]:
        """Analyze economic implications of regulatory compliance requirements."""
        
        return {
            "compliance_costs": {
                "aemo_vpp_compliance": {
                    "implementation_cost": 20000,
                    "annual_cost": 5000,
                    "description": "AEMO VPP API and monitoring compliance"
                },
                "cybersecurity_standards": {
                    "implementation_cost": 35000,
                    "annual_cost": 8000,
                    "description": "Cybersecurity standards implementation"
                },
                "grid_connection_standards": {
                    "implementation_cost": 15000,
                    "annual_cost": 2000,
                    "description": "AS4777 and grid connection compliance"
                }
            },
            "non_compliance_penalties": {
                "grid_disconnection_cost": {
                    "immediate_cost": 50000,
                    "ongoing_daily_cost": 2000,
                    "description": "Cost of grid disconnection and reconnection"
                },
                "regulatory_fines": {
                    "minor_violations": 5000,
                    "major_violations": 25000,
                    "severe_violations": 100000
                },
                "lost_revenue": {
                    "daily_generation_loss": 1200,
                    "description": "Lost revenue during non-compliance period"
                }
            },
            "economic_benefits": {
                "vpp_participation_revenue": {
                    "annual_revenue": 8000,
                    "description": "Revenue from VPP participation and grid services"
                },
                "avoided_penalties": {
                    "annual_value": 15000,
                    "description": "Value of avoiding regulatory penalties"
                },
                "insurance_benefits": {
                    "annual_savings": 3000,
                    "description": "Insurance premium reductions for compliance"
                }
            }
        }
    
    def _generate_economic_recommendations(self, scenario_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate economic recommendations based on analysis results."""
        
        recommendations = []
        
        # Calculate total potential impact
        total_impact = sum(scenario["total_economic_impact"] for scenario in scenario_results.values())
        
        # High-level strategic recommendations
        if total_impact > 200000:  # High economic risk
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Risk Management",
                "recommendation": "Implement comprehensive cybersecurity program immediately",
                "economic_justification": f"Total potential economic impact of ${total_impact:,.0f} justifies significant security investment",
                "estimated_cost": 85000,
                "estimated_benefit": total_impact * 0.85,
                "roi_estimate": "900%+ over 5 years"
            })
        
        # Scenario-specific recommendations
        highest_impact_scenario = max(scenario_results.items(), key=lambda x: x[1]["total_economic_impact"])
        scenario_name, scenario_data = highest_impact_scenario
        
        recommendations.append({
            "priority": "HIGH",
            "category": "Threat-Specific Mitigation",
            "recommendation": f"Prioritize protection against {scenario_name.replace('_', ' ').title()}",
            "economic_justification": f"Highest potential impact scenario: ${scenario_data['total_economic_impact']:,.0f}",
            "estimated_cost": 25000,
            "estimated_benefit": scenario_data["total_economic_impact"] * 0.7
        })
        
        # Regulatory compliance recommendations
        recommendations.append({
            "priority": "HIGH",
            "category": "Regulatory Compliance",
            "recommendation": "Ensure full AEMO VPP compliance to avoid penalties",
            "economic_justification": "Non-compliance penalties can exceed $100,000 plus lost revenue",
            "estimated_cost": 20000,
            "estimated_benefit": 100000
        })
        
        # Insurance and risk transfer recommendations
        recommendations.append({
            "priority": "MEDIUM",
            "category": "Risk Transfer",
            "recommendation": "Evaluate cybersecurity insurance options",
            "economic_justification": "Insurance can transfer significant portions of economic risk",
            "estimated_cost": 15000,  # Annual premium
            "estimated_benefit": total_impact * 0.6  # Coverage amount
        })
        
        # Monitoring and detection recommendations
        recommendations.append({
            "priority": "MEDIUM",
            "category": "Early Detection",
            "recommendation": "Implement continuous monitoring and threat detection",
            "economic_justification": "Early detection can reduce incident duration and costs by 60%",
            "estimated_cost": 30000,
            "estimated_benefit": total_impact * 0.4  # Reduction in average impact
        })
        
        return recommendations
    
    def export_economic_analysis(self, output_path: str = "outputs/economic_impact_analysis.json") -> None:
        """Export economic analysis results to JSON file."""
        results = self.run_comprehensive_economic_analysis()
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Economic analysis exported to {output_path}")
    
    def generate_economic_summary_csv(self, output_path: str = "outputs/economic_impact_summary.csv") -> None:
        """Generate CSV summary of economic impacts for easy analysis."""
        results = self.run_comprehensive_economic_analysis()
        
        # Prepare data for CSV
        csv_data = []
        for scenario_name, scenario_data in results["scenario_analysis"].items():
            csv_data.append({
                "Scenario": scenario_name.replace('_', ' ').title(),
                "Duration_Hours": scenario_data["duration_hours"],
                "Affected_Capacity_MW": scenario_data["affected_capacity_mw"],
                "Total_Economic_Impact_AUD": scenario_data["total_economic_impact"],
                "Direct_Costs_AUD": sum(scenario_data["direct_costs"].values()),
                "Indirect_Costs_AUD": sum(scenario_data["indirect_costs"].values()),
                "Recovery_Costs_AUD": sum(scenario_data["recovery_costs"].values()),
                "Spot_Price_Impact_AUD": scenario_data["spot_price_impact"]["total_market_impact"]
            })
        
        # Create DataFrame and export
        df = pd.DataFrame(csv_data)
        df.to_csv(output_path, index=False)
        
        logger.info(f"Economic summary CSV exported to {output_path}")

# Example usage and testing functions
def main():
    """Main function for testing the economic impact analysis module."""
    # Initialize economic impact calculator
    economic_calculator = EconomicImpactCalculator()
    
    # Run comprehensive analysis
    results = economic_calculator.run_comprehensive_economic_analysis()
    
    # Export results
    economic_calculator.export_economic_analysis()
    economic_calculator.generate_economic_summary_csv()
    
    # Print summary
    print("Economic Impact Analysis Results:")
    print(f"Total Potential Impact: ${results['aggregated_metrics']['total_potential_impact_aud']:,.0f}")
    
    highest_impact = results['aggregated_metrics']['highest_impact_scenario']
    print(f"Highest Impact Scenario: {highest_impact[0]} (${highest_impact[1]['total_economic_impact']:,.0f})")
    
    # Print top recommendations
    print("\nTop Economic Recommendations:")
    for i, rec in enumerate(results['recommendations'][:3], 1):
        print(f"{i}. {rec['recommendation']} (Priority: {rec['priority']})")

if __name__ == "__main__":
    main()