"""
Report Generator Module

This module generates comprehensive cybersecurity analysis reports
combining vulnerability assessment, threat modeling, risk analysis,
regulatory compliance, and economic impact data.

Key Components:
- ReportGenerator: Main report generation engine
- HTMLReportBuilder: HTML report generation with visualization
- ExecutiveSummaryGenerator: Executive-level summary reports
- TechnicalReportGenerator: Detailed technical reports

This module demonstrates how to create professional security reports
suitable for different stakeholder audiences.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import base64
from dataclasses import dataclass
from jinja2 import Template, Environment, FileSystemLoader
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from io import BytesIO

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class ReportConfiguration:
    """Configuration for report generation."""
    report_title: str
    organization: str
    author: str
    classification: str = "CONFIDENTIAL"
    include_executive_summary: bool = True
    include_technical_details: bool = True
    include_visualizations: bool = True
    include_recommendations: bool = True
    output_format: str = "html"  # html, pdf, markdown
    
class VisualizationGenerator:
    """
    Generates visualizations for cybersecurity analysis reports.
    
    This class creates charts and graphs to support data analysis
    and make complex security data more accessible to stakeholders.
    """
    
    def __init__(self):
        # Set visualization style
        plt.style.use('default')
        sns.set_palette("husl")
    
    def create_vulnerability_severity_chart(self, vulnerability_data: Dict[str, Any]) -> str:
        """Create vulnerability severity distribution chart."""
        try:
            # Extract severity data
            severity_counts = {
                "Critical": len(vulnerability_data.get("critical_vulnerabilities", [])),
                "High": len(vulnerability_data.get("high_vulnerabilities", [])),
                "Medium": len(vulnerability_data.get("medium_vulnerabilities", [])),
                "Low": len(vulnerability_data.get("low_vulnerabilities", []))
            }
            
            # Create pie chart
            fig, ax = plt.subplots(figsize=(10, 8))
            colors = ['#ff4444', '#ff8800', '#ffdd00', '#44aa44']
            
            wedges, texts, autotexts = ax.pie(
                severity_counts.values(),
                labels=severity_counts.keys(),
                colors=colors,
                autopct='%1.1f%%',
                startangle=90
            )
            
            ax.set_title('Vulnerability Distribution by Severity', fontsize=16, fontweight='bold')
            
            # Enhance text appearance
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
            
            plt.tight_layout()
            
            # Convert to base64 string
            return self._fig_to_base64(fig)
            
        except Exception as e:
            logger.error(f"Error creating vulnerability severity chart: {e}")
            return ""
    
    def create_stride_threat_matrix(self, stride_data: Dict[str, Any]) -> str:
        """Create STRIDE threat category matrix visualization."""
        try:
            # Extract STRIDE breakdown data
            stride_breakdown = stride_data.get("stride_breakdown", {})
            
            categories = list(stride_breakdown.keys())
            counts = list(stride_breakdown.values())
            
            # Create horizontal bar chart
            fig, ax = plt.subplots(figsize=(12, 8))
            
            bars = ax.barh(categories, counts, color=sns.color_palette("viridis", len(categories)))
            
            # Add value labels on bars
            for i, (bar, count) in enumerate(zip(bars, counts)):
                ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                       str(count), va='center', fontweight='bold')
            
            ax.set_xlabel('Number of Threats', fontsize=12, fontweight='bold')
            ax.set_title('STRIDE Threat Category Distribution', fontsize=16, fontweight='bold')
            ax.grid(axis='x', alpha=0.3)
            
            plt.tight_layout()
            return self._fig_to_base64(fig)
            
        except Exception as e:
            logger.error(f"Error creating STRIDE matrix: {e}")
            return ""
    
    def create_risk_heat_map(self, dread_data: Dict[str, Any]) -> str:
        """Create risk heat map based on DREAD scores."""
        try:
            # Extract threat data
            threats = dread_data.get("detailed_scores", [])
            
            if not threats:
                return ""
            
            # Prepare data for heat map
            threat_names = [threat["threat_id"][:20] + "..." if len(threat["threat_id"]) > 20 
                          else threat["threat_id"] for threat in threats[:10]]  # Top 10 threats
            
            dread_components = ["damage", "reproducibility", "exploitability", "affected_users", "discoverability"]
            
            # Create matrix
            matrix_data = []
            for threat in threats[:10]:
                row = [threat.get(component, 0) for component in dread_components]
                matrix_data.append(row)
            
            # Create heat map
            fig, ax = plt.subplots(figsize=(12, 10))
            
            im = ax.imshow(matrix_data, cmap='RdYlBu_r', aspect='auto', vmin=0, vmax=10)
            
            # Set ticks and labels
            ax.set_xticks(range(len(dread_components)))
            ax.set_xticklabels([comp.title() for comp in dread_components], rotation=45)
            ax.set_yticks(range(len(threat_names)))
            ax.set_yticklabels(threat_names)
            
            # Add colorbar
            cbar = plt.colorbar(im, ax=ax)
            cbar.set_label('DREAD Score (0-10)', rotation=270, labelpad=20)
            
            # Add text annotations
            for i in range(len(threat_names)):
                for j in range(len(dread_components)):
                    text = ax.text(j, i, f'{matrix_data[i][j]:.0f}',
                                 ha="center", va="center", color="white", fontweight='bold')
            
            ax.set_title('DREAD Risk Assessment Heat Map', fontsize=16, fontweight='bold', pad=20)
            
            plt.tight_layout()
            return self._fig_to_base64(fig)
            
        except Exception as e:
            logger.error(f"Error creating risk heat map: {e}")
            return ""
    
    def create_economic_impact_chart(self, economic_data: Dict[str, Any]) -> str:
        """Create economic impact analysis chart."""
        try:
            scenario_analysis = economic_data.get("scenario_analysis", {})
            
            scenarios = []
            impacts = []
            
            for scenario_name, scenario_data in scenario_analysis.items():
                scenarios.append(scenario_name.replace('_', ' ').title())
                impacts.append(scenario_data.get("total_economic_impact", 0))
            
            # Create bar chart
            fig, ax = plt.subplots(figsize=(14, 8))
            
            bars = ax.bar(range(len(scenarios)), impacts, 
                         color=sns.color_palette("rocket", len(scenarios)))
            
            # Format y-axis as currency
            ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'${x/1000:.0f}K'))
            
            # Add value labels on bars
            for bar, impact in zip(bars, impacts):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2., height + max(impacts)*0.01,
                       f'${impact/1000:.0f}K', ha='center', va='bottom', fontweight='bold')
            
            ax.set_xlabel('Attack Scenarios', fontsize=12, fontweight='bold')
            ax.set_ylabel('Economic Impact (AUD)', fontsize=12, fontweight='bold')
            ax.set_title('Economic Impact by Cyberattack Scenario', fontsize=16, fontweight='bold')
            
            # Rotate x-axis labels for better readability
            plt.xticks(range(len(scenarios)), scenarios, rotation=45, ha='right')
            
            ax.grid(axis='y', alpha=0.3)
            plt.tight_layout()
            
            return self._fig_to_base64(fig)
            
        except Exception as e:
            logger.error(f"Error creating economic impact chart: {e}")
            return ""
    
    def create_compliance_radar_chart(self, compliance_data: Dict[str, Any]) -> str:
        """Create regulatory compliance radar chart."""
        try:
            framework_results = compliance_data.get("framework_results", {})
            
            frameworks = []
            scores = []
            
            for framework, assessments in framework_results.items():
                frameworks.append(framework.replace('_', ' '))
                # Calculate average compliance score for framework
                if assessments:
                    avg_score = sum(assessment["compliance_score"] for assessment in assessments) / len(assessments)
                    scores.append(avg_score)
                else:
                    scores.append(0)
            
            if not frameworks:
                return ""
            
            # Create radar chart
            fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
            
            # Calculate angles for each framework
            angles = np.linspace(0, 2 * np.pi, len(frameworks), endpoint=False)
            
            # Close the plot
            scores_plot = scores + [scores[0]]
            angles_plot = np.append(angles, angles[0])
            
            # Plot
            ax.plot(angles_plot, scores_plot, 'o-', linewidth=2, label='Compliance Score')
            ax.fill(angles_plot, scores_plot, alpha=0.25)
            
            # Add framework labels
            ax.set_xticks(angles)
            ax.set_xticklabels(frameworks)
            
            # Set y-axis limits and labels
            ax.set_ylim(0, 100)
            ax.set_yticks([20, 40, 60, 80, 100])
            ax.set_yticklabels(['20%', '40%', '60%', '80%', '100%'])
            
            ax.set_title('Regulatory Compliance Assessment', fontsize=16, fontweight='bold', pad=20)
            ax.grid(True)
            
            plt.tight_layout()
            return self._fig_to_base64(fig)
            
        except Exception as e:
            logger.error(f"Error creating compliance radar chart: {e}")
            return ""
    
    def _fig_to_base64(self, fig) -> str:
        """Convert matplotlib figure to base64 string."""
        try:
            buffer = BytesIO()
            fig.savefig(buffer, format='png', dpi=150, bbox_inches='tight')
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            plt.close(fig)
            return image_base64
        except Exception as e:
            logger.error(f"Error converting figure to base64: {e}")
            plt.close(fig)
            return ""

class HTMLReportBuilder:
    """
    Builds comprehensive HTML reports with embedded visualizations.

    This class creates professional-looking HTML reports suitable
    for executive and technical audiences.
    """

    def __init__(self):
        self.viz_generator = VisualizationGenerator()
        self.template_env = self._setup_template_environment()

    def _setup_template_environment(self) -> Environment:
        """Setup Jinja2 template environment."""
        # Create templates directory if it doesn't exist
        templates_dir = Path("templates")
        templates_dir.mkdir(exist_ok=True)

        # Load templates from directory
        return Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)

    def build_report(self, config: ReportConfiguration, data: Dict[str, Any]) -> str:
        """Generate an HTML report from data and config."""
        try:
            template_path = Path("templates/report_template.html")
            if not template_path.exists():
                logger.warning("Default template not found. Creating fallback template.")
                template_content = """
                <html>
                <head><title>{{ report_title }}</title></head>
                <body>
                    <h1>{{ report_title }}</h1>
                    <h2>Author: {{ author }}</h2>
                    <h3>Organization: {{ organization }}</h3>
                    <p><strong>Classification:</strong> {{ classification }}</p>
                    {% if executive_summary %}
                    <h2>Executive Summary</h2>
                    <p>{{ executive_summary }}</p>
                    {% endif %}
                    {% if technical_details %}
                    <h2>Technical Details</h2>
                    <p>{{ technical_details }}</p>
                    {% endif %}
                    {% if visualizations %}
                    <h2>Visualizations</h2>
                    {% for viz_title, viz_image in visualizations.items() %}
                    <h3>{{ viz_title }}</h3>
                    <img src="data:image/png;base64,{{ viz_image }}" alt="{{ viz_title }}" />
                    {% endfor %}
                    {% endif %}
                    {% if recommendations %}
                    <h2>Recommendations</h2>
                    <ul>
                        {% for rec in recommendations %}<li>{{ rec }}</li>{% endfor %}
                    </ul>
                    {% endif %}
                </body>
                </html>
                """
                with open(template_path, 'w') as f:
                    f.write(template_content)

            template = self.template_env.get_template("report_template.html")

            visualizations = {}
            if config.include_visualizations:
                visualizations = {
                    "Vulnerability Severity": self.viz_generator.create_vulnerability_severity_chart(data.get("vulnerabilities", {})),
                    "STRIDE Threat Matrix": self.viz_generator.create_stride_threat_matrix(data.get("stride", {})),
                    "DREAD Risk Heat Map": self.viz_generator.create_risk_heat_map(data.get("dread", {})),
                    "Economic Impact": self.viz_generator.create_economic_impact_chart(data.get("economic", {})),
                    "Compliance Radar": self.viz_generator.create_compliance_radar_chart(data.get("compliance", {}))
                }

            report_html = template.render(
                report_title=config.report_title,
                organization=config.organization,
                author=config.author,
                classification=config.classification,
                executive_summary=data.get("executive_summary") if config.include_executive_summary else None,
                technical_details=data.get("technical_details") if config.include_technical_details else None,
                visualizations=visualizations,
                recommendations=data.get("recommendations") if config.include_recommendations else None
            )

            return report_html

        except Exception as e:
            logger.error(f"Error building HTML report: {e}")
            return "<p>Error generating report</p>"