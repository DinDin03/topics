from src.report_generator import ReportGenerator, ReportConfiguration

# Dummy data for testing
data = {
    "executive_summary": "This is a test executive summary.",
    "technical_details": "Technical details go here.",
    "vulnerabilities": {
        "critical_vulnerabilities": [{"cve_id": "CVE-TEST-0001"}],
        "high_vulnerabilities": [],
        "medium_vulnerabilities": [],
        "low_vulnerabilities": []
    },
    "stride": {
        "stride_breakdown": {"SPOOFING": 1, "TAMPERING": 0, "REPUDIATION": 0, "INFORMATION_DISCLOSURE": 0, "DENIAL_OF_SERVICE": 0, "ELEVATION_OF_PRIVILEGE": 0}
    },
    "dread": {
        "detailed_scores": [
            {"threat_id": "T1", "damage": 8, "reproducibility": 7, "exploitability": 6, "affected_users": 5, "discoverability": 4}
        ]
    },
    "economic": {
        "scenario_analysis": {"Test Scenario": {"total_economic_impact": 10000}}
    },
    "compliance": {
        "framework_results": {"AEMO_VPP": []}
    },
    "recommendations": ["Test recommendation 1", "Test recommendation 2"]
}

config = ReportConfiguration(
    report_title="Test Report",
    organization="Test Org",
    author="Test Author"
)

generator = ReportGenerator()
report_html = generator.generate_report(config, data)

output_path = "test_report.html"
generator.save_report(config, data, output_path)

print(f"Report generated and saved to {output_path}") 