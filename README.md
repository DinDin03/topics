# Solar Inverter Cybersecurity Research Project

## Overview

This project examines cybersecurity vulnerabilities in internet-connected solar inverters within distributed energy systems, with a focus on South Australia's regulatory environment where remote inverter control is mandatory.

## Project Objectives

- Identify common cyber threats targeting solar inverters (firmware attacks, network intrusions, communication vulnerabilities)
- Analyze vulnerabilities in communication protocols (Modbus, MQTT, HTTP, TLS)
- Evaluate the impact of security mechanisms on performance, latency, and power consumption
- Simulate attack scenarios and propose mitigation strategies

## Project Structure

```
solar-inverter-cybersecurity/
├── README.md                           # Project documentation
├── requirements.txt                    # Python dependencies
├── data/                              # Raw and processed data files
│   ├── vulnerabilities/               # Vulnerability databases
│   ├── regulatory/                    # SA regulatory requirements
│   └── simulation/                    # Simulation input data
├── src/                              # Source code modules
│   ├── __init__.py                   # Package initialization
│   ├── vulnerability_analysis.py     # Vulnerability assessment tools
│   ├── stride_threat_modeling.py     # STRIDE threat analysis
│   ├── dread_assessment.py          # DREAD risk assessment
│   ├── regulatory_analysis.py       # Regulatory compliance analysis
│   ├── economic_impact.py           # Economic impact calculations
│   └── report_generator.py          # Automated report generation
├── config/                           # Configuration files
│   ├── system_components.json       # System architecture definitions
│   └── threat_templates.json        # Threat modeling templates
├── outputs/                          # Generated results
│   ├── threat_model_results.json    # Threat analysis outputs
│   ├── vulnerability_report.html    # Vulnerability assessment report
│   └── economic_impact_analysis.csv # Economic impact data
├── tests/                           # Unit and integration tests
│   ├── test_vulnerability_analysis.py
│   ├── test_stride_modeling.py
│   └── test_economic_impact.py
└── docs/                           # Documentation
    ├── methodology.md              # Research methodology
    ├── experimental_setup.md      # Experiment configuration
    └── results_analysis.md        # Results and findings
```

## Key Technologies and Protocols

### Communication Protocols Analyzed
- **Modbus**: Industrial communication protocol (plaintext, minimal authentication)
- **MQTT**: Lightweight messaging protocol for IoT
- **HTTP/HTTPS**: Web communication protocols
- **TLS**: Transport Layer Security for encryption

### Security Frameworks
- **STRIDE**: Threat modeling methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- **DREAD**: Risk assessment model (Damage, Reproducibility, Exploitability, Affected Users, Discoverability)

## Installation and Setup

1. **Clone the repository**
```bash
git clone <repository-url>
cd solar-inverter-cybersecurity
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Configure the environment**
```bash
# Copy example configuration
cp config/system_components.json.example config/system_components.json
# Edit configuration files as needed
```

## Usage

### 1. Vulnerability Analysis
```bash
python src/vulnerability_analysis.py --input data/vulnerabilities/ --output outputs/
```

### 2. STRIDE Threat Modeling
```bash
python src/stride_threat_modeling.py --config config/system_components.json
```

### 3. Economic Impact Assessment
```bash
python src/economic_impact.py --scenario attack_simulation --duration 3h
```

### 4. Generate Reports
```bash
python src/report_generator.py --all --format html,csv,json
```

## Research Context

### South Australia's Unique Environment
- **Mandatory API Access**: Government requires remote inverter control via manufacturer APIs
- **High Solar Penetration**: Significant residential solar adoption
- **Economic Volatility**: Spot price fluctuations and infrastructure strain

### Attack Scenarios Simulated
1. **Modbus Kill Commands**: Shutting down inverters during peak generation
2. **MQTT Credential Hijacking**: Unauthorized access through weak authentication
3. **API Key Exploitation**: Static key compromise and brute force attacks
4. **Firmware Injection**: Malicious code insertion through update mechanisms

## Key Findings Preview

- **Default Credentials**: Many inverters deployed with admin/admin credentials
- **Protocol Vulnerabilities**: Plaintext Modbus and unencrypted MQTT widely used
- **API Security Gaps**: Static keys and lack of rate limiting
- **Economic Impact**: Potential for significant spot price manipulation

## Mitigation Strategies

1. **Protocol Security**: Implement TLS encryption for all communications
2. **Authentication**: Deploy multi-factor authentication and certificate-based auth
3. **API Security**: Implement key rotation, rate limiting, and proper authorization
4. **Firmware Security**: Code signing, secure boot, and encrypted updates
5. **Network Segmentation**: Isolate inverter networks from general IT infrastructure


## Academic Context

This project is part of a cybersecurity research initiative focusing on critical infrastructure protection. The research methodology follows academic standards and includes peer review of findings.

**Student**: Dineth Katanwala  
**Supervisor**: Dr. Marian Mihailescu  
**Institution**: [University Name]  
**Course**: Cybersecurity Research Project


## Acknowledgments

- Australian Energy Market Operator (AEMO) for VPP demonstration data
- National Renewable Energy Laboratory (NREL) for PVWatts API access
- Secura Security Research for vulnerability disclosure frameworks
- South Australian government for regulatory documentation

## References

See `docs/methodology.md` for complete academic references and citation format.