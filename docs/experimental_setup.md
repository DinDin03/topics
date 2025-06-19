# Experimental Setup and System Configuration

## System Architecture Overview

### Target System: Adelaide Solar Inverter Network

The experimental setup focuses on a representative solar inverter system deployed in Adelaide, South Australia, designed to meet AEMO Virtual Power Plant (VPP) requirements and demonstrate cybersecurity analysis capabilities.

### System Components

#### 1. Primary Solar Inverter (inverter_001)
- **Manufacturer**: Sungrow
- **Model**: SG5KTL
- **Capacity**: 5.0 kW
- **Firmware Version**: 1.0.3
- **Location**: Residential Rooftop - North Array
- **Protocols**: Modbus, MQTT, HTTPS
- **Network Interfaces**: Ethernet, WiFi
- **API Endpoints**: `/api/v1/status`, `/api/v1/control`, `/api/v1/telemetry`, `/api/v1/configuration`

#### 2. Secondary Solar Inverter (inverter_002)
- **Manufacturer**: Sungrow
- **Model**: SG3KTL
- **Capacity**: 3.0 kW
- **Firmware Version**: 1.0.1
- **Location**: Residential Rooftop - South Array
- **Protocols**: Modbus, MQTT
- **Network Interfaces**: Ethernet
- **API Endpoints**: `/api/v1/status`, `/api/v1/telemetry`

#### 3. IoT Communication Gateway (gateway_001)
- **Manufacturer**: Generic
- **Model**: IoT-GW-001
- **Capacity**: 0.0 kW (non-power component)
- **Firmware Version**: 2.0.0
- **Location**: Electrical Panel - Main Distribution
- **Protocols**: MQTT, HTTPS, Modbus, Ethernet
- **Network Interfaces**: Ethernet, WiFi, Cellular
- **Features**: Data aggregation, remote control, protocol translation, cloud connectivity

#### 4. AEMO VPP API Endpoint (api_001)
- **Manufacturer**: AEMO
- **Model**: VPP-API-v2
- **Version**: 2.1.0
- **Location**: Cloud Infrastructure
- **Protocols**: HTTPS, OAuth2
- **API Endpoints**: `/vpp/v2/devices/register`, `/vpp/v2/devices/control`, `/vpp/v2/devices/status`, `/vpp/v2/market/dispatch`

#### 5. Solar Monitoring Platform (monitoring_001)
- **Manufacturer**: Solar Analytics
- **Model**: SA-Monitor-Pro
- **Version**: 3.2.1
- **Location**: Cloud Infrastructure
- **Protocols**: HTTPS, MQTT
- **API Endpoints**: `/monitor/v1/devices`, `/monitor/v1/data/ingest`, `/monitor/v1/alerts`, `/monitor/v1/reports`

#### 6. Web Management Interface (web_interface_001)
- **Manufacturer**: Sungrow
- **Model**: iSolarCloud
- **Version**: 4.1.2
- **Location**: Inverter Local Network
- **Protocols**: HTTP, HTTPS
- **Network Interfaces**: Ethernet

#### 7. Local Configuration Database (database_001)
- **Manufacturer**: SQLite
- **Model**: SQLite3
- **Version**: 3.36.0
- **Location**: Gateway Local Storage
- **Protocols**: SQLite

## Network Topology

### Network Configuration
- **Internet Facing**: Yes
- **Firewall Enabled**: No
- **Network Segmentation**: No
- **VPN Access**: No
- **Intrusion Detection**: No
- **Network Monitoring**: No

### Trust Boundaries
1. **INTERNET**: Public internet access
2. **DMZ**: Demilitarized zone (not implemented)
3. **INTERNAL_NETWORK**: Internal corporate network (not implemented)
4. **DEVICE_NETWORK**: IoT device network (inverters, gateway)
5. **MANAGEMENT_NETWORK**: Network management zone (not implemented)

### Data Flows

#### Flow 1: Inverter to Gateway Telemetry
- **Source**: inverter_001
- **Destination**: gateway_001
- **Protocol**: Modbus TCP
- **Port**: 502
- **Frequency**: 30 seconds
- **Encryption**: No
- **Authentication**: No
- **Data Types**: Power output, voltage measurements, current measurements, temperature readings, status flags

#### Flow 2: Gateway to AEMO VPP API
- **Source**: gateway_001
- **Destination**: api_001
- **Protocol**: HTTPS
- **Port**: 443
- **Encryption**: Yes
- **Authentication**: OAuth2
- **Data Types**: Device status, control acknowledgments

#### Flow 3: Gateway to Monitoring Platform
- **Source**: gateway_001
- **Destination**: monitoring_001
- **Protocol**: MQTT
- **Port**: 1883
- **Encryption**: No
- **Authentication**: Basic
- **Data Types**: Aggregated telemetry, performance metrics

## Security Configuration

### Current Security Controls

#### Inverter Security
- **Basic Authentication**: Enabled (default credentials)
- **HTTPS**: Available but not enforced
- **Default Credentials**: Not changed
- **Vulnerability Notes**:
  - Default credentials not changed
  - HTTP interface available alongside HTTPS
  - Modbus interface unencrypted

#### Gateway Security
- **Encryption**: Enabled
- **Authentication**: Enabled
- **Access Logging**: Enabled
- **Default Credentials**: Changed
- **Internet Facing**: Yes

#### API Security
- **OAuth2 Authentication**: Enabled
- **HTTPS Encryption**: Enabled
- **Rate Limiting**: Enabled
- **API Key Management**: Enabled
- **Audit Logging**: Enabled

### Known Vulnerabilities

#### Critical Vulnerabilities
1. **Default Admin Credentials**: Multiple components use unchanged default credentials
2. **Unencrypted Communications**: Modbus and some MQTT communications lack encryption
3. **Outdated Firmware**: Secondary inverter running outdated firmware version

#### High Vulnerabilities
1. **HTTP Interface**: Web interface supports both HTTP and HTTPS
2. **No Network Segmentation**: All components on same network
3. **No Firewall**: Network lacks firewall protection

#### Medium Vulnerabilities
1. **Weak Authentication**: Basic authentication on some interfaces
2. **No Intrusion Detection**: No monitoring for suspicious activities
3. **Unencrypted Database**: Local database lacks encryption

## Experimental Parameters

### Analysis Scope
- **Geographic Focus**: South Australia
- **Regulatory Framework**: AEMO VPP, AS4777, NER
- **Time Period**: 2024-2025
- **Market Conditions**: Representative South Australian electricity market

### Economic Parameters
- **Electricity Spot Price**: Based on historical SA market data
- **Generation Revenue**: $80/MWh average
- **Capacity Factor**: 30% (typical for residential solar)
- **Emergency Response Cost**: $500/hour
- **Equipment Replacement Cost**: $1,500/kW

### Risk Assessment Parameters
- **DREAD Scoring**: 1-10 scale for each component
- **STRIDE Categories**: All six threat categories analyzed
- **CVSS Scoring**: Standard Common Vulnerability Scoring System
- **Risk Levels**: Critical, High, Medium, Low, Minimal

### Compliance Requirements
- **AEMO VPP**: Mandatory participation requirements
- **AS4777**: Grid connection standards
- **Cybersecurity Standards**: Recommended implementation
- **Deadlines**: 2024-12-31 for AEMO VPP compliance

## Test Environment

### Software Environment
- **Python Version**: 3.11.7
- **Operating System**: macOS (Darwin 24.5.0)
- **Dependencies**: See requirements.txt for complete list
- **Testing Framework**: pytest 8.4.1

### Data Sources
- **CVE Database**: NIST National Vulnerability Database (simulated)
- **Manufacturer Data**: Representative data for major manufacturers
- **Regulatory Requirements**: Current South Australian regulations
- **Economic Data**: Historical electricity market data

### Output Formats
- **JSON Reports**: Comprehensive analysis results
- **CSV Summaries**: Economic impact summaries
- **HTML Reports**: Human-readable analysis reports
- **Log Files**: Detailed execution logs

## Validation and Verification

### Test Cases
1. **Vulnerability Analysis**: CVE database integration and analysis
2. **STRIDE Modeling**: Threat identification and risk scoring
3. **DREAD Assessment**: Quantitative risk assessment
4. **Regulatory Compliance**: Multi-framework compliance evaluation
5. **Economic Impact**: Scenario-based economic modeling

### Quality Assurance
- **Unit Tests**: Comprehensive test coverage for all modules
- **Integration Tests**: End-to-end analysis workflow testing
- **Data Validation**: Input data accuracy verification
- **Result Consistency**: Cross-validation between analysis frameworks

### Performance Metrics
- **Analysis Time**: < 5 seconds for comprehensive analysis
- **Memory Usage**: < 500MB for typical analysis
- **Accuracy**: Validated against known vulnerability databases
- **Scalability**: Supports multiple inverter configurations

This experimental setup provides a realistic foundation for cybersecurity analysis of solar inverter systems in South Australia's regulatory environment, enabling comprehensive assessment of vulnerabilities, threats, and economic impacts.
