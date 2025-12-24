# Threat Hunting Queries & Validation

## Overview

Advanced threat hunting platform with validated detection capabilities across multiple MITRE ATT&CK techniques. All queries validated through controlled penetration testing and industry-standard Atomic Red Team framework.

**Validation Status**: 5 techniques validated with 100% detection accuracy  
**Detection Platform**: Splunk Enterprise with Sysmon telemetry  
**Threat Intelligence Integration**: 59,994 IOCs with real-time correlation  
**Methodology**: Hypothesis-driven validation with quantified results  

---

## 🎯 Validated Hunting Capabilities

### Summary Statistics

**Techniques Validated**: 5 MITRE ATT&CK techniques  
**Tactics Covered**: 3 (Credential Access, Execution, Persistence)  
**Total Events Detected**: 142+  
**Detection Rate**: 100% across all tests  
**False Positives**: 0  
**Validation Methods**: Kali Linux penetration testing + Atomic Red Team  

---

## 🔍 Validated Techniques

### 1. T1110.001 - Brute Force: Password Guessing ✅

**Validation Method**: Kali Linux Hydra RDP brute force attack  
**Results**: 123/123 events detected (100% accuracy)  
**Detection Query**: IOC-based correlation with threat intelligence  

**Key Achievement**: Automated IOC correlation with 59,994 threat indicators, achieving sub-second detection latency with zero false positives.

[View detailed validation methodology →](./validation-methodology.md)

---

### 2. T1059.001 - PowerShell Execution ✅

**Validation Method**: Atomic Red Team Test #1 (Mimikatz download cradle)  
**Results**: 11 events detected (100% accuracy)  
**Detection**: Sysmon Event 1 (Process Creation)  

**Query Category**: Command and Scripting Interpreter detection

---

### 3. T1053.005 - Scheduled Task Creation ✅

**Validation Method**: Atomic Red Team Test #1  
**Results**: 2 scheduled tasks detected (100% accuracy)  
**Detection**: Windows Event 4698 (Scheduled Task Created)  

**Query Category**: Persistence mechanism detection

---

### 4. T1106 - Native API Execution ✅

**Validation Method**: Atomic Red Team (multiple tests)  
**Results**: 6 events detected (100% accuracy)  
**Detection**: Sysmon Event 1 with MITRE mapping  

**Query Category**: Execution technique detection

---

### 5. T1047 - Windows Management Instrumentation ✅

**Validation Method**: Atomic Red Team Test #1  
**Results**: Multiple wmic.exe executions detected  
**Detection**: Sysmon Event 1 (Process Creation)  

**Query Category**: WMI-based execution detection

---

## 📊 MITRE ATT&CK Coverage

### Tactic Distribution

**Execution**: 75% of detected activity (4 techniques)  
- T1059.001 (PowerShell)
- T1106 (Native API)
- T1047 (WMI)

**Persistence**: 25% of detected activity (1 technique)  
- T1053.005 (Scheduled Task)

**Credential Access**: Validated separately  
- T1110.001 (Brute Force)

### Coverage Visualization

![Tactic Distribution](../../screenshots/05-attack-validation/tactic-distribution-atomic.png)

![Technique Coverage](../../screenshots/05-attack-validation/atomic-summary-visualization.png)

---

## 🔧 Detection Capabilities

### IOC-Based Hunting

**Database**: 59,994 unique threat indicators  
**Sources**: 5 threat intelligence feeds  
**Correlation**: Real-time automated matching  
**Confidence Scoring**: Multi-source weighted algorithm  

**Signature Query**: Enhanced IOC hunt with automatic MITRE ATT&CK mapping
```splunk
index=endpoint (EventCode=3 OR EventCode=4624 OR EventCode=4625)
| eval extracted_ip=coalesce(DestinationIp, Source_Network_Address, SourceAddress)
| join type=left extracted_ip 
    [search index=cti indicator_type="ip" earliest=0
    | eval extracted_ip=indicator
    | fields extracted_ip, confidence_score, source_feed, description]
| lookup mitre_attack_mapping EventCode OUTPUT TechniqueID, TechniqueName, Tactic, Description
| where isnotnull(confidence_score)
| table _time, ComputerName, extracted_ip, confidence_score, source_feed, TechniqueID, TechniqueName, Tactic, EventCode, Account_Name
| sort -confidence_score, -_time
```

**Achievement**: Detected 123 Kali brute force attempts with 0.95 confidence score and automatic T1110.001 attribution.

---

### MITRE ATT&CK Framework Integration

**Implementation**: Custom lookup table mapping EventCodes to ATT&CK techniques  
**Coverage**: 24 techniques across 8 tactics  
**Automation**: Automatic technique attribution in all queries  

**Framework Query**: Real-time technique detection dashboard
```splunk
index=endpoint 
| lookup mitre_attack_mapping EventCode OUTPUT TechniqueID, TechniqueName, Tactic, Description
| where isnotnull(TechniqueID)
| stats count by TechniqueID, TechniqueName, Tactic
| sort -count
```

---

### Atomic Red Team Validation

**Framework**: Industry-standard attack simulation  
**Techniques Tested**: 5 (100% success rate)  
**Detection Platform**: Splunk + Sysmon telemetry  

**Validation Benefits**:
- Proves detection capabilities with real attack simulation
- Quantifies detection accuracy (100% across all tests)
- Demonstrates professional security testing methodology
- Provides reproducible validation evidence

[View complete Atomic Red Team validation report →](../../05-attack-validation/atomic-red-team-validation.md)

---

## 📚 Query Library

Complete collection of validated threat hunting queries with MITRE ATT&CK integration:

[📖 View Complete Hunting Query Library →](hunting-query-library.md)

**Query Categories**:
- IOC-based threat hunting (59,994 indicator correlation)
- MITRE ATT&CK detection dashboard queries
- Atomic Red Team validated technique queries
- Coverage reporting and visualization queries

---

## 🎯 Validation Methodology

**Four-Step Scientific Approach**:

1. **Baseline Hunt** - Query clean environment (expect 0 results)
2. **IOC Enrichment** - Add controlled test indicators to threat database
3. **Attack Execution** - Perform controlled penetration test
4. **Validated Detection** - Confirm 100% event detection

**Key Principle**: Hypothesis-driven validation with quantified results

[View detailed validation methodology →](validation-methodology.md)

---

## 📊 Performance Metrics

### Detection Performance

| Metric | Result | Industry Benchmark |
|--------|--------|-------------------|
| Detection Rate | 100% | 85-95% |
| False Positive Rate | 0% | 5-15% |
| Detection Latency | <1 second | <5 seconds |
| IOC Correlation Speed | Sub-second | 1-3 seconds |
| Threat Intel Database | 59,994 indicators | 10K-50K typical |

### Coverage Metrics

| Category | Coverage | Target |
|----------|----------|--------|
| MITRE Techniques Validated | 5 | 3-5 for portfolio |
| MITRE Tactics Covered | 3 | 2-4 for portfolio |
| Attack Simulations | 6 (Kali + 5 Atomic) | 3-5 typical |
| Detection Queries | 7+ validated | 5-8 typical |

---

## 🔬 Technical Implementation

### Data Sources

**Windows Event Logs**:
- Event 4624/4625 (Authentication)
- Event 4698 (Scheduled Task Created)
- Event 4720 (User Created)

**Sysmon Operational Logs**:
- Event 1 (Process Creation)
- Event 3 (Network Connection)
- Event 10 (ProcessAccess)

**Threat Intelligence**:
- Custom SQLite database (59,994 indicators)
- Real-time correlation via Splunk join operations
- Multi-source confidence scoring

### Splunk Integration

**Add-ons Installed**:
- Splunk Add-on for Microsoft Sysmon
- Custom MITRE ATT&CK lookup table

**Index Strategy**:
- `index=endpoint`: Windows Security + Sysmon events
- `index=cti`: Threat intelligence indicators
- Real-time correlation across indexes

---

## 🎓 Skills Demonstrated

### Technical Competencies

✅ **Threat Hunting**: Hypothesis-driven methodology with validation  
✅ **MITRE ATT&CK**: Framework integration and technique mapping  
✅ **Detection Engineering**: Query development with 100% accuracy  
✅ **Threat Intelligence**: Multi-source IOC correlation at scale  
✅ **SIEM Engineering**: Advanced Splunk query development  
✅ **Penetration Testing**: Controlled attack simulation for validation  

### Professional Capabilities

✅ **Validation Methodology**: Scientific approach with quantified results  
✅ **Documentation**: Executive-ready reporting and visualization  
✅ **Tool Expertise**: Atomic Red Team, Kali Linux, Splunk, Sysmon  
✅ **Framework Knowledge**: MITRE ATT&CK practical application  

---

## 📁 Documentation Structure
```
03-threat-hunting/
├── README.md (this file)
├── validation-methodology.md (4-step validation process)
└── hunting-query-library.md (7+ validated queries)

Related Documentation:
├── 05-attack-validation/atomic-red-team-validation.md
└── screenshots/04-threat-hunting/ (28 validation screenshots)
```

---

**Last Updated**: December 20, 2025  
**Validation**: 5 techniques, 100% detection rate, 0 false positives  
**Portfolio Component**: Advanced Threat Hunting & Intelligence Operations Platform
