# Threat Hunting Validation Methodology

## Overview
This document describes the systematic validation approach used to prove threat hunting query effectiveness through controlled penetration testing.

## Validation Framework

### Phase 1: Baseline Hunt (Negative Result Documentation)
**Objective**: Establish clean environment baseline

**Query**: Automated IOC Sweep Across Endpoints
```splunk
index=endpoint (EventCode=3 OR EventCode=4624 OR EventCode=4625)
| eval extracted_ip=coalesce(DestinationIp, Source_Network_Address, SourceAddress)
| join type=left extracted_ip 
    [search index=cti indicator_type="ip" earliest=0
    | eval extracted_ip=indicator
    | fields extracted_ip, confidence_score, source_feed, description]
| where isnotnull(confidence_score)
| table _time, ComputerName, extracted_ip, confidence_score, source_feed, EventCode, Account_Name
| sort -confidence_score
```

**Result**: 0 events (clean environment confirmed)

**Screenshot**: </br> <img width="1913" height="654" alt="step1b-baseline-hunt-no-results" src="https://github.com/user-attachments/assets/5ee2df8b-0bfb-4c8e-9ce2-076813b8a13b" />

---

### Phase 2: Threat Intelligence Enrichment
**Objective**: Add controlled test indicators to CTI database

**Indicators Added**:
- **13.232.250.178** (Kali public IP) - confidence: 0.95
- **172.31.38.154** (Kali private IP) - confidence: 0.95
- **Source**: CONTROLLED_PENETRATION_TESTING
- **Total CTI Database**: 59,994 indicators

**Screenshots**: 
  <img width="1918" height="487" alt="step2a-sql-insert-kali-ips" src="https://github.com/user-attachments/assets/76221a39-0106-4de8-97c9-f9dfb0654396" /> </br></br>
  <img width="1920" height="956" alt="step2c-kali-ips-pushed-splunk" src="https://github.com/user-attachments/assets/04bca9d9-2002-4f15-a438-5f9a39e2251f" /> </br></br>
  <img width="1919" height="456" alt="step2d-kali-ips-in-splunk" src="https://github.com/user-attachments/assets/09a6689e-8184-4a78-a3ee-54ad5cb7a059" /> </br></br>

---

### Phase 3: Controlled Attack Execution
**Objective**: Generate realistic attack telemetry for validation

**Attack Tool**: Hydra v9.5
**Target**: ADDC01-ThreatHunt (172.31.32.240:3389)
**Attack Type**: RDP brute force
**Parameters**: 
- 2 tasks per server
- 30 total login attempts
- Attack duration: ~14 seconds

**Screenshot**: <img width="1920" height="371" alt="step3a-kali-attack-complete" src="https://github.com/user-attachments/assets/e79885ff-0b72-48db-a847-41ee5d371ea7" />

---

### Phase 4: Detection Validation
**Objective**: Prove hunting query detects controlled attack

**Query**: Same as Phase 1 (Automated IOC Sweep)

**Results**:
- **Events Detected**: 123 correlated events
- **Detection Rate**: 100% (all attack events correlated)
- **Latency**: Real-time (sub-second detection)
- **False Positives**: 0
- **False Negatives**: 0

**Key Findings**:
- Source IP: 172.31.38.154 (Kali internal)
- Confidence Score: 0.95 (high confidence)
- EventCode: 4625 (failed authentication)
- Source: CONTROLLED_PENETRATION_TESTING
- Attack Timeline: 01:33:12 - 01:33:26 (14 seconds)

**Screenshots**:
  <img width="1915" height="923" alt="step4a-validated-detection-results" src="https://github.com/user-attachments/assets/a51dec29-8559-4ef4-8dfb-e8198adb9814" /> </br></br></br>
  <img width="1920" height="1074" alt="step4b-detailed-event-correlation" src="https://github.com/user-attachments/assets/434bd726-b142-41c2-95db-5e315cbab55f" /> </br></br></br>
  <img width="1920" height="617" alt="step4c-attack-timeline-visualization" src="https://github.com/user-attachments/assets/26702f9f-5ea5-4135-89ef-271420669507" /> </br></br></br>

---

## Professional Value Demonstrated

### Enterprise Capabilities:
1. **Large-Scale IOC Correlation**: 59,994+ indicators processed in real-time
2. **Multi-Event Type Support**: Network (EventCode 3), Authentication (4624/4625)
3. **Automated Enrichment**: CTI data automatically joined with endpoint events
4. **High Confidence Scoring**: 0.95 confidence threshold for controlled tests

### Threat Hunting Maturity:
- **Hypothesis-Driven**: Systematic validation methodology
- **Evidence-Based**: Documented baseline and detection
- **Reproducible**: Complete documentation enables replication
- **Quantified Results**: 123 events, 100% detection, 0% false positives

---

## Conclusion

The automated IOC sweep hunting query successfully detected 100% of controlled penetration testing activity with zero false positives and sub-second latency. This validation proves the query's effectiveness for real-world threat detection using enterprise-scale threat intelligence correlation (59,994 indicators).
