# System Architecture

## Overview

Advanced Threat Hunting & Intelligence Operations Platform architecture built on AWS infrastructure with Splunk SIEM integration, automated threat intelligence collection, and validated detection capabilities.

## Architecture Diagram

![architecture-diagram-01](https://github.com/user-attachments/assets/dcf1168a-1998-4be2-9e17-61ce156ff2dc)


**Animated Architecture**: Complete data flow visualization showing threat intelligence collection from 5 OSINT sources, Splunk SIEM correlation, Active Directory monitoring, and attack validation infrastructure.

For detailed architecture documentation, see the [Main Project README](../README.md#-architecture).

## Quick Reference

**Infrastructure**:
- 4 AWS EC2 instances (t3.medium, ap-south-1 region)
- Splunk Enterprise 9.4.4 SIEM
- Active Directory domain controller (Windows Server 2022)
- Kali Linux attack validation platform

**Data Flow**:
1. OSINT sources → Analysis Workstation (59,994+ IOCs daily)
2. Analysis Workstation → Splunk (index=cti via HEC)
3. ADDC01 → Splunk (index=endpoint via Universal Forwarder)
4. Kali Linux → ADDC01 (controlled attack validation)
5. Splunk correlation engine (cti + endpoint indexes)

**Key Components**:
- Threat Intelligence: 59,994 indicators from 5 sources
- MITRE ATT&CK: 24 techniques mapped
- Detection: 5 validated techniques, 100% accuracy
- Automation: Daily collection at 2 AM UTC

For complete technical details, implementation guides, and validation results, refer to component-specific README files in the project structure.

