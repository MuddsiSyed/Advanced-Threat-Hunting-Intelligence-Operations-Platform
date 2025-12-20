# Threat Intelligence Automation

## Overview

Automated collection and management of 59,994+ threat indicators from 5 open-source intelligence feeds.

## Components

- `threat_feed_collector.py` - Automated daily collection
- `threat_intel_analyzer.py` - Manual IOC enrichment
- `feed_config.json` - Source configuration
- `threat_intel.db` - SQLite storage (59,994 indicators)

## Sources

| Source | Indicators | Confidence Weight |
|--------|-----------|-------------------|
| AlienVault OTX | 53,031 | 0.85 |
| Malware Domain List | 2,810 | 0.90 |
| PhishTank | 2,035 | 0.80 |
| Emerging Threats | 2,116 | 0.95 |
| Controlled Testing | 2 | 0.95 |

## Features

- Automated daily collection (2 AM UTC cron)
- Deduplication (262 duplicates removed)
- Confidence scoring algorithm
- Splunk HEC integration
- 90-day retention policy

## Usage
```bash
# Manual collection
python3 threat_feed_collector.py

# IOC analysis
python3 threat_intel_analyzer.py --ioc 1.2.3.4
```

---

**Full documentation coming Week 3**
