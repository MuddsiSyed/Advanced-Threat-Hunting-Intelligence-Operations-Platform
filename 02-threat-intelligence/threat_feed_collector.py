#!/usr/bin/env python3
"""
Threat Intelligence Feed Collector

This script automatically collects threat intelligence from multiple free sources,
normalizes the data, deduplicates indicators, and stores them in a local database.
It's designed for Security Operations Centers (SOCs) to maintain current threat
intelligence without manual intervention.

What is Threat Intelligence?
- Threat Intelligence (TI) is evidence-based knowledge about existing or emerging
  security threats that helps organizations make informed security decisions
- IOCs (Indicators of Compromise) are pieces of forensic data that identify
  potentially malicious activity (IPs, domains, URLs, file hashes, etc.)

This script collects IOCs from multiple public feeds to build a comprehensive
threat intelligence database for your organization.

Author: SOC Team
Date: 2025-01-XX
Version: 1.0
"""

import sqlite3
import json
import csv
import time
import logging
import requests
import datetime
import hashlib
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, urljoin
import os
import gzip
import io
import urllib3
import warnings

class ThreatFeedCollector:
    """
    Main class for collecting and managing threat intelligence feeds.
    
    This class handles:
    1. Fetching data from multiple threat intelligence sources
    2. Normalizing different data formats into a consistent structure
    3. Deduplicating indicators using hash comparison
    4. Calculating confidence scores based on source reputation
    5. Storing results in SQLite database
    6. Generating reports and summaries
    """
    
    def __init__(self, config_file: str = "feed_config.json", db_path: str = "threat_intel.db"):
        """
        Initialize the threat feed collector.
        
        Args:
            config_file (str): Path to configuration file
            db_path (str): Path to SQLite database file
        """
        self.config = self._load_config(config_file)
        self.db_path = db_path
        self.logger = self._setup_logging()
        
        # Initialize database
        self._init_database()
        
        # Source reliability weights (0.0 to 1.0)
        # Higher weight = more reliable source
        self.source_weights = {
            'otx': 0.85,              # AlienVault OTX - High quality, community-driven
            'malware_domain_list': 0.90,  # Malware Domain List - Very reliable
            'phishtank': 0.80,       # PhishTank - Good for phishing detection
            'emerging_threats': 0.95, # Emerging Threats - Excellent reputation
            'urlhaus': 0.85,         # URLhaus - Reliable malware URL database
        }
        
        # Statistics tracking
        self.collection_stats = {
            'total_collected': 0,
            'total_duplicates': 0,
            'total_stored': 0,
            'source_counts': {},
            'errors': []
        }
        
        self.logger.info("Threat Feed Collector initialized successfully")

    def _load_config(self, config_file: str) -> Dict:
        """
        Load configuration from JSON file.
        
        Args:
            config_file (str): Path to configuration file
            
        Returns:
            Dict: Configuration dictionary
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            return config
        except FileNotFoundError:
            print(f"Configuration file {config_file} not found. Using default settings.")
            # Return default configuration
            return {
                "feeds": {
                    "otx": {"enabled": True, "api_key": ""},
                    "malware_domain_list": {"enabled": True},
                    "phishtank": {"enabled": True, "api_key": ""},
                    "emerging_threats": {"enabled": True},
                    "urlhaus": {"enabled": True}
                },
                "database": {
                    "retention_days": 90,
                    "batch_size": 1000
                },
                "output": {
                    "splunk_enabled": False,
                    "s3_enabled": False
                },
                "settings": {
                    "request_timeout": 30,
                    "max_retries": 3,
                    "delay_between_sources": 2
                }
            }
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in configuration file: {e}")
            raise

    def _setup_logging(self) -> logging.Logger:
        """
        Configure logging for the application.
        
        Returns:
            logging.Logger: Configured logger instance
        """
        logger = logging.getLogger('ThreatFeedCollector')
        logger.setLevel(logging.INFO)
        
        # Create file handler
        log_filename = f"threat_feeds_{datetime.datetime.now().strftime('%Y%m%d')}.log"
        file_handler = logging.FileHandler(log_filename)
        file_handler.setLevel(logging.INFO)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger

    def _init_database(self):
        """
        Initialize the SQLite database with required tables.
        
        Database Schema:
        - indicators: Main table storing all IOCs with metadata
        - sources: Information about threat intelligence sources
        - collection_runs: Track each collection run for auditing
        - feed_reliability: Track source reliability metrics over time
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create indicators table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_hash TEXT UNIQUE NOT NULL,  -- Hash for deduplication
                    indicator_value TEXT NOT NULL,        -- The actual IOC (IP, domain, etc.)
                    indicator_type TEXT NOT NULL,         -- Type: ip, domain, url, hash, email
                    source TEXT NOT NULL,                 -- Source feed name
                    confidence_score REAL NOT NULL,       -- Calculated confidence (0.0-1.0)
                    first_seen DATE NOT NULL,            -- When first collected
                    last_seen DATE NOT NULL,             -- When last observed
                    times_seen INTEGER DEFAULT 1,        -- How many times seen across sources
                    description TEXT,                     -- Human-readable description
                    tags TEXT,                           -- JSON array of tags
                    raw_data TEXT,                       -- Original raw data from source
                    sent_to_splunk BOOLEAN DEFAULT False, -- Track if sent to Splunk
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Add sent_to_splunk column to existing database if it doesn't exist
            try:
                cursor.execute("ALTER TABLE indicators ADD COLUMN sent_to_splunk BOOLEAN DEFAULT False")
                self.logger.info("Added sent_to_splunk column to indicators table")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e).lower():
                    self.logger.debug("sent_to_splunk column already exists")
                else:
                    raise
            
            # Create sources table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT UNIQUE NOT NULL,
                    source_url TEXT,
                    reliability_weight REAL,
                    last_updated TIMESTAMP,
                    total_indicators INTEGER DEFAULT 0,
                    success_rate REAL DEFAULT 1.0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create collection runs table for auditing
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS collection_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    sources_attempted TEXT,               -- JSON array
                    sources_successful TEXT,              -- JSON array
                    total_collected INTEGER,
                    total_new INTEGER,
                    total_updated INTEGER,
                    errors TEXT,                         -- JSON array of errors
                    duration_seconds REAL
                )
            ''')
            
            # Create feed reliability tracking table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS feed_reliability (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_name TEXT NOT NULL,
                    date DATE NOT NULL,
                    indicators_collected INTEGER,
                    collection_time_seconds REAL,
                    success BOOLEAN,
                    error_message TEXT,
                    UNIQUE(source_name, date)
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicator_hash ON indicators(indicator_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicator_value ON indicators(indicator_value)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_indicator_type ON indicators(indicator_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_source ON indicators(source)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_seen ON indicators(last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_confidence ON indicators(confidence_score)')
            
            conn.commit()
            conn.close()
            
            self.logger.info("Database initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")
            raise

    def _calculate_indicator_hash(self, indicator_value: str, indicator_type: str) -> str:
        """
        Calculate a unique hash for an indicator to enable deduplication.
        
        Args:
            indicator_value (str): The IOC value (IP, domain, etc.)
            indicator_type (str): The type of indicator
            
        Returns:
            str: SHA-256 hash of the normalized indicator
            
        Note: We normalize indicators before hashing to catch variations:
        - Domains: convert to lowercase, remove www.
        - IPs: no change needed
        - URLs: normalize protocol, remove fragments
        - Hashes: convert to lowercase
        """
        # Normalize the indicator value based on type
        normalized_value = indicator_value.lower().strip()
        
        if indicator_type == 'domain':
            # Remove www. prefix for domain deduplication
            if normalized_value.startswith('www.'):
                normalized_value = normalized_value[4:]
        elif indicator_type == 'url':
            # Parse URL and normalize
            try:
                parsed = urlparse(normalized_value)
                # Reconstruct without fragment
                normalized_value = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    normalized_value += f"?{parsed.query}"
            except:
                pass  # Keep original if parsing fails
        
        # Create hash combining normalized value and type
        hash_input = f"{normalized_value}:{indicator_type}"
        return hashlib.sha256(hash_input.encode('utf-8')).hexdigest()

    def _detect_indicator_type(self, indicator: str) -> str:
        """
        Automatically detect the type of an indicator.
        
        Args:
            indicator (str): The indicator to classify
            
        Returns:
            str: The detected type ('ip', 'domain', 'url', 'hash', 'email', or 'unknown')
        """
        indicator = indicator.strip()
        
        # Check for IPv4 address
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, indicator):
            return 'ip'
        
        # Check for URL (starts with http/https/ftp)
        if indicator.lower().startswith(('http://', 'https://', 'ftp://')):
            return 'url'
        
        # Check for email address
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(email_pattern, indicator):
            return 'email'
        
        # Check for file hashes
        if re.match(r'^[a-fA-F0-9]{32}$', indicator):  # MD5
            return 'hash'
        elif re.match(r'^[a-fA-F0-9]{40}$', indicator):  # SHA1
            return 'hash'
        elif re.match(r'^[a-fA-F0-9]{64}$', indicator):  # SHA256
            return 'hash'
        
        # Check for domain (basic domain pattern)
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if re.match(domain_pattern, indicator) and '.' in indicator:
            return 'domain'
        
        return 'unknown'

    def _make_request(self, url: str, headers: Dict = None, timeout: int = 30) -> Optional[requests.Response]:
        """
        Make HTTP request with retry logic and error handling.
        
        Args:
            url (str): URL to request
            headers (Dict): Optional headers
            timeout (int): Request timeout in seconds
            
        Returns:
            Optional[requests.Response]: Response object or None if failed
        """
        max_retries = self.config['settings']['max_retries']
        
        for attempt in range(max_retries):
            try:
                response = requests.get(
                    url,
                    headers=headers or {},
                    timeout=timeout,
                    stream=True  # Enable streaming for large files
                )
                response.raise_for_status()
                return response
                
            except requests.exceptions.Timeout:
                self.logger.warning(f"Timeout on attempt {attempt + 1} for {url}")
            except requests.exceptions.HTTPError as e:
                # Handle rate limiting specifically
                if e.response.status_code == 429:
                    wait_time = (2 ** attempt) * 5  # Longer wait for rate limits
                    self.logger.warning(f"Rate limited (429) on attempt {attempt + 1} for {url}, waiting {wait_time}s")
                    if attempt < max_retries - 1:
                        time.sleep(wait_time)
                        continue
                elif e.response.status_code == 403:
                    self.logger.warning(f"Forbidden (403) on attempt {attempt + 1} for {url}: {e}")
                else:
                    self.logger.warning(f"HTTP error on attempt {attempt + 1} for {url}: {e}")
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Request error on attempt {attempt + 1} for {url}: {e}")
            
            if attempt < max_retries - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
        
        self.logger.error(f"Failed to fetch {url} after {max_retries} attempts")
        return None

    def collect_from_otx(self) -> List[Dict]:
        """
        Collect threat intelligence from AlienVault OTX (Open Threat Exchange).
        
        OTX is a community-driven threat intelligence platform where security
        researchers share indicators and analysis. It provides high-quality
        threat data with context about ongoing campaigns.
        
        Returns:
            List[Dict]: List of normalized indicator dictionaries
        """
        if not self.config['feeds']['otx']['enabled']:
            self.logger.info("OTX feed disabled, skipping")
            return []
        
        indicators = []
        api_key = self.config['feeds']['otx'].get('api_key', '')
        
        # OTX API endpoints
        base_url = "https://otx.alienvault.com/api/v1"
        
        headers = {
            'User-Agent': 'ThreatFeedCollector/1.0',
            'Accept': 'application/json'
        }
        
        # Add API key to headers if available
        if api_key:
            headers['X-OTX-API-KEY'] = api_key
            self.logger.info("Using OTX API key for authenticated access")
        else:
            self.logger.info("No OTX API key provided, using public endpoints")
        
        try:
            self.logger.info("Collecting from AlienVault OTX...")
            
            # Get recent pulses (threat intelligence reports)
            # A "pulse" in OTX is a collection of indicators related to a specific threat
            if api_key:
                # Use authenticated endpoint for subscribed pulses
                pulses_url = f"{base_url}/pulses/subscribed"
            else:
                # Use public activity feed 
                pulses_url = f"{base_url}/pulses/activity"
            
            response = self._make_request(pulses_url, headers)
            if not response:
                return indicators
            
            data = response.json()
            pulses = data.get('results', []) if 'results' in data else data
            
            # Process each pulse
            for pulse in pulses[:50]:  # Limit to recent 50 pulses
                pulse_name = pulse.get('name', 'Unknown')
                pulse_description = pulse.get('description', '')
                tags = pulse.get('tags', [])
                
                # Extract indicators from pulse
                pulse_indicators = pulse.get('indicators', [])
                
                for indicator_data in pulse_indicators:
                    try:
                        indicator_value = indicator_data.get('indicator', '').strip()
                        if not indicator_value:
                            continue
                        
                        indicator_type = indicator_data.get('type', '').lower()
                        
                        # Map OTX types to our standard types
                        type_mapping = {
                            'ipv4': 'ip',
                            'domain': 'domain', 
                            'hostname': 'domain',
                            'url': 'url',
                            'md5': 'hash',
                            'sha1': 'hash',
                            'sha256': 'hash',
                            'email': 'email'
                        }
                        
                        normalized_type = type_mapping.get(indicator_type, self._detect_indicator_type(indicator_value))
                        
                        # Create normalized indicator
                        normalized_indicator = {
                            'value': indicator_value,
                            'type': normalized_type,
                            'source': 'otx',
                            'description': f"From OTX pulse: {pulse_name}",
                            'tags': tags,
                            'confidence': 0.85,  # Base confidence for OTX
                            'raw_data': json.dumps(indicator_data),
                            'first_seen': datetime.datetime.now().isoformat(),
                            'context': {
                                'pulse_name': pulse_name,
                                'pulse_description': pulse_description
                            }
                        }
                        
                        indicators.append(normalized_indicator)
                        
                    except Exception as e:
                        self.logger.warning(f"Error processing OTX indicator: {e}")
                        continue
            
            self.logger.info(f"Collected {len(indicators)} indicators from OTX")
            self.collection_stats['source_counts']['otx'] = len(indicators)
            
        except Exception as e:
            self.logger.error(f"Error collecting from OTX: {e}")
            self.collection_stats['errors'].append(f"OTX: {str(e)}")
        
        return indicators

    def collect_from_malware_domain_list(self) -> List[Dict]:
        """
        Collect malicious domains from Malware Domain List.
        
        Malware Domain List maintains a list of domains known to host malware,
        phishing sites, and other malicious content. This is a high-quality
        source with low false positives.
        
        Returns:
            List[Dict]: List of normalized indicator dictionaries
        """
        if not self.config['feeds']['malware_domain_list']['enabled']:
            self.logger.info("Malware Domain List feed disabled, skipping")
            return []
        
        indicators = []
        
        try:
            self.logger.info("Collecting from Malware Domain List...")
            
            # Use alternative working malware domain feeds since original MDL is down
            # These are reliable alternative sources for malicious domains
            urls = [
                {
                    'url': 'https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt',
                    'name': 'URLhaus Domains',
                    'format': 'hosts'
                },
                {
                    'url': 'https://someonewhocares.org/hosts/zero/hosts',
                    'name': 'SomeoneWhoCares Hosts',
                    'format': 'hosts'
                },
                {
                    'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
                    'name': 'StevenBlack Unified Hosts',
                    'format': 'hosts'
                }
            ]
            
            for url_info in urls:
                url = url_info['url']
                feed_name = url_info['name']
                
                self.logger.info(f"Fetching from {feed_name}: {url}")
                response = self._make_request(url)
                if not response:
                    self.logger.warning(f"Failed to fetch {feed_name}")
                    continue
                
                # Parse the hosts file format
                content = response.text
                domain_count = 0
                
                for line in content.split('\n'):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#') or line.startswith('!'):
                        continue
                    
                    # Parse hosts file format: "127.0.0.1 malicious.domain.com" or "0.0.0.0 malicious.domain.com"
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in ['127.0.0.1', '0.0.0.0']:
                        domain = parts[1].strip()
                        
                        # Skip localhost and common non-malicious entries
                        if domain in ['localhost', 'localhost.localdomain', 'local', 'broadcasthost']:
                            continue
                        
                        # Skip generic entries
                        if domain.startswith('www.') and len(domain) > 100:
                            continue
                        
                        # Basic domain validation
                        if '.' not in domain or domain.startswith('.') or domain.endswith('.'):
                            continue
                        
                        normalized_indicator = {
                            'value': domain,
                            'type': 'domain',
                            'source': 'malware_domain_list',
                            'description': f'Malicious domain from {feed_name}',
                            'tags': ['malware', 'domain', 'blocklist'],
                            'confidence': 0.85,  # Slightly lower for alternative sources
                            'raw_data': line,
                            'first_seen': datetime.datetime.now().isoformat(),
                            'context': {
                                'feed_name': feed_name,
                                'feed_url': url
                            }
                        }
                        
                        indicators.append(normalized_indicator)
                        domain_count += 1
                        
                        # Limit per feed to avoid too many indicators
                        if domain_count >= 1000:
                            break
                
                self.logger.info(f"Collected {domain_count} domains from {feed_name}")
                
                # Add delay between feeds
                time.sleep(1)
            
            self.logger.info(f"Collected {len(indicators)} indicators from Malware Domain List")
            self.collection_stats['source_counts']['malware_domain_list'] = len(indicators)
            
        except Exception as e:
            self.logger.error(f"Error collecting from Malware Domain List: {e}")
            self.collection_stats['errors'].append(f"Malware Domain List: {str(e)}")
        
        return indicators

    def collect_from_phishtank(self) -> List[Dict]:
        """
        Collect phishing URLs from PhishTank.
        
        PhishTank is a collaborative database of phishing websites.
        Security researchers and organizations submit suspected phishing
        URLs which are then verified by the community.
        
        Returns:
            List[Dict]: List of normalized indicator dictionaries
        """
        if not self.config['feeds']['phishtank']['enabled']:
            self.logger.info("PhishTank feed disabled, skipping")
            return []
        
        indicators = []
        api_key = self.config['feeds']['phishtank'].get('api_key', '')
        
        max_retries = 3
        retry_delay = 5  # Start with 5 seconds
        
        for attempt in range(max_retries):
            try:
                self.logger.info(f"Collecting from PhishTank (attempt {attempt + 1}/{max_retries})...")
                
                # PhishTank provides data in JSON format
                # API key is optional but recommended for higher rate limits
                url = "http://data.phishtank.com/data/online-valid.json"
                if api_key:
                    url += f"?key={api_key}"
                    self.logger.info("Using PhishTank API key for higher rate limits")
                else:
                    self.logger.info("No PhishTank API key - using public access (lower rate limits)")
                
                headers = {
                    'User-Agent': 'ThreatFeedCollector/1.0',
                    'Accept': 'application/json'
                }
                
                response = self._make_request(url, headers, timeout=60)  # Longer timeout for PhishTank
                if not response:
                    if attempt < max_retries - 1:
                        self.logger.warning(f"PhishTank request failed, retrying in {retry_delay} seconds...")
                        time.sleep(retry_delay)
                        retry_delay *= 2  # Exponential backoff
                        continue
                    else:
                        self.logger.error("PhishTank: All retry attempts failed")
                        return indicators
                
                # Check for rate limiting
                if response.status_code == 429:
                    if attempt < max_retries - 1:
                        wait_time = retry_delay * (attempt + 1)
                        self.logger.warning(f"PhishTank rate limited (429), waiting {wait_time} seconds...")
                        time.sleep(wait_time)
                        continue
                    else:
                        self.logger.error("PhishTank: Rate limit exceeded, skipping")
                        return indicators
                
                break  # Success - exit retry loop
                
            except Exception as e:
                if attempt < max_retries - 1:
                    self.logger.warning(f"PhishTank error on attempt {attempt + 1}: {e}")
                    time.sleep(retry_delay)
                    retry_delay *= 2
                    continue
                else:
                    self.logger.error(f"PhishTank: Final attempt failed: {e}")
                    return indicators
        
        try:
            
            # PhishTank data can be large, so we stream and parse incrementally
            data = response.json()
            
            # Limit to recent entries to avoid overwhelming the database
            recent_entries = data[:1000] if len(data) > 1000 else data
            
            for entry in recent_entries:
                try:
                    phish_url = entry.get('url', '').strip()
                    if not phish_url:
                        continue
                    
                    # Extract additional context
                    phish_id = entry.get('phish_id', '')
                    submission_time = entry.get('submission_time', '')
                    target = entry.get('target', 'Unknown')
                    verified = entry.get('verified', 'no')
                    
                    # Only include verified phishing URLs
                    if verified != 'yes':
                        continue
                    
                    normalized_indicator = {
                        'value': phish_url,
                        'type': 'url',
                        'source': 'phishtank',
                        'description': f'Verified phishing URL targeting {target}',
                        'tags': ['phishing', 'url', target.lower()],
                        'confidence': 0.80,  # Good confidence for verified entries
                        'raw_data': json.dumps(entry),
                        'first_seen': submission_time or datetime.datetime.now().isoformat(),
                        'context': {
                            'phish_id': phish_id,
                            'target': target,
                            'verified': verified
                        }
                    }
                    
                    indicators.append(normalized_indicator)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing PhishTank entry: {e}")
                    continue
            
            self.logger.info(f"Collected {len(indicators)} indicators from PhishTank")
            self.collection_stats['source_counts']['phishtank'] = len(indicators)
            
        except Exception as e:
            self.logger.error(f"Error collecting from PhishTank: {e}")
            self.collection_stats['errors'].append(f"PhishTank: {str(e)}")
        
        return indicators

    def collect_from_emerging_threats(self) -> List[Dict]:
        """
        Collect IOCs from Emerging Threats feeds.
        
        Emerging Threats (now part of Proofpoint) provides high-quality
        threat intelligence including IP reputation lists, domain lists,
        and Suricata/Snort rules with embedded IOCs.
        
        Returns:
            List[Dict]: List of normalized indicator dictionaries
        """
        if not self.config['feeds']['emerging_threats']['enabled']:
            self.logger.info("Emerging Threats feed disabled, skipping")
            return []
        
        indicators = []
        
        try:
            self.logger.info("Collecting from Emerging Threats...")
            
            # Emerging Threats provides several free feeds
            feeds = [
                {
                    'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
                    'type': 'ip',
                    'description': 'Emerging Threats blocked IPs'
                },
                {
                    'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt', 
                    'type': 'ip',
                    'description': 'Compromised IP addresses'
                }
            ]
            
            for feed in feeds:
                response = self._make_request(feed['url'])
                if not response:
                    continue
                
                content = response.text
                for line in content.split('\n'):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Extract IP addresses (handle various formats)
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if ip_match:
                        ip_address = ip_match.group()
                        
                        normalized_indicator = {
                            'value': ip_address,
                            'type': 'ip',
                            'source': 'emerging_threats',
                            'description': feed['description'],
                            'tags': ['malicious', 'ip', 'emerging_threats'],
                            'confidence': 0.95,  # Very high confidence
                            'raw_data': line,
                            'first_seen': datetime.datetime.now().isoformat(),
                            'context': {
                                'feed_url': feed['url'],
                                'feed_type': feed['type']
                            }
                        }
                        
                        indicators.append(normalized_indicator)
            
            self.logger.info(f"Collected {len(indicators)} indicators from Emerging Threats")
            self.collection_stats['source_counts']['emerging_threats'] = len(indicators)
            
        except Exception as e:
            self.logger.error(f"Error collecting from Emerging Threats: {e}")
            self.collection_stats['errors'].append(f"Emerging Threats: {str(e)}")
        
        return indicators

    def collect_from_urlhaus(self) -> List[Dict]:
        """
        Collect malware URLs from URLhaus (abuse.ch).
        
        URLhaus is a project from abuse.ch that collects and shares
        malware URLs. It's an excellent source for URLs distributing
        malware payloads.
        
        Returns:
            List[Dict]: List of normalized indicator dictionaries
        """
        if not self.config['feeds']['urlhaus']['enabled']:
            self.logger.info("URLhaus feed disabled, skipping")
            return []
        
        indicators = []
        
        try:
            self.logger.info("Collecting from URLhaus...")
            
            # URLhaus provides CSV feeds
            csv_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
            
            response = self._make_request(csv_url)
            if not response:
                return indicators
            
            # Parse CSV content
            content = response.text
            csv_reader = csv.DictReader(io.StringIO(content))
            
            for row in csv_reader:
                try:
                    # Skip comment lines
                    if row.get('id', '').startswith('#'):
                        continue
                    
                    url = row.get('url', '').strip()
                    if not url:
                        continue
                    
                    # Extract metadata
                    url_status = row.get('url_status', '')
                    threat = row.get('threat', '')
                    tags = row.get('tags', '').split(',') if row.get('tags') else []
                    dateadded = row.get('dateadded', '')
                    
                    # Only include online/active URLs
                    if url_status not in ['online']:
                        continue
                    
                    normalized_indicator = {
                        'value': url,
                        'type': 'url',
                        'source': 'urlhaus',
                        'description': f'Malware URL - {threat}',
                        'tags': ['malware', 'url'] + [tag.strip() for tag in tags if tag.strip()],
                        'confidence': 0.85,  # High confidence
                        'raw_data': json.dumps(dict(row)),
                        'first_seen': dateadded or datetime.datetime.now().isoformat(),
                        'context': {
                            'threat_type': threat,
                            'url_status': url_status,
                            'tags': tags
                        }
                    }
                    
                    indicators.append(normalized_indicator)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing URLhaus entry: {e}")
                    continue
            
            self.logger.info(f"Collected {len(indicators)} indicators from URLhaus")
            self.collection_stats['source_counts']['urlhaus'] = len(indicators)
            
        except Exception as e:
            self.logger.error(f"Error collecting from URLhaus: {e}")
            self.collection_stats['errors'].append(f"URLhaus: {str(e)}")
        
        return indicators

    def deduplicate_indicators(self, indicators: List[Dict]) -> List[Dict]:
        """
        Remove duplicate indicators using hash comparison.
        
        This function identifies duplicate indicators across different sources
        and merges their metadata while keeping the highest confidence score.
        
        Args:
            indicators (List[Dict]): List of indicator dictionaries
            
        Returns:
            List[Dict]: Deduplicated list of indicators
        """
        self.logger.info(f"Deduplicating {len(indicators)} indicators...")
        
        # Dictionary to track unique indicators by hash
        unique_indicators = {}
        duplicate_count = 0
        
        for indicator in indicators:
            try:
                # Calculate hash for deduplication
                indicator_hash = self._calculate_indicator_hash(
                    indicator['value'], 
                    indicator['type']
                )
                
                if indicator_hash in unique_indicators:
                    # Merge duplicate indicator data
                    existing = unique_indicators[indicator_hash]
                    duplicate_count += 1
                    
                    # Keep highest confidence score
                    if indicator['confidence'] > existing['confidence']:
                        existing['confidence'] = indicator['confidence']
                    
                    # Merge sources
                    if 'sources' not in existing:
                        existing['sources'] = [existing['source']]
                    if indicator['source'] not in existing['sources']:
                        existing['sources'].append(indicator['source'])
                    
                    # Merge tags
                    existing_tags = set(existing.get('tags', []))
                    new_tags = set(indicator.get('tags', []))
                    existing['tags'] = list(existing_tags.union(new_tags))
                    
                    # Update times_seen counter
                    existing['times_seen'] = existing.get('times_seen', 1) + 1
                    
                else:
                    # Add hash to indicator for database storage
                    indicator['indicator_hash'] = indicator_hash
                    indicator['times_seen'] = 1
                    unique_indicators[indicator_hash] = indicator
                    
            except Exception as e:
                self.logger.warning(f"Error processing indicator for deduplication: {e}")
                continue
        
        deduplicated = list(unique_indicators.values())
        
        self.logger.info(f"Deduplication complete: {len(deduplicated)} unique indicators "
                        f"({duplicate_count} duplicates removed)")
        
        self.collection_stats['total_duplicates'] = duplicate_count
        
        return deduplicated

    def calculate_confidence_scores(self, indicators: List[Dict]) -> List[Dict]:
        """
        Calculate enhanced confidence scores based on multiple factors.
        
        Confidence scoring considers:
        1. Source reliability weight
        2. Number of sources reporting the same indicator
        3. Recency of the indicator
        4. Type of indicator (some types are more reliable than others)
        
        Args:
            indicators (List[Dict]): List of indicator dictionaries
            
        Returns:
            List[Dict]: Indicators with updated confidence scores
        """
        self.logger.info("Calculating enhanced confidence scores...")
        
        for indicator in indicators:
            try:
                base_confidence = indicator.get('confidence', 0.5)
                source = indicator.get('source', '')
                times_seen = indicator.get('times_seen', 1)
                indicator_type = indicator.get('type', 'unknown')
                
                # Start with source reliability weight
                source_weight = self.source_weights.get(source, 0.5)
                adjusted_confidence = base_confidence * source_weight
                
                # Boost confidence for indicators seen in multiple sources
                if times_seen > 1:
                    multi_source_boost = min(0.2, (times_seen - 1) * 0.05)
                    adjusted_confidence += multi_source_boost
                
                # Type-based adjustments
                type_weights = {
                    'ip': 1.0,        # IPs are generally reliable
                    'domain': 0.95,   # Domains are very reliable
                    'url': 0.90,      # URLs can change but are good indicators
                    'hash': 1.0,      # File hashes are excellent indicators
                    'email': 0.85,    # Email addresses can be spoofed
                    'unknown': 0.7    # Lower confidence for unknown types
                }
                
                type_weight = type_weights.get(indicator_type, 0.7)
                adjusted_confidence *= type_weight
                
                # Recency boost (newer indicators get slight boost)
                try:
                    first_seen = datetime.datetime.fromisoformat(
                        indicator.get('first_seen', '').replace('Z', '+00:00')
                    )
                    days_old = (datetime.datetime.now() - first_seen.replace(tzinfo=None)).days
                    
                    if days_old <= 1:
                        adjusted_confidence += 0.05  # Recent indicators boost
                    elif days_old > 30:
                        adjusted_confidence -= 0.05  # Older indicators slight penalty
                        
                except (ValueError, TypeError):
                    pass  # Skip recency adjustment if date parsing fails
                
                # Ensure confidence stays within bounds
                indicator['confidence'] = max(0.0, min(1.0, adjusted_confidence))
                
            except Exception as e:
                self.logger.warning(f"Error calculating confidence for indicator: {e}")
                indicator['confidence'] = 0.5  # Default confidence
        
        return indicators

    def store_indicators(self, indicators: List[Dict]) -> Tuple[int, int]:
        """
        Store indicators in the SQLite database.
        
        Args:
            indicators (List[Dict]): List of normalized indicators
            
        Returns:
            Tuple[int, int]: (new_indicators_count, updated_indicators_count)
        """
        if not indicators:
            return 0, 0
        
        self.logger.info(f"Storing {len(indicators)} indicators in database...")
        
        new_count = 0
        updated_count = 0
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for indicator in indicators:
                try:
                    # Check if indicator already exists
                    cursor.execute(
                        "SELECT id, times_seen, confidence_score FROM indicators WHERE indicator_hash = ?",
                        (indicator['indicator_hash'],)
                    )
                    existing = cursor.fetchone()
                    
                    current_time = datetime.datetime.now().isoformat()
                    
                    if existing:
                        # Update existing indicator
                        existing_id, existing_times_seen, existing_confidence = existing
                        
                        # Update with new information
                        new_times_seen = max(existing_times_seen, indicator.get('times_seen', 1))
                        new_confidence = max(existing_confidence, indicator.get('confidence', 0))
                        
                        cursor.execute('''
                            UPDATE indicators SET
                                last_seen = ?,
                                times_seen = ?,
                                confidence_score = ?,
                                tags = ?,
                                updated_at = ?
                            WHERE id = ?
                        ''', (
                            current_time,
                            new_times_seen,
                            new_confidence,
                            json.dumps(indicator.get('tags', [])),
                            current_time,
                            existing_id
                        ))
                        
                        updated_count += 1
                        
                    else:
                        # Insert new indicator
                        cursor.execute('''
                            INSERT INTO indicators (
                                indicator_hash, indicator_value, indicator_type, source,
                                confidence_score, first_seen, last_seen, times_seen,
                                description, tags, raw_data, created_at, updated_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            indicator['indicator_hash'],
                            indicator['value'],
                            indicator['type'],
                            indicator['source'],
                            indicator.get('confidence', 0.5),
                            indicator.get('first_seen', current_time),
                            current_time,
                            indicator.get('times_seen', 1),
                            indicator.get('description', ''),
                            json.dumps(indicator.get('tags', [])),
                            indicator.get('raw_data', ''),
                            current_time,
                            current_time
                        ))
                        
                        new_count += 1
                        
                except Exception as e:
                    self.logger.warning(f"Error storing individual indicator: {e}")
                    continue
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Storage complete: {new_count} new, {updated_count} updated")
            
        except Exception as e:
            self.logger.error(f"Error storing indicators: {e}")
            if 'conn' in locals():
                conn.close()
        
        return new_count, updated_count

    def cleanup_old_indicators(self):
        """
        Remove old indicators based on retention policy.
        
        This helps keep the database size manageable while maintaining
        recent threat intelligence data.
        """
        retention_days = self.config['database']['retention_days']
        cutoff_date = (datetime.datetime.now() - datetime.timedelta(days=retention_days)).isoformat()
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Count indicators to be removed
            cursor.execute(
                "SELECT COUNT(*) FROM indicators WHERE last_seen < ?",
                (cutoff_date,)
            )
            count_to_remove = cursor.fetchone()[0]
            
            if count_to_remove > 0:
                # Remove old indicators
                cursor.execute(
                    "DELETE FROM indicators WHERE last_seen < ?",
                    (cutoff_date,)
                )
                
                conn.commit()
                self.logger.info(f"Cleaned up {count_to_remove} old indicators (older than {retention_days} days)")
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")

    def generate_collection_report(self, new_count: int, updated_count: int, 
                                 start_time: datetime.datetime) -> Dict:
        """
        Generate a comprehensive collection report.
        
        Args:
            new_count (int): Number of new indicators collected
            updated_count (int): Number of updated indicators
            start_time (datetime.datetime): Collection start time
            
        Returns:
            Dict: Collection report
        """
        end_time = datetime.datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        report = {
            'collection_summary': {
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'total_collected': self.collection_stats['total_collected'],
                'total_duplicates': self.collection_stats['total_duplicates'],
                'new_indicators': new_count,
                'updated_indicators': updated_count,
                'sources_attempted': list(self.config['feeds'].keys()),
                'sources_successful': list(self.collection_stats['source_counts'].keys()),
                'errors': self.collection_stats['errors']
            },
            'source_breakdown': self.collection_stats['source_counts'],
            'database_stats': self._get_database_stats(),
            'feed_reliability': self._calculate_feed_reliability()
        }
        
        return report

    def _get_database_stats(self) -> Dict:
        """Get current database statistics."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total indicators
            cursor.execute("SELECT COUNT(*) FROM indicators")
            total_indicators = cursor.fetchone()[0]
            
            # Indicators by type
            cursor.execute("""
                SELECT indicator_type, COUNT(*) 
                FROM indicators 
                GROUP BY indicator_type
                ORDER BY COUNT(*) DESC
            """)
            by_type = dict(cursor.fetchall())
            
            # Indicators by source
            cursor.execute("""
                SELECT source, COUNT(*) 
                FROM indicators 
                GROUP BY source
                ORDER BY COUNT(*) DESC
            """)
            by_source = dict(cursor.fetchall())
            
            # Recent indicators (last 24 hours)
            yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
            cursor.execute(
                "SELECT COUNT(*) FROM indicators WHERE last_seen >= ?",
                (yesterday,)
            )
            recent_count = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_indicators': total_indicators,
                'by_type': by_type,
                'by_source': by_source,
                'recent_24h': recent_count
            }
            
        except Exception as e:
            self.logger.error(f"Error getting database stats: {e}")
            return {}

    def _calculate_feed_reliability(self) -> Dict:
        """Calculate reliability metrics for each feed."""
        reliability = {}
        
        for source in self.collection_stats['source_counts']:
            count = self.collection_stats['source_counts'][source]
            weight = self.source_weights.get(source, 0.5)
            
            reliability[source] = {
                'indicators_collected': count,
                'reliability_weight': weight,
                'success': source not in [error.split(':')[0] for error in self.collection_stats['errors']]
            }
        
        return reliability

    def test_splunk_connectivity(self) -> bool:
        """
        Test connectivity to Splunk HEC before attempting data transmission.
        
        Sends a small test event to verify the HEC endpoint is reachable,
        authentication is working, and the service is responding correctly.
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        if not self.config['output'].get('splunk_enabled', False):
            return True
        
        try:
            splunk_config = self.config.get('splunk', {})
            hec_url = splunk_config.get('hec_url', '')
            hec_token = splunk_config.get('hec_token', '')
            verify_ssl = splunk_config.get('verify_ssl', True)
            
            if not hec_url or not hec_token:
                self.logger.warning("Splunk configuration incomplete - cannot test connectivity")
                return False
            
            # Handle SSL certificate verification
            if not verify_ssl:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                warnings.filterwarnings('ignore', message='Unverified HTTPS request')
                self.logger.debug("SSL certificate verification disabled for Splunk HEC connectivity test")
            
            headers = {
                'Authorization': f'Splunk {hec_token}',
                'Content-Type': 'application/json'
            }
            
            # Create a minimal test event
            test_event = {
                'time': int(datetime.datetime.now().timestamp()),
                'source': splunk_config.get('source', 'threat_feed_collector'),
                'sourcetype': 'connectivity_test',
                'index': splunk_config.get('index', 'main'),
                'event': {
                    'test_type': 'hec_connectivity_test',
                    'message': 'Threat Feed Collector connectivity test',
                    'timestamp': datetime.datetime.now().isoformat(),
                    'status': 'testing'
                }
            }
            
            self.logger.info(f"Testing Splunk HEC connectivity to: {hec_url}")
            
            response = requests.post(
                f"{hec_url}/services/collector",
                headers=headers,
                json=test_event,
                timeout=self.config['settings'].get('request_timeout', 30),
                verify=verify_ssl
            )
            
            response.raise_for_status()
            
            # Check Splunk HEC response
            try:
                result = response.json()
                if result.get('text') == 'Success':
                    self.logger.info("✓ Splunk HEC connectivity test successful")
                    return True
                else:
                    self.logger.error(f"✗ Splunk HEC connectivity test failed - Response: {result}")
                    return False
            except json.JSONDecodeError:
                # Some Splunk versions return plain text success
                if response.status_code == 200:
                    self.logger.info("✓ Splunk HEC connectivity test successful")
                    return True
                else:
                    self.logger.error(f"✗ Splunk HEC connectivity test failed - Status: {response.status_code}")
                    return False
            
        except requests.exceptions.SSLError as e:
            self.logger.error(f"✗ SSL error during Splunk connectivity test: {e}")
            self.logger.error("  Try setting 'verify_ssl': false in the Splunk configuration")
            return False
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"✗ Connection error during Splunk connectivity test: {e}")
            self.logger.error("  Check if Splunk HEC URL is correct and reachable")
            return False
        except requests.exceptions.Timeout as e:
            self.logger.error(f"✗ Timeout during Splunk connectivity test: {e}")
            self.logger.error("  Check network connectivity and Splunk server responsiveness")
            return False
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"✗ HTTP error during Splunk connectivity test: {e}")
            self.logger.error(f"  Response status: {e.response.status_code}")
            if e.response.status_code == 401:
                self.logger.error("  Check if HEC token is valid and has proper permissions")
            elif e.response.status_code == 403:
                self.logger.error("  Check if HEC token has access to the specified index")
            try:
                self.logger.error(f"  Response body: {e.response.text}")
            except:
                pass
            return False
        except Exception as e:
            self.logger.error(f"✗ Unexpected error during Splunk connectivity test: {e}")
            return False

    def send_to_splunk(self, report: Dict) -> bool:
        """
        Send collection report to Splunk via HTTP Event Collector.
        
        Handles SSL certificate verification based on configuration settings.
        When verify_ssl is False, disables SSL warnings and certificate verification
        to work with self-signed certificates.
        
        Args:
            report (Dict): Collection report to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.config['output'].get('splunk_enabled', False):
            return True
        
        # Test connectivity before attempting to send data
        if not self.test_splunk_connectivity():
            self.logger.error("Splunk connectivity test failed - skipping report transmission")
            return False
        
        try:
            splunk_config = self.config.get('splunk', {})
            hec_url = splunk_config.get('hec_url', '')
            hec_token = splunk_config.get('hec_token', '')
            verify_ssl = splunk_config.get('verify_ssl', True)
            
            if not hec_url or not hec_token:
                self.logger.warning("Splunk configuration incomplete, skipping")
                return False
            
            # Handle SSL certificate verification
            if not verify_ssl:
                # Disable SSL warnings for self-signed certificates
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                # Also disable general SSL warnings
                warnings.filterwarnings('ignore', message='Unverified HTTPS request')
                self.logger.debug("SSL certificate verification disabled for Splunk HEC")
            
            headers = {
                'Authorization': f'Splunk {hec_token}',
                'Content-Type': 'application/json'
            }
            
            splunk_event = {
                'time': int(datetime.datetime.now().timestamp()),
                'source': splunk_config.get('source', 'threat_feed_collector'),
                'sourcetype': splunk_config.get('sourcetype', 'threat_intelligence_collection'),
                'index': splunk_config.get('index', 'main'),
                'event': report
            }
            
            self.logger.info(f"Sending collection report to Splunk HEC: {hec_url}")
            
            response = requests.post(
                f"{hec_url}/services/collector",
                headers=headers,
                json=splunk_event,
                timeout=self.config['settings'].get('request_timeout', 30),
                verify=verify_ssl  # This is the key fix - respect the verify_ssl setting
            )
            
            response.raise_for_status()
            
            # Check Splunk HEC response
            try:
                result = response.json()
                if result.get('text') == 'Success':
                    self.logger.info("Successfully sent collection report to Splunk")
                    return True
                else:
                    self.logger.warning(f"Splunk HEC returned non-success response: {result}")
                    return False
            except json.JSONDecodeError:
                # Some Splunk versions return plain text success
                if response.status_code == 200:
                    self.logger.info("Successfully sent collection report to Splunk")
                    return True
                else:
                    self.logger.warning(f"Unexpected Splunk response format. Status: {response.status_code}")
                    return False
            
        except requests.exceptions.SSLError as e:
            self.logger.error(f"SSL error sending to Splunk: {e}")
            self.logger.error("Try setting 'verify_ssl': false in the Splunk configuration")
            return False
        except requests.exceptions.ConnectionError as e:
            self.logger.error(f"Connection error sending to Splunk: {e}")
            return False
        except requests.exceptions.Timeout as e:
            self.logger.error(f"Timeout sending to Splunk: {e}")
            return False
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error sending to Splunk: {e}")
            self.logger.error(f"Response status: {e.response.status_code}")
            try:
                self.logger.error(f"Response body: {e.response.text}")
            except:
                pass
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending to Splunk: {e}")
            return False

    def send_indicators_to_splunk(self) -> Tuple[int, int]:
        """
        Send unsent indicators to Splunk as separate events.
        
        This method queries the database for indicators that haven't been sent to Splunk yet,
        sends them as individual events, and marks them as sent after successful transmission.
        This prevents duplicate transmission of indicators.
        
        Returns:
            Tuple[int, int]: (successful_sends, failed_sends)
        """
        if not self.config['output'].get('splunk_enabled', False):
            return 0, 0
        
        # Check if individual indicator sending is enabled
        if not self.config.get('splunk', {}).get('send_individual_indicators', True):
            self.logger.info("Individual indicator sending to Splunk is disabled")
            return 0, 0
        
        # Test connectivity before attempting to send indicators
        if not self.test_splunk_connectivity():
            self.logger.error("Splunk connectivity test failed - skipping indicator transmission")
            return 0, 0
        
        # Query database for unsent indicators
        unsent_indicators = self._get_unsent_indicators()
        
        if not unsent_indicators:
            self.logger.info("No new indicators to send to Splunk")
            return 0, 0
        
        self.logger.info(f"Sending {len(unsent_indicators)} unsent indicators to Splunk...")
        
        successful_sends = 0
        failed_sends = 0
        batch_size = self.config.get('splunk', {}).get('batch_size', 100)
        sent_indicator_ids = []
        
        # Process indicators in batches to avoid overwhelming Splunk
        for i in range(0, len(unsent_indicators), batch_size):
            batch = unsent_indicators[i:i + batch_size]
            batch_num = (i // batch_size) + 1
            total_batches = (len(unsent_indicators) + batch_size - 1) // batch_size
            
            self.logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} indicators)")
            
            for indicator in batch:
                try:
                    # Send individual indicator
                    if self._send_single_indicator_to_splunk(indicator):
                        successful_sends += 1
                        sent_indicator_ids.append(indicator['id'])
                    else:
                        failed_sends += 1
                        
                    # Small delay between individual sends to avoid rate limiting
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.warning(f"Error sending indicator {indicator.get('indicator_value', 'unknown')}: {e}")
                    failed_sends += 1
            
            # Mark successfully sent indicators in database
            if sent_indicator_ids:
                self._mark_indicators_as_sent(sent_indicator_ids)
                sent_indicator_ids = []  # Reset for next batch
            
            # Delay between batches
            if i + batch_size < len(unsent_indicators):
                time.sleep(1)
        
        # Mark any remaining successfully sent indicators
        if sent_indicator_ids:
            self._mark_indicators_as_sent(sent_indicator_ids)
        
        self.logger.info(f"Indicator transmission complete: {successful_sends} successful, {failed_sends} failed")
        return successful_sends, failed_sends

    def _get_unsent_indicators(self) -> List[Dict]:
        """
        Query database for indicators that haven't been sent to Splunk yet.
        
        Returns:
            List[Dict]: List of unsent indicator records from database
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Query for indicators where sent_to_splunk is False or NULL
            cursor.execute("""
                SELECT id, indicator_hash, indicator_value, indicator_type, source,
                       confidence_score, first_seen, last_seen, times_seen,
                       description, tags, raw_data, created_at, updated_at
                FROM indicators 
                WHERE sent_to_splunk IS NULL OR sent_to_splunk = False
                ORDER BY created_at DESC
            """)
            
            rows = cursor.fetchall()
            conn.close()
            
            # Convert rows to dictionaries
            indicators = []
            for row in rows:
                indicator = {
                    'id': row[0],
                    'indicator_hash': row[1],
                    'indicator_value': row[2],
                    'indicator_type': row[3],
                    'source': row[4],
                    'confidence_score': row[5],
                    'first_seen': row[6],
                    'last_seen': row[7],
                    'times_seen': row[8],
                    'description': row[9],
                    'tags': json.loads(row[10]) if row[10] else [],
                    'raw_data': row[11],
                    'created_at': row[12],
                    'updated_at': row[13]
                }
                indicators.append(indicator)
            
            self.logger.info(f"Found {len(indicators)} unsent indicators in database")
            return indicators
            
        except Exception as e:
            self.logger.error(f"Error querying unsent indicators: {e}")
            return []
    
    def _mark_indicators_as_sent(self, indicator_ids: List[int]) -> bool:
        """
        Mark indicators as sent to Splunk in the database.
        
        Args:
            indicator_ids (List[int]): List of indicator IDs to mark as sent
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not indicator_ids:
            return True
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Update sent_to_splunk flag for the given indicator IDs
            placeholders = ','.join('?' * len(indicator_ids))
            cursor.execute(f"""
                UPDATE indicators 
                SET sent_to_splunk = True, updated_at = ? 
                WHERE id IN ({placeholders})
            """, [datetime.datetime.now().isoformat()] + indicator_ids)
            
            affected_rows = cursor.rowcount
            conn.commit()
            conn.close()
            
            self.logger.debug(f"Marked {affected_rows} indicators as sent to Splunk")
            return True
            
        except Exception as e:
            self.logger.error(f"Error marking indicators as sent: {e}")
            return False

    def _send_single_indicator_to_splunk(self, indicator: Dict) -> bool:
        """
        Send a single threat indicator to Splunk as an individual event.
        
        Args:
            indicator (Dict): Normalized indicator dictionary
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            splunk_config = self.config.get('splunk', {})
            hec_url = splunk_config.get('hec_url', '')
            hec_token = splunk_config.get('hec_token', '')
            verify_ssl = splunk_config.get('verify_ssl', True)
            
            if not hec_url or not hec_token:
                return False
            
            # Handle SSL certificate verification
            if not verify_ssl:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                warnings.filterwarnings('ignore', message='Unverified HTTPS request')
            
            headers = {
                'Authorization': f'Splunk {hec_token}',
                'Content-Type': 'application/json'
            }
            
            # Create detailed event for the indicator (handle both database and collection formats)
            indicator_event = {
                'indicator': indicator.get('indicator_value', indicator.get('value', '')),
                'indicator_type': indicator.get('indicator_type', indicator.get('type', '')),
                'source_feed': indicator.get('source', ''),
                'confidence_score': indicator.get('confidence_score', indicator.get('confidence', 0)),
                'first_seen': indicator.get('first_seen', ''),
                'last_seen': indicator.get('last_seen', ''),
                'description': indicator.get('description', ''),
                'tags': indicator.get('tags', []),
                'times_seen': indicator.get('times_seen', 1),
                'indicator_hash': indicator.get('indicator_hash', ''),
                'collection_timestamp': datetime.datetime.now().isoformat(),
                'context': indicator.get('context', {}),
                'event_type': 'threat_indicator'
            }
            
            # Add source-specific metadata
            if 'raw_data' in indicator:
                try:
                    raw_data = json.loads(indicator['raw_data']) if isinstance(indicator['raw_data'], str) else indicator['raw_data']
                    if isinstance(raw_data, dict):
                        indicator_event['raw_metadata'] = raw_data
                except:
                    pass  # Skip if raw_data can't be parsed
            
            # Create Splunk HEC event
            splunk_event = {
                'time': int(datetime.datetime.now().timestamp()),
                'source': splunk_config.get('source', 'threat_feed_collector'),
                'sourcetype': 'threat_indicator',  # Different sourcetype for individual indicators
                'index': splunk_config.get('index', 'main'),
                'event': indicator_event
            }
            
            response = requests.post(
                f"{hec_url}/services/collector",
                headers=headers,
                json=splunk_event,
                timeout=self.config['settings'].get('request_timeout', 30),
                verify=verify_ssl
            )
            
            response.raise_for_status()
            
            # Check response
            if response.status_code == 200:
                return True
            else:
                self.logger.debug(f"Unexpected response code for indicator {indicator.get('indicator_value', indicator.get('value', ''))}: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request error sending indicator {indicator.get('indicator_value', indicator.get('value', ''))}: {e}")
            return False
        except Exception as e:
            self.logger.debug(f"Error sending indicator {indicator.get('indicator_value', indicator.get('value', ''))}: {e}")
            return False

    def upload_to_s3(self, report: Dict) -> bool:
        """
        Upload daily summary and data to AWS S3 bucket.
        
        This function uploads threat intelligence data to S3 for:
        1. Long-term storage and backup
        2. Integration with other AWS services
        3. Sharing with partner organizations
        4. Historical analysis and trending
        
        Args:
            report (Dict): Collection report to upload
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.config['output'].get('s3_enabled', False):
            return True
        
        try:
            # Note: This is a basic implementation using requests
            # In production, consider using boto3 library for full AWS SDK support
            aws_config = self.config.get('aws', {})
            
            if not aws_config.get('enabled', False):
                return True
            
            bucket = aws_config.get('s3_bucket', '')
            access_key = aws_config.get('access_key_id', '')
            secret_key = aws_config.get('secret_access_key', '')
            region = aws_config.get('region', 'us-east-1')
            
            if not all([bucket, access_key, secret_key]):
                self.logger.warning("AWS S3 configuration incomplete, skipping")
                return False
            
            # Generate filename with timestamp
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"threat_intel_summary_{timestamp}.json"
            
            # Prepare data for upload
            upload_data = {
                'metadata': {
                    'upload_timestamp': datetime.datetime.now().isoformat(),
                    'data_type': 'threat_intelligence_summary',
                    'version': '1.0'
                },
                'report': report
            }
            
            # Convert to JSON
            json_data = json.dumps(upload_data, indent=2)
            
            # For basic S3 upload without boto3, we would need to implement
            # AWS signature v4 authentication, which is complex
            # This is a placeholder that logs the action
            self.logger.info(f"Would upload {filename} to S3 bucket {bucket} ({len(json_data)} bytes)")
            
            # In a real implementation with boto3:
            # import boto3
            # s3_client = boto3.client('s3', 
            #                         aws_access_key_id=access_key,
            #                         aws_secret_access_key=secret_key,
            #                         region_name=region)
            # s3_client.put_object(Bucket=bucket, Key=filename, Body=json_data)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error uploading to S3: {e}")
            return False

    def run_collection(self) -> Dict:
        """
        Main method to run the complete threat intelligence collection process.
        
        Returns:
            Dict: Collection report
        """
        start_time = datetime.datetime.now()
        self.logger.info("Starting threat intelligence collection...")
        
        # Reset statistics
        self.collection_stats = {
            'total_collected': 0,
            'total_duplicates': 0,
            'total_stored': 0,
            'source_counts': {},
            'errors': []
        }
        
        all_indicators = []
        
        # Collect from each source
        collectors = [
            self.collect_from_otx,
            self.collect_from_malware_domain_list,
            self.collect_from_phishtank,
            self.collect_from_emerging_threats,
            self.collect_from_urlhaus
        ]
        
        for collector in collectors:
            try:
                indicators = collector()
                all_indicators.extend(indicators)
                
                # Add delay between sources to be respectful
                time.sleep(self.config['settings']['delay_between_sources'])
                
            except Exception as e:
                self.logger.error(f"Error in collector {collector.__name__}: {e}")
                self.collection_stats['errors'].append(f"{collector.__name__}: {str(e)}")
        
        self.collection_stats['total_collected'] = len(all_indicators)
        
        # Deduplicate indicators
        if all_indicators:
            unique_indicators = self.deduplicate_indicators(all_indicators)
            
            # Calculate enhanced confidence scores
            enhanced_indicators = self.calculate_confidence_scores(unique_indicators)
            
            # Store in database
            new_count, updated_count = self.store_indicators(enhanced_indicators)
            
            # Send individual indicators to Splunk (only unsent ones)
            splunk_sent, splunk_failed = self.send_indicators_to_splunk()
            
            # Cleanup old indicators
            self.cleanup_old_indicators()
            
        else:
            new_count = updated_count = 0
            splunk_sent = splunk_failed = 0
        
        # Generate report (include Splunk transmission stats)
        report = self.generate_collection_report(new_count, updated_count, start_time)
        report['splunk_transmission'] = {
            'indicators_sent': splunk_sent,
            'indicators_failed': splunk_failed,
            'total_indicators': splunk_sent + splunk_failed,
            'success_rate': round((splunk_sent / (splunk_sent + splunk_failed)) * 100, 2) if (splunk_sent + splunk_failed) > 0 else 0
        }
        
        # Send collection summary report to Splunk
        self.send_to_splunk(report)
        
        # Upload to S3
        self.upload_to_s3(report)
        
        self.logger.info("Threat intelligence collection completed")
        return report

def main():
    """Main execution function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Threat Intelligence Feed Collector'
    )
    parser.add_argument(
        '-c', '--config',
        help='Configuration file path',
        default='feed_config.json'
    )
    parser.add_argument(
        '-d', '--database',
        help='Database file path',
        default='threat_intel.db'
    )
    parser.add_argument(
        '--cleanup-only',
        help='Only run database cleanup',
        action='store_true'
    )
    
    args = parser.parse_args()
    
    try:
        collector = ThreatFeedCollector(args.config, args.database)
        
        if args.cleanup_only:
            collector.cleanup_old_indicators()
            print("Database cleanup completed")
        else:
            report = collector.run_collection()
            print("\n=== COLLECTION REPORT ===")
            print(json.dumps(report, indent=2))
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())