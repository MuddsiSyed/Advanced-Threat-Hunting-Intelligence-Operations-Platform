#!/usr/bin/env python3
"""
Cybersecurity Threat Intelligence Analyzer

This script performs comprehensive threat intelligence analysis by:
1. Reading IOCs (Indicators of Compromise) from CSV files
2. Querying multiple threat intelligence APIs
3. Enriching data with geographic and reputation information
4. Calculating confidence scores based on source correlation
5. Outputting results to JSON and Splunk

Author: SOC Team
Date: 2025-01-XX
Version: 1.0
"""

import csv
import json
import time
import logging
import requests
import datetime
import base64
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import hashlib
import re

class ThreatIntelAnalyzer:
    """
    Main class for threat intelligence analysis operations.
    Handles API integrations, data enrichment, and result aggregation.
    """
    
    def __init__(self, config_file: str = "config.json"):
        """
        Initialize the analyzer with configuration settings.
        
        Args:
            config_file (str): Path to configuration file containing API keys and settings
        """
        self.config = self._load_config(config_file)
        self.logger = self._setup_logging()
        
        # Rate limiting trackers for different APIs
        self.vt_last_request = 0  # VirusTotal last request timestamp
        self.vt_request_count = 0  # VirusTotal requests in current minute
        self.abuseipdb_daily_count = 0  # AbuseIPDB daily request count
        self.abuseipdb_last_reset = datetime.date.today()
        
        # Results storage
        self.enriched_results = []
        
        self.logger.info("Threat Intelligence Analyzer initialized successfully")

    def _load_config(self, config_file: str) -> Dict:
        """
        Load configuration from JSON file.
        
        Args:
            config_file (str): Path to configuration file
            
        Returns:
            Dict: Configuration dictionary
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            json.JSONDecodeError: If config file is invalid JSON
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            return config
        except FileNotFoundError:
            print(f"Configuration file {config_file} not found. Please create it first.")
            raise
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in configuration file: {e}")
            raise

    def _setup_logging(self) -> logging.Logger:
        """
        Configure logging for the application.
        
        Returns:
            logging.Logger: Configured logger instance
        """
        # Create logger
        logger = logging.getLogger('ThreatIntelAnalyzer')
        logger.setLevel(logging.INFO)
        
        # Create file handler
        log_filename = f"threat_intel_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
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

    def load_iocs_from_csv(self, csv_file: str) -> List[Dict]:
        """
        Load Indicators of Compromise (IOCs) from CSV file.
        
        Args:
            csv_file (str): Path to CSV file containing IOCs
            
        Returns:
            List[Dict]: List of IOC dictionaries with type classification
            
        Expected CSV format:
        indicator,type,description
        192.168.1.1,ip,Suspicious IP from logs
        malicious.com,domain,C2 domain
        abc123...,hash,Malware file hash
        """
        iocs = []
        
        try:
            with open(csv_file, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                
                for row_num, row in enumerate(reader, start=2):  # Start at 2 for header
                    try:
                        # Extract and validate required fields
                        indicator = row.get('indicator', '').strip()
                        ioc_type = row.get('type', '').strip().lower()
                        description = row.get('description', '').strip()
                        
                        if not indicator:
                            self.logger.warning(f"Empty indicator in row {row_num}, skipping")
                            continue
                        
                        # Auto-detect IOC type if not provided or validate existing type
                        detected_type = self._detect_ioc_type(indicator)
                        if not ioc_type:
                            ioc_type = detected_type
                        elif ioc_type != detected_type:
                            self.logger.warning(
                                f"Type mismatch for {indicator}: provided '{ioc_type}', "
                                f"detected '{detected_type}'. Using detected type."
                            )
                            ioc_type = detected_type
                        
                        # Create IOC dictionary
                        ioc_dict = {
                            'indicator': indicator,
                            'type': ioc_type,
                            'description': description,
                            'source_row': row_num,
                            'timestamp_added': datetime.datetime.now().isoformat()
                        }
                        
                        iocs.append(ioc_dict)
                        
                    except Exception as e:
                        self.logger.error(f"Error processing row {row_num}: {e}")
                        continue
                        
        except FileNotFoundError:
            self.logger.error(f"CSV file {csv_file} not found")
            raise
        except Exception as e:
            self.logger.error(f"Error reading CSV file: {e}")
            raise
        
        # Remove duplicates while preserving order
        unique_iocs = []
        seen_indicators = set()
        
        for ioc in iocs:
            if ioc['indicator'] not in seen_indicators:
                unique_iocs.append(ioc)
                seen_indicators.add(ioc['indicator'])
            else:
                self.logger.info(f"Duplicate indicator removed: {ioc['indicator']}")
        
        self.logger.info(f"Loaded {len(unique_iocs)} unique IOCs from {csv_file}")
        return unique_iocs

    def _detect_ioc_type(self, indicator: str) -> str:
        """
        Automatically detect the type of an indicator.
        
        Args:
            indicator (str): The indicator to classify
            
        Returns:
            str: The detected type ('ip', 'domain', 'url', 'hash', or 'unknown')
        """
        # Remove whitespace
        indicator = indicator.strip()
        
        # Check for IP address (IPv4)
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if re.match(ip_pattern, indicator):
            return 'ip'
        
        # Check for URL (starts with http/https)
        if indicator.lower().startswith(('http://', 'https://')):
            return 'url'
        
        # Check for file hashes (MD5: 32 chars, SHA1: 40 chars, SHA256: 64 chars)
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

    def _wait_for_virustotal_rate_limit(self):
        """
        Implement rate limiting for VirusTotal API (4 requests per minute).
        This function ensures we don't exceed the API rate limits.
        """
        current_time = time.time()
        
        # Reset counter if a minute has passed
        if current_time - self.vt_last_request >= 60:
            self.vt_request_count = 0
        
        # If we've made 4 requests in the current minute, wait
        if self.vt_request_count >= 4:
            wait_time = 60 - (current_time - self.vt_last_request)
            if wait_time > 0:
                self.logger.info(f"VirusTotal rate limit reached, waiting {wait_time:.2f} seconds")
                time.sleep(wait_time)
                self.vt_request_count = 0
        
        self.vt_last_request = time.time()
        self.vt_request_count += 1

    def _check_abuseipdb_rate_limit(self) -> bool:
        """
        Check if we can make an AbuseIPDB request (1000 per day limit).
        
        Returns:
            bool: True if we can make a request, False if limit exceeded
        """
        today = datetime.date.today()
        
        # Reset counter if it's a new day
        if today != self.abuseipdb_last_reset:
            self.abuseipdb_daily_count = 0
            self.abuseipdb_last_reset = today
        
        if self.abuseipdb_daily_count >= 1000:
            self.logger.warning("AbuseIPDB daily rate limit (1000) exceeded")
            return False
        
        self.abuseipdb_daily_count += 1
        return True

    def query_virustotal(self, indicator: str, ioc_type: str) -> Dict:
        """
        Query VirusTotal API v3 for threat intelligence data.
        
        Args:
            indicator (str): The indicator to query
            ioc_type (str): Type of indicator ('ip', 'domain', 'url', 'hash')
            
        Returns:
            Dict: VirusTotal analysis results
        """
        self._wait_for_virustotal_rate_limit()
        
        api_key = self.config['apis']['virustotal']['api_key']
        base_url = "https://www.virustotal.com/api/v3"
        
        headers = {
            'x-apikey': api_key,
            'User-Agent': 'ThreatIntelAnalyzer/1.0'
        }
        
        # Determine the appropriate endpoint based on IOC type
        if ioc_type == 'hash':
            endpoint = f"{base_url}/files/{indicator}"
        elif ioc_type == 'domain':
            endpoint = f"{base_url}/domains/{indicator}"
        elif ioc_type == 'ip':
            endpoint = f"{base_url}/ip_addresses/{indicator}"
        elif ioc_type == 'url':
            # For URLs in v3, we need to encode them as base64
            url_id = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip('=')
            endpoint = f"{base_url}/urls/{url_id}"
        else:
            self.logger.warning(f"Unsupported IOC type for VirusTotal: {ioc_type}")
            return {'error': 'Unsupported IOC type', 'source': 'VirusTotal'}
        
        max_retries = self.config['settings'].get('max_retries', 3)
        
        for attempt in range(max_retries):
            try:
                self.logger.info(f"Querying VirusTotal v3 for {ioc_type}: {indicator} (attempt {attempt + 1})")
                
                response = requests.get(
                    endpoint,
                    headers=headers,
                    timeout=self.config['settings']['request_timeout']
                )
                
                # Handle different response codes gracefully
                if response.status_code == 404:
                    self.logger.info(f"Indicator {indicator} not found in VirusTotal")
                    return {
                        'source': 'VirusTotal',
                        'indicator': indicator,
                        'type': ioc_type,
                        'status': 'Not found',
                        'reputation_score': 0,
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                elif response.status_code == 429:
                    self.logger.warning(f"Rate limit exceeded for VirusTotal, attempt {attempt + 1}")
                    if attempt < max_retries - 1:
                        time.sleep(60)  # Wait 1 minute before retry
                        continue
                    else:
                        return {'error': 'Rate limit exceeded', 'source': 'VirusTotal'}
                
                response.raise_for_status()
                data = response.json()
                
                # Extract relevant information from v3 API response
                result = {
                    'source': 'VirusTotal',
                    'indicator': indicator,
                    'type': ioc_type,
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']
                    
                    # Extract scan results
                    last_analysis_stats = attributes.get('last_analysis_stats', {})
                    malicious = last_analysis_stats.get('malicious', 0)
                    suspicious = last_analysis_stats.get('suspicious', 0)
                    total_engines = sum(last_analysis_stats.values())
                    
                    result.update({
                        'malicious': malicious,
                        'suspicious': suspicious,
                        'total_engines': total_engines,
                        'detection_ratio': f"{malicious + suspicious}/{total_engines}",
                        'last_analysis_date': attributes.get('last_analysis_date', ''),
                        'reputation_score': self._calculate_vt_v3_reputation_score(attributes)
                    })
                    
                    # Add type-specific information
                    if ioc_type == 'domain':
                        result['categories'] = attributes.get('categories', {})
                        result['registrar'] = attributes.get('registrar', '')
                        result['creation_date'] = attributes.get('creation_date', '')
                    elif ioc_type == 'ip':
                        result['country'] = attributes.get('country', '')
                        result['as_owner'] = attributes.get('as_owner', '')
                        result['asn'] = attributes.get('asn', '')
                        result['network'] = attributes.get('network', '')
                    elif ioc_type == 'hash':
                        result['md5'] = attributes.get('md5', '')
                        result['sha1'] = attributes.get('sha1', '')
                        result['sha256'] = attributes.get('sha256', '')
                        result['file_type'] = attributes.get('type_description', '')
                        result['size'] = attributes.get('size', 0)
                        result['names'] = attributes.get('names', [])
                    elif ioc_type == 'url':
                        result['title'] = attributes.get('title', '')
                        result['final_url'] = attributes.get('final_url', '')
                        
                else:
                    result['status'] = 'No analysis data available'
                    result['reputation_score'] = 0
                
                return result
                
            except requests.exceptions.Timeout:
                self.logger.error(f"Timeout querying VirusTotal for {indicator} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    time.sleep(2)  # Short delay before retry
                    continue
                else:
                    return {'error': 'Timeout after retries', 'source': 'VirusTotal'}
            except requests.exceptions.HTTPError as e:
                self.logger.error(f"HTTP error querying VirusTotal for {indicator}: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1 and e.response.status_code >= 500:
                    time.sleep(2)  # Retry on server errors
                    continue
                else:
                    return {'error': f'HTTP error: {e}', 'source': 'VirusTotal'}
            except Exception as e:
                self.logger.error(f"Error querying VirusTotal for {indicator}: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return {'error': str(e), 'source': 'VirusTotal'}
        
        return {'error': 'Max retries exceeded', 'source': 'VirusTotal'}

    def _calculate_vt_reputation_score(self, vt_data: Dict) -> float:
        """
        Calculate reputation score based on VirusTotal v2 detection results.
        
        Args:
            vt_data (Dict): VirusTotal API v2 response data
            
        Returns:
            float: Reputation score between 0-100 (0=clean, 100=malicious)
        """
        positives = vt_data.get('positives', 0)
        total = vt_data.get('total', 1)
        
        if total == 0:
            return 0
        
        # Calculate base score from detection ratio
        detection_ratio = positives / total
        base_score = detection_ratio * 100
        
        # Apply weighting based on total engines
        # More engines = more reliable score
        engine_weight = min(total / 70, 1.0)  # VirusTotal typically has ~70 engines
        weighted_score = base_score * engine_weight
        
        return round(weighted_score, 2)
    
    def _calculate_vt_v3_reputation_score(self, attributes: Dict) -> float:
        """
        Calculate reputation score based on VirusTotal v3 detection results.
        
        Args:
            attributes (Dict): VirusTotal API v3 attributes data
            
        Returns:
            float: Reputation score between 0-100 (0=clean, 100=malicious)
        """
        last_analysis_stats = attributes.get('last_analysis_stats', {})
        
        malicious = last_analysis_stats.get('malicious', 0)
        suspicious = last_analysis_stats.get('suspicious', 0)
        total = sum(last_analysis_stats.values())
        
        if total == 0:
            return 0
        
        # Calculate weighted score (malicious = full weight, suspicious = half weight)
        weighted_detections = malicious + (suspicious * 0.5)
        detection_ratio = weighted_detections / total
        base_score = detection_ratio * 100
        
        # Apply weighting based on total engines
        engine_weight = min(total / 70, 1.0)  # VirusTotal typically has ~70 engines
        weighted_score = base_score * engine_weight
        
        return round(weighted_score, 2)

    def query_abuseipdb(self, ip_address: str) -> Dict:
        """
        Query AbuseIPDB for IP reputation and geolocation data.
        
        Args:
            ip_address (str): IP address to query
            
        Returns:
            Dict: AbuseIPDB analysis results
        """
        if not self._check_abuseipdb_rate_limit():
            return {'error': 'Daily rate limit exceeded', 'source': 'AbuseIPDB'}
        
        api_key = self.config['apis']['abuseipdb']['api_key']
        url = "https://api.abuseipdb.com/api/v2/check"
        
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': self.config['apis']['abuseipdb']['max_age_days'],
            'verbose': ''
        }
        
        max_retries = self.config['settings'].get('max_retries', 3)
        
        for attempt in range(max_retries):
            try:
                self.logger.info(f"Querying AbuseIPDB for IP: {ip_address} (attempt {attempt + 1})")
                
                response = requests.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=self.config['settings']['request_timeout']
                )
                
                # Handle rate limiting gracefully
                if response.status_code == 429:
                    self.logger.warning(f"AbuseIPDB rate limit hit for {ip_address}, attempt {attempt + 1}")
                    if attempt < max_retries - 1:
                        time.sleep(60)  # Wait 1 minute before retry
                        continue
                    else:
                        return {'error': 'Rate limit exceeded after retries', 'source': 'AbuseIPDB'}
                
                response.raise_for_status()
                data = response.json()
                
                if 'data' in data and isinstance(data['data'], dict):
                    ip_data = data['data']
                    result = {
                        'source': 'AbuseIPDB',
                        'indicator': ip_address,
                        'type': 'ip',
                        'abuse_confidence': ip_data.get('abuseConfidencePercentage', 0),
                        'is_public': ip_data.get('isPublic', False),
                        'ip_version': ip_data.get('ipVersion', 4),
                        'is_whitelisted': ip_data.get('isWhitelisted', False),
                        'country_code': ip_data.get('countryCode', ''),
                        'country_name': ip_data.get('countryName', ''),
                        'usage_type': ip_data.get('usageType', ''),
                        'isp': ip_data.get('isp', ''),
                        'domain': ip_data.get('domain', ''),
                        'total_reports': ip_data.get('totalReports', 0),
                        'num_distinct_users': ip_data.get('numDistinctUsers', 0),
                        'last_reported_at': ip_data.get('lastReportedAt', ''),
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                    
                    return result
                else:
                    self.logger.warning(f"Unexpected data format from AbuseIPDB for {ip_address}")
                    return {'error': 'Unexpected data format', 'source': 'AbuseIPDB'}
                    
            except requests.exceptions.Timeout:
                self.logger.error(f"Timeout querying AbuseIPDB for {ip_address} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    time.sleep(2)  # Short delay before retry
                    continue
                else:
                    return {'error': 'Timeout after retries', 'source': 'AbuseIPDB'}
            except requests.exceptions.HTTPError as e:
                self.logger.error(f"HTTP error querying AbuseIPDB for {ip_address}: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1 and e.response.status_code >= 500:
                    time.sleep(2)  # Retry on server errors
                    continue
                else:
                    return {'error': f'HTTP error: {e}', 'source': 'AbuseIPDB'}
            except (KeyError, TypeError) as e:
                self.logger.error(f"Data format error querying AbuseIPDB for {ip_address}: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return {'error': f'Data format error: {e}', 'source': 'AbuseIPDB'}
            except Exception as e:
                self.logger.error(f"Error querying AbuseIPDB for {ip_address}: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return {'error': str(e), 'source': 'AbuseIPDB'}
        
        return {'error': 'Max retries exceeded', 'source': 'AbuseIPDB'}

    def query_otx(self, indicator: str, ioc_type: str) -> Dict:
        """
        Query AlienVault OTX (Open Threat Exchange) for threat intelligence.
        
        Args:
            indicator (str): The indicator to query
            ioc_type (str): Type of indicator
            
        Returns:
            Dict: OTX analysis results
        """
        api_key = self.config['apis']['otx']['api_key']
        base_url = "https://otx.alienvault.com/api/v1/indicators"
        
        headers = {
            'X-OTX-API-KEY': api_key,
            'Content-Type': 'application/json'
        }
        
        # Map IOC types to OTX indicator types
        otx_type_mapping = {
            'ip': 'IPv4',
            'domain': 'domain',
            'url': 'url',
            'hash': 'file_hash'
        }
        
        otx_type = otx_type_mapping.get(ioc_type)
        if not otx_type:
            return {'error': 'Unsupported IOC type for OTX', 'source': 'OTX'}
        
        # Determine hash type for file indicators
        if ioc_type == 'hash':
            if len(indicator) == 32:
                otx_type = 'file_hash'
            elif len(indicator) == 40:
                otx_type = 'file_hash'
            elif len(indicator) == 64:
                otx_type = 'file_hash'
        
        url = f"{base_url}/{otx_type}/{indicator}/general"
        max_retries = self.config['settings'].get('max_retries', 3)
        
        for attempt in range(max_retries):
            try:
                self.logger.info(f"Querying OTX for {ioc_type}: {indicator} (attempt {attempt + 1})")
                
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=self.config['settings']['request_timeout']
                )
                
                # Handle different response codes gracefully
                if response.status_code == 404:
                    self.logger.info(f"Indicator {indicator} not found in OTX")
                    return {
                        'source': 'OTX',
                        'indicator': indicator,
                        'type': ioc_type,
                        'pulse_count': 0,
                        'reputation_score': 0,
                        'status': 'Not found',
                        'timestamp': datetime.datetime.now().isoformat()
                    }
                
                response.raise_for_status()
                data = response.json()
                
                # Handle different response formats more robustly
                result = {
                    'source': 'OTX',
                    'indicator': indicator,
                    'type': ioc_type,
                    'timestamp': datetime.datetime.now().isoformat()
                }
                
                # Extract pulse information safely
                pulse_info = data.get('pulse_info', {})
                
                # Handle case where pulse_info might be a list instead of dict
                if isinstance(pulse_info, list):
                    pulse_count = len(pulse_info)
                    references = []
                    pulses = pulse_info[:5]  # Limit to first 5 for brevity
                elif isinstance(pulse_info, dict):
                    pulse_count = pulse_info.get('count', 0)
                    references = pulse_info.get('references', [])
                    pulses = pulse_info.get('pulses', [])[:5]
                else:
                    pulse_count = 0
                    references = []
                    pulses = []
                
                result.update({
                    'pulse_count': pulse_count,
                    'references': references,
                    'pulses': pulses,
                    'reputation_score': min(pulse_count * 10, 100),
                })
                
                # Add additional fields if available
                if 'sections' in data and isinstance(data['sections'], dict):
                    result['sections'] = list(data['sections'].keys())
                elif 'sections' in data and isinstance(data['sections'], list):
                    result['sections'] = data['sections']
                
                # Add base indicator info if available
                if 'base_indicator' in data:
                    base_info = data['base_indicator']
                    if isinstance(base_info, dict):
                        result['base_indicator'] = {
                            'indicator': base_info.get('indicator', ''),
                            'type': base_info.get('type', ''),
                            'description': base_info.get('description', '')
                        }
                
                return result
                
            except requests.exceptions.Timeout:
                self.logger.error(f"Timeout querying OTX for {indicator} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    time.sleep(2)  # Short delay before retry
                    continue
                else:
                    return {'error': 'Timeout after retries', 'source': 'OTX'}
            except requests.exceptions.HTTPError as e:
                self.logger.error(f"HTTP error querying OTX for {indicator}: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1 and e.response.status_code >= 500:
                    time.sleep(2)  # Retry on server errors
                    continue
                else:
                    return {'error': f'HTTP error: {e}', 'source': 'OTX'}
            except (KeyError, TypeError, AttributeError) as e:
                self.logger.error(f"Data format error querying OTX for {indicator}: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return {'error': f'Data format error: {e}', 'source': 'OTX'}
            except Exception as e:
                self.logger.error(f"Error querying OTX for {indicator}: {e} (attempt {attempt + 1})")
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                else:
                    return {'error': str(e), 'source': 'OTX'}
        
        return {'error': 'Max retries exceeded', 'source': 'OTX'}

    def calculate_confidence_score(self, sources_data: List[Dict]) -> Tuple[float, Dict]:
        """
        Calculate overall confidence score based on multiple threat intelligence sources.
        
        Args:
            sources_data (List[Dict]): List of results from different TI sources
            
        Returns:
            Tuple[float, Dict]: Overall confidence score (0-100) and scoring breakdown
        """
        # Source reliability weights (based on general reputation and data quality)
        source_weights = {
            'VirusTotal': 0.4,   # High weight due to multiple AV engines
            'AbuseIPDB': 0.35,   # High weight for IP reputation
            'OTX': 0.25          # Lower weight as community-driven
        }
        
        total_weight = 0
        weighted_score = 0
        source_scores = {}
        
        for source_data in sources_data:
            if 'error' in source_data:
                continue
                
            source = source_data.get('source', '')
            weight = source_weights.get(source, 0.1)  # Default small weight for unknown sources
            
            # Extract score based on source type
            if source == 'VirusTotal':
                score = source_data.get('reputation_score', 0)
            elif source == 'AbuseIPDB':
                score = source_data.get('abuse_confidence', 0)
            elif source == 'OTX':
                score = source_data.get('reputation_score', 0)
            else:
                score = 0
            
            source_scores[source] = score
            weighted_score += score * weight
            total_weight += weight
        
        # Calculate final confidence score
        if total_weight > 0:
            confidence_score = weighted_score / total_weight
        else:
            confidence_score = 0
        
        # Create scoring breakdown for transparency
        scoring_breakdown = {
            'overall_confidence': round(confidence_score, 2),
            'source_scores': source_scores,
            'source_weights': source_weights,
            'sources_queried': len(sources_data),
            'sources_with_data': len([s for s in sources_data if 'error' not in s])
        }
        
        return round(confidence_score, 2), scoring_breakdown

    def enrich_ioc_data(self, ioc: Dict) -> Dict:
        """
        Enrich a single IOC with threat intelligence from multiple sources.
        This method is resilient to API failures and will continue even if some sources fail.
        
        Args:
            ioc (Dict): IOC dictionary with indicator, type, and description
            
        Returns:
            Dict: Enriched IOC data with TI results and confidence scoring
        """
        indicator = ioc['indicator']
        ioc_type = ioc['type']
        
        self.logger.info(f"Enriching {ioc_type}: {indicator}")
        
        # Initialize enriched data structure
        enriched_data = {
            'original_ioc': ioc,
            'enrichment_timestamp': datetime.datetime.now().isoformat(),
            'threat_intelligence': {},
            'confidence_analysis': {},
            'summary': {},
            'api_status': {}  # Track which APIs succeeded/failed
        }
        
        # Collect results from different sources
        ti_results = []
        
        # Query VirusTotal for all supported types
        if ioc_type in ['ip', 'domain', 'url', 'hash']:
            try:
                self.logger.debug(f"Querying VirusTotal for {indicator}")
                vt_result = self.query_virustotal(indicator, ioc_type)
                enriched_data['threat_intelligence']['virustotal'] = vt_result
                
                if 'error' not in vt_result:
                    ti_results.append(vt_result)
                    enriched_data['api_status']['virustotal'] = 'success'
                else:
                    enriched_data['api_status']['virustotal'] = f"error: {vt_result.get('error', 'unknown')}"
                    self.logger.warning(f"VirusTotal query failed for {indicator}: {vt_result.get('error')}")
            except Exception as e:
                self.logger.error(f"Unexpected error querying VirusTotal for {indicator}: {e}")
                enriched_data['api_status']['virustotal'] = f"exception: {str(e)}"
                enriched_data['threat_intelligence']['virustotal'] = {'error': f'Exception: {e}', 'source': 'VirusTotal'}
        else:
            enriched_data['api_status']['virustotal'] = 'skipped: unsupported IOC type'
        
        # Query AbuseIPDB specifically for IP addresses
        if ioc_type == 'ip':
            try:
                self.logger.debug(f"Querying AbuseIPDB for {indicator}")
                abuseipdb_result = self.query_abuseipdb(indicator)
                enriched_data['threat_intelligence']['abuseipdb'] = abuseipdb_result
                
                if 'error' not in abuseipdb_result:
                    ti_results.append(abuseipdb_result)
                    enriched_data['api_status']['abuseipdb'] = 'success'
                else:
                    enriched_data['api_status']['abuseipdb'] = f"error: {abuseipdb_result.get('error', 'unknown')}"
                    self.logger.warning(f"AbuseIPDB query failed for {indicator}: {abuseipdb_result.get('error')}")
            except Exception as e:
                self.logger.error(f"Unexpected error querying AbuseIPDB for {indicator}: {e}")
                enriched_data['api_status']['abuseipdb'] = f"exception: {str(e)}"
                enriched_data['threat_intelligence']['abuseipdb'] = {'error': f'Exception: {e}', 'source': 'AbuseIPDB'}
        else:
            enriched_data['api_status']['abuseipdb'] = 'skipped: not an IP address'
        
        # Query OTX for supported types
        if ioc_type in ['ip', 'domain', 'url', 'hash']:
            try:
                self.logger.debug(f"Querying OTX for {indicator}")
                otx_result = self.query_otx(indicator, ioc_type)
                enriched_data['threat_intelligence']['otx'] = otx_result
                
                if 'error' not in otx_result:
                    ti_results.append(otx_result)
                    enriched_data['api_status']['otx'] = 'success'
                else:
                    enriched_data['api_status']['otx'] = f"error: {otx_result.get('error', 'unknown')}"
                    self.logger.warning(f"OTX query failed for {indicator}: {otx_result.get('error')}")
            except Exception as e:
                self.logger.error(f"Unexpected error querying OTX for {indicator}: {e}")
                enriched_data['api_status']['otx'] = f"exception: {str(e)}"
                enriched_data['threat_intelligence']['otx'] = {'error': f'Exception: {e}', 'source': 'OTX'}
        else:
            enriched_data['api_status']['otx'] = 'skipped: unsupported IOC type'
        
        # Calculate confidence score even if some sources failed
        try:
            confidence_score, scoring_breakdown = self.calculate_confidence_score(ti_results)
            enriched_data['confidence_analysis'] = scoring_breakdown
        except Exception as e:
            self.logger.error(f"Error calculating confidence score for {indicator}: {e}")
            enriched_data['confidence_analysis'] = {
                'error': str(e),
                'overall_confidence': 0,
                'sources_with_data': len(ti_results)
            }
            confidence_score = 0
        
        # Generate summary
        try:
            enriched_data['summary'] = self._generate_ioc_summary(enriched_data, confidence_score)
        except Exception as e:
            self.logger.error(f"Error generating summary for {indicator}: {e}")
            enriched_data['summary'] = {
                'indicator': indicator,
                'type': ioc_type,
                'threat_level': 'UNKNOWN',
                'confidence_score': confidence_score,
                'error': f'Summary generation failed: {e}'
            }
        
        # Log overall enrichment status
        successful_apis = [api for api, status in enriched_data['api_status'].items() if status == 'success']
        self.logger.info(f"Enrichment complete for {indicator}. Successful APIs: {successful_apis}")
        
        return enriched_data

    def _generate_ioc_summary(self, enriched_data: Dict, confidence_score: float) -> Dict:
        """
        Generate a human-readable summary of the IOC analysis.
        
        Args:
            enriched_data (Dict): Complete enriched data for the IOC
            confidence_score (float): Overall confidence score
            
        Returns:
            Dict: Summary information for easy interpretation
        """
        original_ioc = enriched_data['original_ioc']
        ti_data = enriched_data['threat_intelligence']
        
        # Determine threat level based on confidence score
        if confidence_score >= 75:
            threat_level = "HIGH"
        elif confidence_score >= 50:
            threat_level = "MEDIUM"
        elif confidence_score >= 25:
            threat_level = "LOW"
        else:
            threat_level = "MINIMAL"
        
        summary = {
            'indicator': original_ioc['indicator'],
            'type': original_ioc['type'],
            'threat_level': threat_level,
            'confidence_score': confidence_score,
            'recommendation': self._get_recommendation(threat_level, confidence_score),
            'key_findings': []
        }
        
        # Extract key findings from each source
        if 'virustotal' in ti_data and 'error' not in ti_data['virustotal']:
            vt_data = ti_data['virustotal']
            if vt_data.get('positives', 0) > 0:
                summary['key_findings'].append(
                    f"VirusTotal: {vt_data['positives']}/{vt_data['total']} engines detected as malicious"
                )
        
        if 'abuseipdb' in ti_data and 'error' not in ti_data['abuseipdb']:
            abuse_data = ti_data['abuseipdb']
            if abuse_data.get('abuse_confidence', 0) > 0:
                summary['key_findings'].append(
                    f"AbuseIPDB: {abuse_data['abuse_confidence']}% abuse confidence, "
                    f"{abuse_data['total_reports']} reports"
                )
            if abuse_data.get('country_name'):
                summary['key_findings'].append(f"Location: {abuse_data['country_name']}")
        
        if 'otx' in ti_data and 'error' not in ti_data['otx']:
            otx_data = ti_data['otx']
            if otx_data.get('pulse_count', 0) > 0:
                summary['key_findings'].append(
                    f"OTX: Found in {otx_data['pulse_count']} threat intelligence pulses"
                )
        
        return summary

    def _get_recommendation(self, threat_level: str, confidence_score: float) -> str:
        """
        Provide actionable recommendations based on threat assessment.
        
        Args:
            threat_level (str): Threat level (HIGH, MEDIUM, LOW, MINIMAL)
            confidence_score (float): Confidence score
            
        Returns:
            str: Recommendation text
        """
        recommendations = {
            "HIGH": "BLOCK immediately. High confidence malicious indicator. Investigate any related activity.",
            "MEDIUM": "MONITOR closely. Likely malicious but requires additional verification before blocking.",
            "LOW": "INVESTIGATE further. Some indicators of suspicious activity detected.",
            "MINIMAL": "LOW PRIORITY. Minimal threat indicators detected. Continue normal monitoring."
        }
        
        return recommendations.get(threat_level, "Review manually for appropriate action.")

    def send_to_splunk(self, enriched_data: Dict) -> bool:
        """
        Send enriched threat intelligence data to Splunk via HTTP Event Collector.
        
        Args:
            enriched_data (Dict): Enriched IOC data to send
            
        Returns:
            bool: True if successful, False otherwise
        """
        splunk_config = self.config['splunk']
        
        if not splunk_config.get('enabled', False):
            self.logger.info("Splunk integration disabled, skipping")
            return True
        
        hec_url = f"{splunk_config['hec_url']}/services/collector"
        hec_token = splunk_config['hec_token']
        
        headers = {
            'Authorization': f'Splunk {hec_token}',
            'Content-Type': 'application/json'
        }
        
        # Format data for Splunk HEC
        splunk_event = {
            'time': int(datetime.datetime.now().timestamp()),
            'source': 'threat_intel_analyzer',
            'sourcetype': 'threat_intelligence',
            'index': splunk_config.get('index', 'main'),
            'event': enriched_data
        }
        
        try:
            response = requests.post(
                hec_url,
                headers=headers,
                json=splunk_event,
                timeout=self.config['settings']['request_timeout'],
                verify=splunk_config.get('verify_ssl', True)
            )
            
            response.raise_for_status()
            
            result = response.json()
            if result.get('text') == 'Success':
                self.logger.info(f"Successfully sent data to Splunk for {enriched_data['original_ioc']['indicator']}")
                return True
            else:
                self.logger.error(f"Splunk HEC error: {result}")
                return False
                
        except requests.exceptions.Timeout:
            self.logger.error("Timeout sending data to Splunk")
            return False
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error sending to Splunk: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Error sending to Splunk: {e}")
            return False

    def save_results_to_json(self, output_file: str) -> bool:
        """
        Save enriched results to JSON file.
        
        Args:
            output_file (str): Path to output JSON file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Add metadata to results
            output_data = {
                'metadata': {
                    'analysis_timestamp': datetime.datetime.now().isoformat(),
                    'total_iocs_analyzed': len(self.enriched_results),
                    'analyzer_version': '1.0',
                    'configuration_used': {
                        'request_timeout': self.config['settings']['request_timeout'],
                        'apis_enabled': list(self.config['apis'].keys())
                    }
                },
                'results': self.enriched_results
            }
            
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Results saved to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving results to JSON: {e}")
            return False

    def analyze_iocs(self, csv_file: str, output_file: str = None) -> List[Dict]:
        """
        Main method to analyze IOCs from CSV file and produce enriched results.
        
        Args:
            csv_file (str): Path to input CSV file
            output_file (str): Path to output JSON file (optional)
            
        Returns:
            List[Dict]: List of enriched IOC data
        """
        self.logger.info("Starting IOC analysis process")
        
        # Load IOCs from CSV
        iocs = self.load_iocs_from_csv(csv_file)
        
        if not iocs:
            self.logger.warning("No IOCs found in CSV file")
            return []
        
        # Process each IOC
        for i, ioc in enumerate(iocs, 1):
            self.logger.info(f"Processing IOC {i}/{len(iocs)}: {ioc['indicator']}")
            
            try:
                # Enrich the IOC data
                enriched_data = self.enrich_ioc_data(ioc)
                self.enriched_results.append(enriched_data)
                
                # Send to Splunk if enabled
                self.send_to_splunk(enriched_data)
                
                # Add small delay between requests to be respectful to APIs
                time.sleep(self.config['settings']['request_delay'])
                
            except Exception as e:
                self.logger.error(f"Error processing IOC {ioc['indicator']}: {e}")
                continue
        
        # Save results to JSON file
        if output_file:
            self.save_results_to_json(output_file)
        else:
            # Generate default filename with timestamp
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            default_output = f"threat_intel_results_{timestamp}.json"
            self.save_results_to_json(default_output)
        
        self.logger.info(f"Analysis complete. Processed {len(self.enriched_results)} IOCs")
        return self.enriched_results

    def generate_summary_report(self) -> Dict:
        """
        Generate a summary report of the analysis results.
        
        Returns:
            Dict: Summary statistics and key findings
        """
        if not self.enriched_results:
            return {'error': 'No results to summarize'}
        
        # Initialize counters
        threat_levels = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'MINIMAL': 0}
        ioc_types = {}
        total_confidence = 0
        
        # Analyze results
        for result in self.enriched_results:
            summary = result.get('summary', {})
            
            # Count threat levels
            threat_level = summary.get('threat_level', 'UNKNOWN')
            if threat_level in threat_levels:
                threat_levels[threat_level] += 1
            
            # Count IOC types
            ioc_type = summary.get('type', 'unknown')
            ioc_types[ioc_type] = ioc_types.get(ioc_type, 0) + 1
            
            # Sum confidence scores
            confidence = summary.get('confidence_score', 0)
            total_confidence += confidence
        
        # Calculate averages
        avg_confidence = total_confidence / len(self.enriched_results)
        
        # Create summary report
        report = {
            'analysis_summary': {
                'total_iocs_analyzed': len(self.enriched_results),
                'average_confidence_score': round(avg_confidence, 2),
                'analysis_timestamp': datetime.datetime.now().isoformat()
            },
            'threat_level_distribution': threat_levels,
            'ioc_type_distribution': ioc_types,
            'high_priority_indicators': [
                {
                    'indicator': result['original_ioc']['indicator'],
                    'type': result['original_ioc']['type'],
                    'threat_level': result['summary']['threat_level'],
                    'confidence_score': result['summary']['confidence_score']
                }
                for result in self.enriched_results
                if result.get('summary', {}).get('threat_level') == 'HIGH'
            ]
        }
        
        return report

def main():
    """
    Main execution function for command-line usage.
    """
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Cybersecurity Threat Intelligence Analyzer'
    )
    parser.add_argument(
        'csv_file',
        help='Path to CSV file containing IOCs'
    )
    parser.add_argument(
        '-o', '--output',
        help='Output JSON file path (optional)',
        default=None
    )
    parser.add_argument(
        '-c', '--config',
        help='Configuration file path',
        default='config.json'
    )
    parser.add_argument(
        '-r', '--report',
        help='Generate summary report',
        action='store_true'
    )
    
    args = parser.parse_args()
    
    try:
        # Initialize analyzer
        analyzer = ThreatIntelAnalyzer(args.config)
        
        # Analyze IOCs
        results = analyzer.analyze_iocs(args.csv_file, args.output)
        
        # Generate report if requested
        if args.report:
            report = analyzer.generate_summary_report()
            print("\n=== THREAT INTELLIGENCE ANALYSIS REPORT ===")
            print(json.dumps(report, indent=2))
        
        print(f"\nAnalysis complete! Processed {len(results)} indicators.")
        print("Check the log file and output JSON for detailed results.")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())