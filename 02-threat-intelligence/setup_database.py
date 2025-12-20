#!/usr/bin/env python3
"""
Database Setup Script for Threat Intelligence Feed Collector

This script initializes the SQLite database and optionally populates it with
sample data for testing and demonstration purposes.

Usage:
    python3 setup_database.py                    # Initialize empty database
    python3 setup_database.py --sample-data      # Initialize with sample data
    python3 setup_database.py --reset            # Reset existing database
"""

import sqlite3
import json
import datetime
import sys
import os

def create_database(db_path: str = "threat_intel.db", reset: bool = False):
    """
    Create the threat intelligence database with proper schema.
    
    Args:
        db_path (str): Path to database file
        reset (bool): Whether to reset existing database
    """
    # Remove existing database if reset requested
    if reset and os.path.exists(db_path):
        os.remove(db_path)
        print(f"Removed existing database: {db_path}")
    
    print(f"Creating database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create indicators table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            indicator_hash TEXT UNIQUE NOT NULL,
            indicator_value TEXT NOT NULL,
            indicator_type TEXT NOT NULL,
            source TEXT NOT NULL,
            confidence_score REAL NOT NULL,
            first_seen DATE NOT NULL,
            last_seen DATE NOT NULL,
            times_seen INTEGER DEFAULT 1,
            description TEXT,
            tags TEXT,
            raw_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
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
    
    # Create collection runs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS collection_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            sources_attempted TEXT,
            sources_successful TEXT,
            total_collected INTEGER,
            total_new INTEGER,
            total_updated INTEGER,
            errors TEXT,
            duration_seconds REAL
        )
    ''')
    
    # Create feed reliability table
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
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_times_seen ON indicators(times_seen)')
    
    # Additional indexes for common queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_confidence_recent ON indicators(confidence_score, last_seen)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_type_confidence ON indicators(indicator_type, confidence_score)')
    
    conn.commit()
    print("Database schema created successfully")
    
    # Insert default sources
    sources_data = [
        ('otx', 'https://otx.alienvault.com', 0.85),
        ('malware_domain_list', 'http://www.malwaredomainlist.com', 0.90),
        ('phishtank', 'https://www.phishtank.com', 0.80),
        ('emerging_threats', 'https://rules.emergingthreats.net', 0.95),
        ('urlhaus', 'https://urlhaus.abuse.ch', 0.85)
    ]
    
    for source_name, source_url, reliability_weight in sources_data:
        cursor.execute('''
            INSERT OR IGNORE INTO sources (source_name, source_url, reliability_weight)
            VALUES (?, ?, ?)
        ''', (source_name, source_url, reliability_weight))
    
    conn.commit()
    print("Default sources added successfully")
    
    return conn

def add_sample_data(conn: sqlite3.Connection):
    """
    Add sample threat intelligence data for testing.
    
    Args:
        conn: SQLite connection object
    """
    print("Adding sample data...")
    
    cursor = conn.cursor()
    current_time = datetime.datetime.now().isoformat()
    yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).isoformat()
    
    # Sample indicators
    sample_indicators = [
        {
            'hash': 'abc123def456',
            'value': '192.168.1.100',
            'type': 'ip',
            'source': 'emerging_threats',
            'confidence': 0.95,
            'description': 'Known malicious IP from botnet',
            'tags': ['botnet', 'malware', 'c2']
        },
        {
            'hash': 'def456ghi789',
            'value': 'malicious.example.com',
            'type': 'domain',
            'source': 'malware_domain_list',
            'confidence': 0.90,
            'description': 'Domain hosting malware',
            'tags': ['malware', 'domain']
        },
        {
            'hash': 'ghi789jkl012',
            'value': 'http://phishing.example.org/login',
            'type': 'url',
            'source': 'phishtank',
            'confidence': 0.85,
            'description': 'Phishing page mimicking bank login',
            'tags': ['phishing', 'banking', 'credential_theft']
        },
        {
            'hash': 'jkl012mno345',
            'value': 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6',
            'type': 'hash',
            'source': 'urlhaus',
            'confidence': 0.88,
            'description': 'SHA-256 hash of known malware sample',
            'tags': ['malware', 'trojan', 'hash']
        },
        {
            'hash': 'mno345pqr678',
            'value': 'attacker@evil.com',
            'type': 'email',
            'source': 'otx',
            'confidence': 0.75,
            'description': 'Email address used in phishing campaigns',
            'tags': ['phishing', 'email', 'campaign']
        },
        {
            'hash': 'pqr678stu901',
            'value': '10.0.0.50',
            'type': 'ip',
            'source': 'otx',
            'confidence': 0.80,
            'description': 'IP associated with APT group',
            'tags': ['apt', 'espionage', 'lateral_movement']
        }
    ]
    
    for indicator in sample_indicators:
        cursor.execute('''
            INSERT INTO indicators (
                indicator_hash, indicator_value, indicator_type, source,
                confidence_score, first_seen, last_seen, times_seen,
                description, tags, raw_data, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            indicator['hash'],
            indicator['value'],
            indicator['type'],
            indicator['source'],
            indicator['confidence'],
            yesterday,
            current_time,
            1,
            indicator['description'],
            json.dumps(indicator['tags']),
            json.dumps({'sample': True, 'indicator_data': indicator}),
            current_time,
            current_time
        ))
    
    # Sample collection run
    cursor.execute('''
        INSERT INTO collection_runs (
            run_timestamp, sources_attempted, sources_successful,
            total_collected, total_new, total_updated, errors, duration_seconds
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        current_time,
        json.dumps(['otx', 'malware_domain_list', 'phishtank', 'emerging_threats', 'urlhaus']),
        json.dumps(['otx', 'malware_domain_list', 'phishtank', 'emerging_threats', 'urlhaus']),
        len(sample_indicators),
        len(sample_indicators),
        0,
        json.dumps([]),
        45.2
    ))
    
    # Sample feed reliability data
    for source in ['otx', 'malware_domain_list', 'phishtank', 'emerging_threats', 'urlhaus']:
        cursor.execute('''
            INSERT INTO feed_reliability (
                source_name, date, indicators_collected, collection_time_seconds, success
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            source,
            datetime.date.today().isoformat(),
            len([i for i in sample_indicators if i['source'] == source]),
            10.5,
            True
        ))
    
    conn.commit()
    print(f"Added {len(sample_indicators)} sample indicators")

def verify_database(db_path: str):
    """
    Verify database was created correctly and show summary.
    
    Args:
        db_path (str): Path to database file
    """
    print(f"\nVerifying database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check tables exist
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cursor.fetchall()]
    
    expected_tables = ['indicators', 'sources', 'collection_runs', 'feed_reliability']
    
    print(f"Tables found: {tables}")
    
    for table in expected_tables:
        if table not in tables:
            print(f"ERROR: Missing table '{table}'")
            return False
    
    # Check record counts
    for table in tables:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        count = cursor.fetchone()[0]
        print(f"Records in {table}: {count}")
    
    # Check indexes
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index'")
    indexes = [row[0] for row in cursor.fetchall()]
    print(f"Indexes created: {len(indexes)}")
    
    conn.close()
    print("Database verification completed successfully!")
    return True

def show_sample_queries(db_path: str):
    """
    Show sample queries that can be run against the database.
    
    Args:
        db_path (str): Path to database file
    """
    print(f"\n=== Sample Database Queries ===")
    print(f"Database: {db_path}")
    print()
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Query 1: Recent high-confidence indicators
    print("1. Recent high-confidence indicators:")
    cursor.execute('''
        SELECT indicator_value, indicator_type, confidence_score, source
        FROM indicators 
        WHERE confidence_score > 0.8
        ORDER BY confidence_score DESC, last_seen DESC
        LIMIT 5
    ''')
    
    results = cursor.fetchall()
    if results:
        print("   Value | Type | Confidence | Source")
        print("   " + "-" * 50)
        for row in results:
            print(f"   {row[0][:30]:<30} | {row[1]:<6} | {row[2]:<10.2f} | {row[3]}")
    else:
        print("   No data found")
    print()
    
    # Query 2: Indicators by type
    print("2. Indicators by type:")
    cursor.execute('''
        SELECT indicator_type, COUNT(*) as count, AVG(confidence_score) as avg_confidence
        FROM indicators 
        GROUP BY indicator_type 
        ORDER BY count DESC
    ''')
    
    results = cursor.fetchall()
    if results:
        print("   Type | Count | Avg Confidence")
        print("   " + "-" * 30)
        for row in results:
            print(f"   {row[0]:<8} | {row[1]:<5} | {row[2]:<10.2f}")
    else:
        print("   No data found")
    print()
    
    # Query 3: Source statistics
    print("3. Source statistics:")
    cursor.execute('''
        SELECT source, COUNT(*) as total_indicators, AVG(confidence_score) as avg_confidence
        FROM indicators 
        GROUP BY source 
        ORDER BY total_indicators DESC
    ''')
    
    results = cursor.fetchall()
    if results:
        print("   Source | Indicators | Avg Confidence")
        print("   " + "-" * 40)
        for row in results:
            print(f"   {row[0]:<15} | {row[1]:<10} | {row[2]:<10.2f}")
    else:
        print("   No data found")
    print()
    
    conn.close()

def main():
    """Main function for database setup."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Setup SQLite database for Threat Intelligence Feed Collector'
    )
    parser.add_argument(
        '--database', '-d',
        default='threat_intel.db',
        help='Database file path (default: threat_intel.db)'
    )
    parser.add_argument(
        '--sample-data',
        action='store_true',
        help='Add sample data for testing'
    )
    parser.add_argument(
        '--reset',
        action='store_true',
        help='Reset existing database (WARNING: deletes all data)'
    )
    parser.add_argument(
        '--verify-only',
        action='store_true',
        help='Only verify existing database'
    )
    parser.add_argument(
        '--queries',
        action='store_true',
        help='Show sample queries'
    )
    
    args = parser.parse_args()
    
    try:
        if args.verify_only:
            if not os.path.exists(args.database):
                print(f"ERROR: Database {args.database} does not exist")
                return 1
            verify_database(args.database)
            if args.queries:
                show_sample_queries(args.database)
            return 0
        
        if args.reset:
            response = input(f"Are you sure you want to reset {args.database}? (yes/no): ")
            if response.lower() != 'yes':
                print("Operation cancelled")
                return 0
        
        # Create database
        conn = create_database(args.database, args.reset)
        
        # Add sample data if requested
        if args.sample_data:
            add_sample_data(conn)
        
        conn.close()
        
        # Verify creation
        verify_database(args.database)
        
        if args.queries or args.sample_data:
            show_sample_queries(args.database)
        
        print(f"\n✅ Database setup completed successfully!")
        print(f"Database location: {os.path.abspath(args.database)}")
        print(f"You can now run: python3 threat_feed_collector.py -d {args.database}")
        
        return 0
        
    except Exception as e:
        print(f"ERROR: {e}")
        return 1

if __name__ == "__main__":
    exit(main())