#!/usr/bin/env python3

import os
import sys
import time
import socket
import ssl
import platform
import subprocess
import re
import json
import threading
import traceback
import hashlib
import pickle
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
from typing import Dict, List, Set, Any, Optional, Tuple
import concurrent.futures
import urllib.parse

# Third-Party Libraries
try:
    import yaml
    import psutil
    import requests
    import numpy as np
    import pyodbc
except ImportError as e:
    print(f"Error: Required library not installed. Run: pip install pyyaml psutil requests numpy pyodbc", file=sys.stderr)
    sys.exit(1)

# Windows-Specific Imports
IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        import win32api
        import wmi
        import pythoncom
    except ImportError:
        print("Warning: Windows libraries not available. Some features will be limited.", file=sys.stderr)
        IS_WINDOWS = False

# ===================================================================
#                      GLOBAL STATE & CONFIGURATION
# ===================================================================

PRINT_LOCK = threading.Lock()

# ENHANCED STATE TRACKING
SECURITY_STATE = {
    'processed_record_numbers': set(),
    'processed_event_hashes': set(),
    'last_event_time': {},
    'last_firewall_collection': 0,
    'event_hash_timestamps': {},
}
SECURITY_STATE_LOCK = threading.Lock()
STATE_FILE_PATH = 'edge_agent_state.pkl'

def create_event_hash(event_dict: dict) -> str:
    """Create unique hash for event deduplication."""
    event_id = str(event_dict.get('event_id', ''))
    source_ip = str(event_dict.get('source_ip', ''))
    target_user = str(event_dict.get('target_user', ''))
    dest_ip = str(event_dict.get('dest_ip', ''))
    dest_port = str(event_dict.get('dest_port', ''))
    timestamp = str(event_dict.get('timestamp', ''))
    
    if event_id == '5152':
        source_port = str(event_dict.get('source_port', ''))
        protocol = str(event_dict.get('protocol', ''))
        key_parts = [event_id, source_ip, source_port, dest_ip, dest_port, protocol, timestamp]
    elif event_id in ['4624', '4625', '4634', '4647', '4672']:
        logon_type = str(event_dict.get('logon_type', ''))
        workstation = str(event_dict.get('workstation_name', ''))
        key_parts = [event_id, target_user, source_ip, logon_type, workstation, timestamp]
    elif event_id in ['4720', '4722', '4725', '4726', '4738', '4723', '4724']:
        subject_user = str(event_dict.get('subject_user', ''))
        key_parts = [event_id, target_user, subject_user, timestamp]
    elif event_id in ['4732', '4733', '4756', '4757', '4751', '4752']:
        group_name = str(event_dict.get('group_name', ''))
        member_user = str(event_dict.get('member_user', ''))
        key_parts = [event_id, group_name, member_user, target_user, timestamp]
    else:
        key_parts = [event_id, source_ip, target_user, dest_ip, dest_port, timestamp]
    
    hash_string = '|'.join(key_parts)
    return hashlib.md5(hash_string.encode()).hexdigest()

def is_event_already_processed(record_number: Optional[int], event_hash: str) -> bool:
    """Check if an event has already been processed."""
    with SECURITY_STATE_LOCK:
        if record_number and record_number in SECURITY_STATE['processed_record_numbers']:
            return True
        if event_hash in SECURITY_STATE['processed_event_hashes']:
            return True
        return False

def mark_event_as_processed(record_number: Optional[int], event_hash: str):
    """Mark an event as processed."""
    with SECURITY_STATE_LOCK:
        current_time = time.time()
        if record_number:
            SECURITY_STATE['processed_record_numbers'].add(record_number)
        SECURITY_STATE['processed_event_hashes'].add(event_hash)
        SECURITY_STATE['event_hash_timestamps'][event_hash] = current_time

def cleanup_old_state():
    """Remove old processed events from state."""
    with SECURITY_STATE_LOCK:
        current_time = time.time()
        cutoff_time = current_time - (24 * 3600)
        
        old_hashes = [
            h for h, t in SECURITY_STATE['event_hash_timestamps'].items()
            if t < cutoff_time
        ]
        
        for hash_val in old_hashes:
            SECURITY_STATE['processed_event_hashes'].discard(hash_val)
            SECURITY_STATE['event_hash_timestamps'].pop(hash_val, None)
        
        if len(SECURITY_STATE['processed_record_numbers']) > 100000:
            sorted_records = sorted(SECURITY_STATE['processed_record_numbers'])
            SECURITY_STATE['processed_record_numbers'] = set(sorted_records[-50000:])
        
        if old_hashes:
            with PRINT_LOCK:
                print(f"[StateCleanup] Removed {len(old_hashes)} old event hashes from memory")

def save_state_to_file():
    """Save current state to file."""
    try:
        with SECURITY_STATE_LOCK:
            state_copy = {
                'processed_record_numbers': SECURITY_STATE['processed_record_numbers'].copy(),
                'processed_event_hashes': SECURITY_STATE['processed_event_hashes'].copy(),
                'event_hash_timestamps': SECURITY_STATE['event_hash_timestamps'].copy(),
                'last_firewall_collection': SECURITY_STATE['last_firewall_collection'],
                'saved_at': time.time()
            }
        
        with open(STATE_FILE_PATH, 'wb') as f:
            pickle.dump(state_copy, f)
        
        with PRINT_LOCK:
            print(f"[StatePersistence] ✅ State saved to {STATE_FILE_PATH}")
    except Exception as e:
        with PRINT_LOCK:
            print(f"[StatePersistence] ⚠️ Failed to save state: {e}")

def load_state_from_file():
    """Load state from file if it exists."""
    if not os.path.exists(STATE_FILE_PATH):
        with PRINT_LOCK:
            print(f"[StatePersistence] No previous state file found, starting fresh")
        return
    
    try:
        with open(STATE_FILE_PATH, 'rb') as f:
            saved_state = pickle.load(f)
        
        with SECURITY_STATE_LOCK:
            SECURITY_STATE['processed_record_numbers'] = saved_state.get('processed_record_numbers', set())
            SECURITY_STATE['processed_event_hashes'] = saved_state.get('processed_event_hashes', set())
            SECURITY_STATE['event_hash_timestamps'] = saved_state.get('event_hash_timestamps', {})
            SECURITY_STATE['last_firewall_collection'] = saved_state.get('last_firewall_collection', 0)
        
        saved_at = saved_state.get('saved_at', 0)
        age_hours = (time.time() - saved_at) / 3600
        
        with PRINT_LOCK:
            print(f"[StatePersistence] ✅ Loaded state from {STATE_FILE_PATH}")
            print(f"[StatePersistence]    - Tracked Record Numbers: {len(SECURITY_STATE['processed_record_numbers'])}")
            print(f"[StatePersistence]    - Tracked Event Hashes: {len(SECURITY_STATE['processed_event_hashes'])}")
            print(f"[StatePersistence]    - State Age: {age_hours:.1f} hours")
    
    except Exception as e:
        with PRINT_LOCK:
            print(f"[StatePersistence] ⚠️ Failed to load state: {e}, starting fresh")

NETWORK_STATE = {
    'wan_link_status': defaultdict(dict),
    'dns_resolution_times': defaultdict(list),
    'application_performance': defaultdict(dict),
    'packet_loss_history': defaultdict(lambda: deque(maxlen=1000)),
    'throughput_history': defaultdict(lambda: deque(maxlen=1000)),
    'latency_history': defaultdict(lambda: deque(maxlen=1000)),
}
NETWORK_STATE_LOCK = threading.Lock()

MONITORING_HOST_NAME = socket.gethostname()
try:
    MONITORING_HOST_IP = socket.gethostbyname(MONITORING_HOST_NAME)
except:
    MONITORING_HOST_IP = "127.0.0.1"

# ===================================================================
#              WINDOWS LOGON FAILURE CODE MAPPING
# ===================================================================
WINDOWS_LOGON_FAILURE_CODES = {
    '0xC0000064': 'User account does not exist',
    '0xC000006A': 'Correct username but wrong password',
    '0xC000006C': 'Password policy not met (e.g., blank password not allowed)',
    '0xC000006D': 'Incorrect username or password',
    '0xC000006E': 'Account restriction prevents login',
    '0xC000006F': 'Login outside allowed time',
    '0xC0000070': 'Workstation restriction prevents login',
    '0xC0000071': 'Password has expired',
    '0xC0000072': 'Account is currently disabled',
    '0xC0000133': 'Time synchronization error between client and server',
    '0xC0000193': 'Account has expired',
    '0xC0000224': 'User must change password at next login',
    '0xC0000234': 'Account is currently locked out',
    '0x00000900': 'Logon failure: Incorrect username or password',
    
    # Common Windows Event Log formats (%%2313 etc.)
    '0x00000569': 'Logon failure: user not allowed to logon to this computer',
    '0x0000052E': 'Logon failure: unknown username or bad password',
    '0x0000052F': 'Logon failure: user account restriction',
    '0x00000530': 'Logon failure: account logon time restriction violation',
    '0x00000531': 'Logon failure: user not allowed to logon to this computer',
    '0x00000532': 'Logon failure: account expired',
    '0x00000533': 'Logon failure: user not allowed to logon to this computer',
    '0x00000534': 'Logon failure: account currently disabled',
    '0x00000535': 'Logon failure: account logon time restriction violation',
    '0x00000536': 'Logon failure: password must change',
    '0x00000537': 'Logon failure: account locked out',
    '0x00000538': 'Logon failure: logon failure',
    '0x00000539': 'Logon failure: account logon time restriction violation',
    '0x00000775': 'User account restriction prevented login',
    
    # ✅ THESE ARE THE MISSING CODES CAUSING YOUR ISSUE:
    '0x00000909': 'Account is currently locked out',  # ← THIS IS YOUR ISSUE!
    '0X00000909': 'Account is currently locked out',  # Uppercase X variant
    '0x0000090A': 'Account is currently disabled',
    '0x0000090B': 'Account has expired',
    '0x0000090C': 'User not allowed to logon at this computer',
    '0x0000090D': 'Password must be changed',
    '0x0000090E': 'Account is locked out',
    '0x00000905': 'Logon failure: account restriction',  # %%2309
    '0x00000906': 'Logon failure: account expired',       # %%2310
    '0x00000907': 'Logon failure: password expired',      # %%2311
    '0x00000908': 'Logon failure: account disabled',      # %%2312
    
    # Advanced Failures
    '0xC00002EE': 'Authentication failed - trust relationship error',
    '0xC0000413': 'Authentication firewall blocked the logon',
    '0x00000415': 'Logon outside of allowed hours',
    '0xC000015B': 'User has not been granted the requested logon type',
    '0xC0000018': 'Username is correct but password is not',
    '0xC0000371': 'Local account restrictions on remote connections',
    '0xC0000192': 'NetLogon service not started',
    '0xC0000380': 'SmartCard logon required',
    '0xC0000381': 'Maximum workstations reached',
    '0xC000038A': 'Password must be changed',
    '0xC0000290': 'Delegation is not enabled on account',
    
    # Network and Protocol Failures
    '0xC000009A': 'Insufficient system resources',
    '0xC0000073': 'Expired password while connecting',
    '0xC00000DC': 'Invalid server state for operation',
    '0xC0000225': 'Not found (generic error)',
    
    # Certificate and Smart Card
    '0xC00000E9': 'User Session Key is invalid',
    '0xC000035C': 'System shutdown in progress',
    '0xC0000361': 'Device attached to system not functioning',
    '0xC000018D': 'Trusted relationship check failed',
    '0xC000018E': 'Netlogon unavailable',
    
    # Kerberos Specific
    '0xC0000188': 'Kerberos: KDC unreachable',
    '0xC0000189': 'Kerberos: Error',
    
    # Success (for comparison)
    '0x0': 'Successful logon (no error)',
    '0x00000000': 'Successful logon (no error)',
}

LOGON_TYPE_MAP = {
    '0': 'System',
    '2': 'Interactive',
    '3': 'Network',
    '4': 'Batch',
    '5': 'Service',
    '7': 'Unlock',
    '8': 'NetworkCleartext',
    '9': 'NewCredentials',
    '10': 'RemoteInteractive',
    '11': 'CachedInteractive',
    '12': 'CachedRemoteInteractive',
    '13': 'CachedUnlock',
}

def get_logon_type_name(logon_type_code: str) -> str:
    if not logon_type_code:
        return 'Unknown'
    logon_type_code = str(logon_type_code).strip()
    return LOGON_TYPE_MAP.get(logon_type_code, f'Type{logon_type_code}')

def translate_failure_reason(failure_code: str) -> str:
    if not failure_code or failure_code == 'Unknown':
        return 'Unknown failure reason'
    
    failure_code = failure_code.strip()
    original_code = failure_code
    
    if failure_code.startswith('%%'):
        try:
            decimal_value = int(failure_code[2:])
            failure_code = f'0x{decimal_value:08X}'
        except ValueError:
            return f"Invalid failure code format: {failure_code}"
    elif failure_code.startswith('%'):
        try:
            decimal_value = int(failure_code[1:])
            failure_code = f'0x{decimal_value:08X}'
        except ValueError:
            return f"Invalid failure code format: {failure_code}"
    elif failure_code.isdigit():
        try:
            decimal_value = int(failure_code)
            failure_code = f'0x{decimal_value:08X}'
        except ValueError:
            return f"Invalid failure code format: {failure_code}"
    
    failure_code_upper = failure_code.upper()
    failure_code_lower = failure_code.lower()
    
    if failure_code_upper in WINDOWS_LOGON_FAILURE_CODES:
        readable_reason = WINDOWS_LOGON_FAILURE_CODES[failure_code_upper]
        return f"{readable_reason} ({failure_code_upper})"
    elif failure_code_lower in WINDOWS_LOGON_FAILURE_CODES:
        readable_reason = WINDOWS_LOGON_FAILURE_CODES[failure_code_lower]
        return f"{readable_reason} ({failure_code_lower})"
    
    return f"Unmapped failure code: {failure_code_upper}"

# ===================================================================
#                    DATABASE INGESTION CLASS - FIXED
# ===================================================================

class DatabaseIngestion:
    """FIXED DatabaseIngestion with proper network metrics handling."""
    
    def __init__(self, config: dict):
        self.config = config
        db_config = config.get('database', {})
        
        self.server = db_config.get('server', 'localhost')
        self.database = db_config.get('database', 'EdgeMonitoring')
        self.port = db_config.get('port', 1433)
        self.auth_method = db_config.get('authentication', 'sql').lower()
        
        sql_creds = db_config.get('sql_credentials', {})
        self.username = sql_creds.get('username', '')
        self.password = sql_creds.get('password', '')
        
        self.timeout = db_config.get('timeout_seconds', 30)
        self.batch_size = db_config.get('batch_size', 100)
        self.max_retries = db_config.get('max_retries', 3)
        self.create_tables = db_config.get('create_tables_if_not_exist', True)
        
        self.metric_buffers = {
            'ApplicationMetrics': [],
            'SecurityEvents': [],
            'NetworkMetrics': [],
            'CertificateMetrics': [],
            'VulnerabilityFindings': []
        }
        self.buffer_lock = threading.Lock()
        self.max_buffer_size = {
            'ApplicationMetrics': 200,
            'SecurityEvents': 500,
            'NetworkMetrics': 300,
            'CertificateMetrics': 100,
            'VulnerabilityFindings': 100
        }
        
        self.connection_string = self._build_connection_string()
        
        print(f"[Database] Initialized SQL Server integration")
        print(f"[Database] Server: {self.server}:{self.port}")
        print(f"[Database] Database: {self.database}")
        print(f"[Database] Authentication: {self.auth_method}")
        
        if self.create_tables:
            self._initialize_database()
    
    def _build_connection_string(self) -> str:
        """Build SQL Server connection string."""
        driver = "{ODBC Driver 17 for SQL Server}"
        
        drivers = [x for x in pyodbc.drivers() if 'SQL Server' in x]
        if drivers:
            driver = f"{{{drivers[0]}}}"
        
        if self.auth_method == 'windows':
            conn_str = (
                f"DRIVER={driver};"
                f"SERVER={self.server},{self.port};"
                f"DATABASE={self.database};"
                f"Trusted_Connection=yes;"
                f"Connection Timeout={self.timeout};"
            )
        else:
            conn_str = (
                f"DRIVER={driver};"
                f"SERVER={self.server},{self.port};"
                f"DATABASE={self.database};"
                f"UID={self.username};"
                f"PWD={self.password};"
                f"Connection Timeout={self.timeout};"
            )
        
        return conn_str
    
    def _get_connection(self):
        """Get database connection with retry logic."""
        for attempt in range(self.max_retries):
            try:
                conn = pyodbc.connect(self.connection_string)
                return conn
            except Exception as e:
                if attempt < self.max_retries - 1:
                    wait_time = 2 ** attempt
                    with PRINT_LOCK:
                        print(f"[Database] Connection attempt {attempt + 1} failed, retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise
        return None
    
    def _initialize_database(self):
        """Create all database tables."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            self._create_application_metrics_table(cursor)
            self._create_security_events_table(cursor)
            self._create_network_metrics_table(cursor)
            self._create_certificate_metrics_table(cursor)
            self._create_vulnerability_findings_table(cursor)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            with PRINT_LOCK:
                print(f"[Database] ✅ All tables initialized successfully")
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Database] ❌ Error initializing database: {e}")
    
    def _create_application_metrics_table(self, cursor):
        """Create ApplicationMetrics table."""
        create_sql = """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'ApplicationMetrics')
        BEGIN
            CREATE TABLE ApplicationMetrics (
                MetricID BIGINT IDENTITY(1,1) PRIMARY KEY,
                Timestamp DATETIME2 NOT NULL,
                MonitoringHost NVARCHAR(255) NOT NULL,
                MonitoringHostIP NVARCHAR(50),
                
                -- Application-specific columns
                ApplicationName NVARCHAR(255) NOT NULL,
                URL NVARCHAR(1000),
                ResponseTimeMS FLOAT,
                StatusCode INT,
                Availability BIT,
                DNSTimeMS FLOAT,
                ConnectTimeMS FLOAT,
                TLSTimeMS FLOAT,
                FirstByteTimeMS FLOAT,
                
                -- Status
                Status NVARCHAR(100),
                Severity NVARCHAR(50),
                Criticality NVARCHAR(50),
                ErrorMessage NVARCHAR(MAX),
                
                -- Optimized indexes
                -- Indexes
                INDEX IX_App_Timestamp NONCLUSTERED (Timestamp DESC),
                INDEX IX_App_Name_Time NONCLUSTERED (ApplicationName, Timestamp DESC),
                INDEX IX_App_Availability NONCLUSTERED (ApplicationName, Availability, Timestamp DESC)
            );
        END
        """
        cursor.execute(create_sql)
    
    def _create_security_events_table(self, cursor):
        """Create SecurityEvents table."""
        create_sql = """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'SecurityEvents')
        BEGIN
            CREATE TABLE SecurityEvents (
                EventID BIGINT IDENTITY(1,1) PRIMARY KEY,
                Timestamp DATETIME2 NOT NULL,
                MonitoringHost NVARCHAR(255) NOT NULL,
                EventType NVARCHAR(100) NOT NULL,
                WindowsEventID NVARCHAR(50),
                SourceHost NVARCHAR(255),
                SourceIP NVARCHAR(50),
                DestinationIP NVARCHAR(50),
                UserName NVARCHAR(255),
                TargetUser NVARCHAR(255),
                LogonType NVARCHAR(50),
                FailureReason NVARCHAR(500),
                ThreatName NVARCHAR(500),
                ThreatAction NVARCHAR(100),
                Protocol NVARCHAR(50),
                SourcePort INT,
                DestinationPort INT,
                Direction NVARCHAR(20),
                Severity NVARCHAR(50),
                AdditionalData NVARCHAR(MAX),
                INDEX IX_Sec_Timestamp NONCLUSTERED (Timestamp DESC),
                INDEX IX_Sec_EventType_Time NONCLUSTERED (EventType, Timestamp DESC),
                INDEX IX_Sec_SourceIP NONCLUSTERED (SourceIP, Timestamp DESC),
                INDEX IX_Sec_User NONCLUSTERED (UserName, Timestamp DESC),
                INDEX IX_Sec_ThreatName NONCLUSTERED (ThreatName, Timestamp DESC)
            );
        END
        """
        cursor.execute(create_sql)
    
    def _create_network_metrics_table(self, cursor):
        """Create NetworkMetrics table."""
        create_sql = """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'NetworkMetrics')
        BEGIN
            CREATE TABLE NetworkMetrics (
                MetricID BIGINT IDENTITY(1,1) PRIMARY KEY,
                Timestamp DATETIME2 NOT NULL,
                MonitoringHost NVARCHAR(255) NOT NULL,
                
                -- Network-specific columns
                MetricType NVARCHAR(100) NOT NULL,
                InterfaceName NVARCHAR(255),
                TargetHost NVARCHAR(255),
                TargetIP NVARCHAR(50),
                
                -- Measurement values
                LatencyMS FLOAT,
                PacketLossPct FLOAT,
                ThroughputMbps FLOAT,
                DNSResolutionMS FLOAT,
                JitterMS FLOAT,
                
                -- Throughput breakdown
                ThroughputSentMbps FLOAT,
                ThroughputReceivedMbps FLOAT,
                
                Direction NVARCHAR(20),
                
                Severity NVARCHAR(50),
                Status NVARCHAR(100),
                
                -- Optimized indexes
                -- Indexes
                INDEX IX_Net_Timestamp NONCLUSTERED (Timestamp DESC),
                INDEX IX_Net_MetricType_Time NONCLUSTERED (MetricType, Timestamp DESC),
                INDEX IX_Net_Interface_Time NONCLUSTERED (InterfaceName, Timestamp DESC),
                INDEX IX_Net_Target_Time NONCLUSTERED (TargetHost, Timestamp DESC)
            );
        END
        """
        cursor.execute(create_sql)
    
    def _create_certificate_metrics_table(self, cursor):
        """Create CertificateMetrics table."""
        create_sql = """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'CertificateMetrics')
        BEGIN
            CREATE TABLE CertificateMetrics (
                CertID BIGINT IDENTITY(1,1) PRIMARY KEY,
                Timestamp DATETIME2 NOT NULL,
                MonitoringHost NVARCHAR(255) NOT NULL,
                
                -- Certificate-specific columns
                Hostname NVARCHAR(255) NOT NULL,
                Port INT DEFAULT 443,
                
                DaysUntilExpiry INT,
                ExpiryDate DATETIME2,
                IssueDate DATETIME2,
                
                Issuer NVARCHAR(500),
                Subject NVARCHAR(500),
                IsSelfSigned BIT,
                HasHostnameMismatch BIT,
                
                -- Certificate validation
                IsValid BIT,
                ValidationError NVARCHAR(MAX),
                
                -- TLS/SSL details
                TLSVersion NVARCHAR(50),
                CipherSuite NVARCHAR(255),
                HasWeakProtocol BIT,
                HasWeakCipher BIT,
                
                Severity NVARCHAR(50),
                Status NVARCHAR(100),
                
                -- Optimized indexes
                -- Indexes
                INDEX IX_Cert_Hostname NONCLUSTERED (Hostname, Timestamp DESC),
                INDEX IX_Cert_Expiry NONCLUSTERED (DaysUntilExpiry, Timestamp DESC),
                INDEX IX_Cert_Severity NONCLUSTERED (Severity, DaysUntilExpiry)
            );
        END
        """
        cursor.execute(create_sql)
    
    def _create_vulnerability_findings_table(self, cursor):
        """Create VulnerabilityFindings table."""
        create_sql = """
        IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'VulnerabilityFindings')
        BEGIN
            CREATE TABLE VulnerabilityFindings (
                FindingID BIGINT IDENTITY(1,1) PRIMARY KEY,
                ScanTimestamp DATETIME2 NOT NULL,
                MonitoringHost NVARCHAR(255) NOT NULL,
                
                -- Vulnerability-specific columns
                TargetName NVARCHAR(255) NOT NULL,
                TargetHostname NVARCHAR(255),
                TargetIP NVARCHAR(50),
                
                FindingType NVARCHAR(100) NOT NULL,
                Severity NVARCHAR(50) NOT NULL,
                
                -- Finding details
                Description NVARCHAR(MAX),
                Recommendation NVARCHAR(MAX),
                
                -- Type-specific details
                Port INT,
                Protocol NVARCHAR(50),
                CipherSuite NVARCHAR(255),
                TLSProtocol NVARCHAR(50),
                MissingHeader NVARCHAR(255),
                
                -- Risk scoring
                RiskScore INT,
                CVSSScore FLOAT,
                
                -- Optimized indexes
                INDEX IX_Vuln_Timestamp NONCLUSTERED (ScanTimestamp DESC),
                INDEX IX_Vuln_Target_Time NONCLUSTERED (TargetName, ScanTimestamp DESC),
                INDEX IX_Vuln_Severity NONCLUSTERED (Severity, ScanTimestamp DESC),
                INDEX IX_Vuln_Type NONCLUSTERED (FindingType, Severity, ScanTimestamp DESC)
            );
        END
        """
        cursor.execute(create_sql)
        print(f"[Database] VulnerabilityFindings table ready")

    def add_metric(self, metric: dict):
        """✅ FIXED: Route ALL metric types to appropriate tables."""
        metric_name = metric.get('metric', '')
        
        # Application metrics
        if metric_name.startswith('application.'):
            table_name = 'ApplicationMetrics'
        
        # Certificate metrics
        elif 'certificate' in metric_name or 'cert.' in metric_name:
            table_name = 'CertificateMetrics'
        
        # Vulnerability metrics
        elif 'vulnerability' in metric_name or 'vuln' in metric_name:
            table_name = 'VulnerabilityFindings'
        
        # Security events (individual events, not aggregates)
        elif metric_name.startswith('security.') and 'mfa' not in metric_name:
            table_name = 'SecurityEvents'
        
        # ✅ NEW: Infrastructure metrics (goes to NetworkMetrics)
        elif metric_name.startswith('infrastructure.'):
            table_name = 'NetworkMetrics'
        
        # ✅ NEW: WAN metrics (goes to NetworkMetrics)
        elif metric_name.startswith('wan.'):
            table_name = 'NetworkMetrics'
        
        # ✅ NEW: MFA health metrics (goes to NetworkMetrics as aggregate data)
        elif 'mfa' in metric_name:
            table_name = 'NetworkMetrics'
        
        # Network metrics (catch-all for other network metrics)
        elif (metric_name.startswith('network.') or 
              'latency' in metric_name or 
              'packet_loss' in metric_name or 
              'throughput' in metric_name or
              'dns' in metric_name or
              'jitter' in metric_name):
            table_name = 'NetworkMetrics'
        
        # Audit metrics - skip (don't store)
        elif metric_name.startswith('audit.'):
            return
        
        else:
            # ✅ Log unknown metrics for debugging
            with PRINT_LOCK:
                print(f"[Database] ⚠️ Unknown metric type: {metric_name}")
            return
        
        # Add to buffer
        with self.buffer_lock:
            max_size = self.max_buffer_size.get(table_name, self.batch_size)
            if len(self.metric_buffers[table_name]) >= max_size:
                self._flush_table_unlocked(table_name)
            
            self.metric_buffers[table_name].append(metric)

    # ✅ CORRECTED: These methods should be at the SAME LEVEL as add_metric, not nested inside it
    def flush(self):
        """Flush all buffers."""
        with self.buffer_lock:
            for table_name in self.metric_buffers.keys():
                if self.metric_buffers[table_name]:
                    self._flush_table_unlocked(table_name)

    def add_metrics(self, metrics: list):
        """Add multiple metrics."""
        for metric in metrics:
            self.add_metric(metric)
        
        def _flush_table(self, table_name: str):
            """Flush metrics to specific table - ALWAYS clears buffer to prevent accumulation."""
            with self.buffer_lock:
                metrics = self.metric_buffers[table_name][:]
                # CRITICAL: Clear buffer immediately to prevent memory accumulation
                self.metric_buffers[table_name] = []
            
            if not metrics:
                return
            
            try:
                # Display metrics summary
                self._display_metrics_summary(table_name, metrics)
                
                conn = self._get_connection()
                cursor = conn.cursor()
                
                # Route to appropriate insert method with batching
                if table_name == 'ApplicationMetrics':
                    self._insert_application_metrics_batched(cursor, metrics)
                elif table_name == 'SecurityEvents':
                    self._insert_security_events_batched(cursor, metrics)
                elif table_name == 'NetworkMetrics':
                    self._insert_network_metrics_batched(cursor, metrics)
                elif table_name == 'CertificateMetrics':
                    self._insert_certificate_metrics_batched(cursor, metrics)
                elif table_name == 'VulnerabilityFindings':
                    self._insert_vulnerability_findings_batched(cursor, metrics)
                
                conn.commit()
                cursor.close()
                conn.close()
                
                with PRINT_LOCK:
                    print(f"[Database] ✅ Sent {len(metrics)} metrics to {table_name}")
            
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] ❌ Error flushing to {table_name}: {e}")
                    print(f"[Database] Lost {len(metrics)} metrics (buffer cleared to prevent overflow)")
    
    def _flush_table_unlocked(self, table_name: str):
        """Internal flush."""
        metrics = self.metric_buffers[table_name][:]
        self.metric_buffers[table_name] = []
        
        if not metrics:
            return
        
        try:
            self._display_metrics_summary(table_name, metrics)
            
            conn = self._get_connection()
            cursor = conn.cursor()
            
            if table_name == 'ApplicationMetrics':
                self._insert_application_metrics_batched(cursor, metrics)
            elif table_name == 'SecurityEvents':
                self._insert_security_events_batched(cursor, metrics)
            elif table_name == 'NetworkMetrics':
                self._insert_network_metrics_batched(cursor, metrics)
            elif table_name == 'CertificateMetrics':
                self._insert_certificate_metrics_batched(cursor, metrics)
            elif table_name == 'VulnerabilityFindings':
                self._insert_vulnerability_findings_batched(cursor, metrics)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            with PRINT_LOCK:
                print(f"[Database] ✅ Sent {len(metrics)} metrics to {table_name}")
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Database] ❌ Error flushing to {table_name}: {e}")
                traceback.print_exc()
    
    def _display_metrics_summary(self, table_name: str, metrics: list):
        """Display summary of metrics."""
        if not metrics:
            return
        
        with PRINT_LOCK:
            print(f"\n{'='*70}")
            print(f"📊 {table_name.upper()} - {len(metrics)} metrics")
            print(f"{'='*70}")
            
            for i, metric in enumerate(metrics[:5]):
                metric_name = metric.get('metric', 'unknown')
                value = metric.get('value', 0)
                dims = metric.get('dimensions', {})
                
                key_dims = {}
                if 'application' in dims:
                    key_dims['app'] = dims['application']
                if 'target' in dims:
                    key_dims['target'] = dims['target']
                if 'target_host' in dims:
                    key_dims['target_host'] = dims['target_host']
                if 'interface' in dims:
                    key_dims['interface'] = dims['interface']
                
                dim_str = ", ".join([f"{k}={v}" for k, v in key_dims.items()])
                print(f"  └─ {metric_name}: {value} | {dim_str}")
            
            if len(metrics) > 5:
                print(f"  └─ ... and {len(metrics) - 5} more")
            print()
    
    # ============================================================================
    # NETWORK METRICS INSERT - COMPLETELY REWRITTEN & FIXED
    # ============================================================================
    
    def _insert_network_metrics(self, cursor, metrics: List[dict]):
        """
        FIXED: Insert network metrics with COMPLETE field population.
        Consolidates metrics per target/timestamp to eliminate NULL values.
        """
        sql = """
        INSERT INTO NetworkMetrics (
            Timestamp, MonitoringHost, MetricType,
            InterfaceName, TargetHost, TargetIP,
            LatencyMS, PacketLossPct, ThroughputMbps, DNSResolutionMS, JitterMS,
            ThroughputSentMbps, ThroughputReceivedMbps,
            Direction, Severity, Status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        # STEP 1: Consolidate metrics by target and timestamp
        consolidated_metrics = {}
        
        for metric in metrics:
            try:
                timestamp = metric.get('timestamp', time.time() * 1000)
                dimensions = metric.get('dimensions', {})
                metric_name = metric.get('metric', '')
                
                app_name = dimensions.get('application', dimensions.get('app', 'Unknown'))
                url = dimensions.get('url', '')
                
                key = app_name
                
                if key not in consolidated_metrics:
                    consolidated_metrics[key] = {
                        'timestamp': datetime.fromtimestamp(timestamp / 1000),
                        'monitoring_host': MONITORING_HOST_NAME,
                        'monitoring_host_ip': MONITORING_HOST_IP,
                        'application_name': app_name,
                        'url': url,
                        'response_time': None,
                        'status_code': None,
                        'availability': None,
                        'dns_time': None,
                        'connect_time': None,
                        'tls_time': None,
                        'first_byte_time': None,
                        'status': 'unknown',
                        'severity': 'unknown',
                        'criticality': dimensions.get('criticality', 'unknown'),
                        'error_message': None
                    }
                
                value = metric.get('value')
                
                # Response time
                if 'response_time' in metric_name:
                    consolidated_metrics[key]['response_time'] = float(value)
                    consolidated_metrics[key]['status'] = dimensions.get('status', 'healthy')
                    consolidated_metrics[key]['severity'] = dimensions.get('severity', 'low')
                    
                    # Extract timing breakdown from dimensions
                    if 'dns_time' in dimensions:
                        try:
                            consolidated_metrics[key]['dns_time'] = float(dimensions['dns_time'])
                        except:
                            pass
                    
                    if 'connect_time' in dimensions:
                        try:
                            consolidated_metrics[key]['connect_time'] = float(dimensions['connect_time'])
                        except:
                            pass
                    
                    if 'tls_time' in dimensions:
                        try:
                            consolidated_metrics[key]['tls_time'] = float(dimensions['tls_time'])
                        except:
                            pass
                    
                    if 'first_byte_time' in dimensions:
                        try:
                            consolidated_metrics[key]['first_byte_time'] = float(dimensions['first_byte_time'])
                        except:
                            pass
                
                # Availability
                elif 'availability' in metric_name:
                    consolidated_metrics[key]['availability'] = 1 if value == 1 else 0
                    if value == 0:
                        consolidated_metrics[key]['status'] = 'unhealthy'
                        consolidated_metrics[key]['severity'] = 'high'
                    else:
                        consolidated_metrics[key]['status'] = 'healthy'
                
                # Status code
                elif 'status_code' in metric_name:
                    consolidated_metrics[key]['status_code'] = int(value)
                
                # Capture status code from dimensions too
                if 'status_code' in dimensions:
                    try:
                        consolidated_metrics[key]['status_code'] = int(dimensions['status_code'])
                    except:
                        pass
                
                # Enhanced error handling
                if 'error' in dimensions and dimensions['error']:
                    error_msg = str(dimensions['error'])
                    consolidated_metrics[key]['error_message'] = error_msg[:4000]
                    consolidated_metrics[key]['status'] = 'error'
                    consolidated_metrics[key]['severity'] = 'critical'
                    
                    # Set meaningful values for failures
                    if consolidated_metrics[key]['response_time'] is None:
                        consolidated_metrics[key]['response_time'] = 30000.0
                    if consolidated_metrics[key]['status_code'] is None:
                        consolidated_metrics[key]['status_code'] = 0
                    consolidated_metrics[key]['availability'] = 0
                    
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Skipping application metric due to error: {e}")
                continue
        # STEP 3: Convert consolidated entries to batch data
        batch_data = []
        for metric_data in consolidated_metrics.values():
            if metric_data.get('status') == 'error':
                # For failed applications
                response_time = metric_data.get('response_time', 30000.0)
                dns_time = metric_data.get('dns_time', 30000.0)
                connect_time = metric_data.get('connect_time', 0)
                tls_time = metric_data.get('tls_time', 0)
                first_byte_time = metric_data.get('first_byte_time', 0)
                
                # Ensure error message is set
                error_msg = metric_data.get('error_message')
                if not error_msg:
                    if dns_time >= 30000.0:
                        error_msg = "DNS resolution failed - hostname not found"
                    elif response_time >= 30000.0:
                        error_msg = "Connection timeout or network unreachable"
                    else:
                        error_msg = "Application health check failed"
            else:
                # For successful applications - CONSISTENT MESSAGE FORMAT
                response_time = metric_data.get('response_time', 0) or 0
                dns_time = max(0, metric_data.get('dns_time', 0) or 0)
                connect_time = max(0, metric_data.get('connect_time', 0) or 0)
                tls_time = max(0, metric_data.get('tls_time', 0) or 0)
                first_byte_time = max(0, metric_data.get('first_byte_time', 0) or 0)
                
                # FIXED: Simple, consistent success message
                error_msg = "Healthy"
            
            # Final validation and formatting
            if error_msg:
                error_msg = error_msg.strip()
                if len(error_msg) > 4000:
                    error_msg = error_msg[:3997] + "..."
            
            batch_data.append((
                metric_data['timestamp'],
                metric_data['monitoring_host'],
                metric_data['monitoring_host_ip'],
                metric_data['application_name'],
                metric_data['url'],
                response_time,
                metric_data['status_code'],
                metric_data['availability'],
                dns_time,
                connect_time,
                tls_time,
                first_byte_time,
                metric_data['status'],
                metric_data['severity'],
                metric_data['criticality'],
                error_msg  # Now always contains meaningful text, never NULL
            ))
        
        if batch_data:
            try:
                cursor.fast_executemany = True
                cursor.executemany(sql, batch_data)
                with PRINT_LOCK:
                    print(f"[Database] ✅ Inserted {len(batch_data)} application metrics")
                    # Show message summary
                    success_count = sum(1 for row in batch_data if row[12] != 'error')
                    error_count = sum(1 for row in batch_data if row[12] == 'error')
                    print(f"[Database]   📊 Summary: {success_count} successful, {error_count} with errors")
            except Exception as e:
                # If batch fails, try one by one
                with PRINT_LOCK:
                    print(f"[Database] Batch insert failed: {e}")
                    print(f"[Database] Attempting individual inserts...")
                
                success_count = 0
                for row in batch_data:
                    try:
                        cursor.execute(sql, row)
                        success_count += 1
                    except Exception as row_error:
                        with PRINT_LOCK:
                            print(f"[Database] Failed to insert row for {row[3]}: {row_error}")
                
                with PRINT_LOCK:
                    print(f"[Database] Individual inserts: {success_count}/{len(batch_data)} successful")
    
    def _insert_network_metrics_batched(self, cursor, metrics: List[dict]):
        """Insert network metrics in batches."""
        BATCH_SIZE = 100
        for i in range(0, len(metrics), BATCH_SIZE):
            batch = metrics[i:i+BATCH_SIZE]
            try:
                self._insert_network_metrics(cursor, batch)
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Network batch {i} failed: {e}")
    
    # ============================================================================
    # APPLICATION METRICS INSERT
    # ============================================================================
    
    def _insert_application_metrics(self, cursor, metrics: List[dict]):
        """
        ✅ FIXED: Insert consolidated application metrics with UNIQUE KEY per application.
        Ensures ALL applications are collected, not just the last one.
        """
        sql = """
        INSERT INTO ApplicationMetrics (
            Timestamp, MonitoringHost, MonitoringHostIP,
            ApplicationName, URL, ResponseTimeMS, StatusCode, Availability,
            DNSTimeMS, ConnectTimeMS, TLSTimeMS, FirstByteTimeMS,
            Status, Severity, Criticality, ErrorMessage
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        consolidated_metrics = {}
        
        for metric in metrics:
            try:
                timestamp = metric.get('timestamp', time.time() * 1000)
                dimensions = metric.get('dimensions', {})
                metric_name = metric.get('metric', '')
                
                app_name = dimensions.get('application', dimensions.get('app', 'Unknown'))
                url = dimensions.get('url', '')
                
                # ✅ FIX: Use app_name + URL as unique key
                # This ensures different applications don't overwrite each other
                # Even if they have the same name, URL makes it unique
                key = (app_name, url)  # ← FIXED: Tuple key instead of just app_name
                
                if key not in consolidated_metrics:
                    consolidated_metrics[key] = {
                        'timestamp': datetime.fromtimestamp(timestamp / 1000),
                        'monitoring_host': MONITORING_HOST_NAME,
                        'monitoring_host_ip': MONITORING_HOST_IP,
                        'application_name': app_name,
                        'url': url,
                        'response_time': None,
                        'status_code': None,
                        'availability': None,
                        'dns_time': None,
                        'connect_time': None,
                        'tls_time': None,
                        'first_byte_time': None,
                        'status': 'unknown',
                        'severity': 'unknown',
                        'criticality': dimensions.get('criticality', 'unknown'),
                        'error_message': None
                    }
                
                value = metric.get('value')
                
                # Response time
                if 'response_time' in metric_name:
                    consolidated_metrics[key]['response_time'] = float(value)
                    consolidated_metrics[key]['status'] = dimensions.get('status', 'healthy')
                    consolidated_metrics[key]['severity'] = dimensions.get('severity', 'low')
                    
                    # Extract timing breakdown from dimensions
                    if 'dns_time' in dimensions:
                        try:
                            consolidated_metrics[key]['dns_time'] = float(dimensions['dns_time'])
                        except:
                            pass
                    
                    if 'connect_time' in dimensions:
                        try:
                            consolidated_metrics[key]['connect_time'] = float(dimensions['connect_time'])
                        except:
                            pass
                    
                    if 'tls_time' in dimensions:
                        try:
                            consolidated_metrics[key]['tls_time'] = float(dimensions['tls_time'])
                        except:
                            pass
                    
                    if 'first_byte_time' in dimensions:
                        try:
                            consolidated_metrics[key]['first_byte_time'] = float(dimensions['first_byte_time'])
                        except:
                            pass
                
                # Availability
                elif 'availability' in metric_name:
                    consolidated_metrics[key]['availability'] = 1 if value == 1 else 0
                    if value == 0:
                        consolidated_metrics[key]['status'] = 'unhealthy'
                        consolidated_metrics[key]['severity'] = 'high'
                    else:
                        consolidated_metrics[key]['status'] = 'healthy'
                
                # Status code
                elif 'status_code' in metric_name:
                    consolidated_metrics[key]['status_code'] = int(value)
                
                # Capture status code from dimensions too
                if 'status_code' in dimensions:
                    try:
                        consolidated_metrics[key]['status_code'] = int(dimensions['status_code'])
                    except:
                        pass
                
                # Enhanced error handling
                if 'error' in dimensions and dimensions['error']:
                    error_msg = str(dimensions['error'])
                    consolidated_metrics[key]['error_message'] = error_msg[:4000]
                    consolidated_metrics[key]['status'] = 'error'
                    consolidated_metrics[key]['severity'] = 'critical'
                    
                    # Set meaningful values for failures
                    if consolidated_metrics[key]['response_time'] is None:
                        consolidated_metrics[key]['response_time'] = 30000.0
                    if consolidated_metrics[key]['status_code'] is None:
                        consolidated_metrics[key]['status_code'] = 0
                    consolidated_metrics[key]['availability'] = 0
                    
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Skipping application metric due to error: {e}")
                continue
        
        # Convert consolidated entries to batch data
        batch_data = []
        for metric_data in consolidated_metrics.values():
            if metric_data.get('status') == 'error':
                # For failed applications
                response_time = metric_data.get('response_time', 30000.0)
                dns_time = metric_data.get('dns_time', 30000.0)
                connect_time = metric_data.get('connect_time', 0)
                tls_time = metric_data.get('tls_time', 0)
                first_byte_time = metric_data.get('first_byte_time', 0)
                
                # Ensure error message is set
                error_msg = metric_data.get('error_message')
                if not error_msg:
                    if dns_time >= 30000.0:
                        error_msg = "DNS resolution failed - hostname not found"
                    elif response_time >= 30000.0:
                        error_msg = "Connection timeout or network unreachable"
                    else:
                        error_msg = "Application health check failed"
            else:
                # For successful applications - CONSISTENT MESSAGE FORMAT
                response_time = metric_data.get('response_time', 0) or 0
                dns_time = max(0, metric_data.get('dns_time', 0) or 0)
                connect_time = max(0, metric_data.get('connect_time', 0) or 0)
                tls_time = max(0, metric_data.get('tls_time', 0) or 0)
                first_byte_time = max(0, metric_data.get('first_byte_time', 0) or 0)
                
                # FIXED: Simple, consistent success message
                error_msg = "Healthy"
            
            # Final validation and formatting
            if error_msg:
                error_msg = error_msg.strip()
                if len(error_msg) > 4000:
                    error_msg = error_msg[:3997] + "..."
            
            batch_data.append((
                metric_data['timestamp'],
                metric_data['monitoring_host'],
                metric_data['monitoring_host_ip'],
                metric_data['application_name'],
                metric_data['url'],
                response_time,
                metric_data['status_code'],
                metric_data['availability'],
                dns_time,
                connect_time,
                tls_time,
                first_byte_time,
                metric_data['status'],
                metric_data['severity'],
                metric_data['criticality'],
                error_msg
            ))
        
        if batch_data:
            try:
                cursor.fast_executemany = True
                cursor.executemany(sql, batch_data)
                with PRINT_LOCK:
                    print(f"[Database] ✅ Inserted {len(batch_data)} application metrics")
                    # Show breakdown of which apps were inserted
                    app_names = [row[3] for row in batch_data]
                    print(f"[Database]   📊 Applications: {', '.join(set(app_names))}")
                    # Show message summary
                    success_count = sum(1 for row in batch_data if row[12] != 'error')
                    error_count = sum(1 for row in batch_data if row[12] == 'error')
                    print(f"[Database]   📊 Summary: {success_count} successful, {error_count} with errors")
            except Exception as e:
                # If batch fails, try one by one
                with PRINT_LOCK:
                    print(f"[Database] Batch insert failed: {e}")
                    print(f"[Database] Attempting individual inserts...")
                
                success_count = 0
                for row in batch_data:
                    try:
                        cursor.execute(sql, row)
                        success_count += 1
                    except Exception as row_error:
                        with PRINT_LOCK:
                            print(f"[Database] Failed to insert row for {row[3]}: {row_error}")
                
                with PRINT_LOCK:
                    print(f"[Database] Individual inserts: {success_count}/{len(batch_data)} successful")
    
    def _insert_application_metrics_batched(self, cursor, metrics: List[dict]):
        """Insert application metrics in batches."""
        BATCH_SIZE = 50
        for i in range(0, len(metrics), BATCH_SIZE):
            batch = metrics[i:i+BATCH_SIZE]
            try:
                self._insert_application_metrics(cursor, batch)
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: App batch failed: {e}")
    
    # ============================================================================
    # SECURITY EVENTS INSERT
    # ============================================================================
    
    def _insert_security_events(self, cursor, metrics: List[dict]):
        """Insert security events."""
        sql = """
        INSERT INTO SecurityEvents (
            Timestamp, MonitoringHost, EventType, WindowsEventID,
            SourceHost, SourceIP, DestinationIP,
            UserName, TargetUser, LogonType, FailureReason,
            ThreatName, ThreatAction,
            Protocol, SourcePort, DestinationPort, Direction,
            Severity, AdditionalData
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        batch_data = []
        for metric in metrics:
            try:
                timestamp = datetime.fromtimestamp(metric.get('timestamp', time.time() * 1000) / 1000)
                dimensions = metric.get('dimensions', {})
                metric_name = metric.get('metric', '')
                
                # ✅ FIXED: Extract event type from metric name
                # Metric names are like: "security.credential_validation_success"
                # We want: "credential_validation_success"
                if 'failed_logon' in metric_name or 'unauthorized' in metric_name:
                    event_type = 'failed_logon'  # FIXED: was 'firewall_drop'
                elif 'successful_logon' in metric_name:
                    event_type = 'successful_logon'
                elif 'firewall' in metric_name or 'drop' in metric_name:
                    event_type = 'firewall_drop'
                elif 'threat' in metric_name or 'malware' in metric_name or 'endpoint_threat' in metric_name:
                    event_type = 'threat_detected'
                elif 'mfa' in metric_name or 'credential_validation' in metric_name:
                    event_type = 'credential_validation'
                elif 'account_created' in metric_name:
                    event_type = 'account_created'
                elif 'account_enabled' in metric_name:
                    event_type = 'account_enabled'
                elif 'account_disabled' in metric_name:
                    event_type = 'account_disabled'
                elif 'account_deleted' in metric_name:
                    event_type = 'account_deleted'
                elif 'account_changed' in metric_name:
                    event_type = 'account_changed'
                elif 'password_change' in metric_name:
                    event_type = 'password_change'
                elif 'password_reset' in metric_name:
                    event_type = 'password_reset'
                elif 'group_membership' in metric_name:
                    event_type = 'group_membership_change'
                elif 'logoff' in metric_name:
                    event_type = 'logoff'
                elif 'admin_logon' in metric_name or 'privileged_logon' in metric_name:
                    event_type = 'privileged_logon'
                else:
                    event_type = 'security_event'
                
                windows_event_id = dimensions.get('event_id', 'Unknown')
                
                # Extract with multiple fallback keys (handles both snake_case and PascalCase)
                windows_event_id = str(dimensions.get('event_id', 
                                      dimensions.get('EventID', 
                                      dimensions.get('eventId', '')))) or None
                
                # Source information (multiple fallbacks)
                source_host = dimensions.get('source_host', 
                             dimensions.get('SourceHost',
                             dimensions.get('host',
                             dimensions.get('monitoring_host', MONITORING_HOST_NAME))))
                
                source_ip = dimensions.get('source_ip',
                           dimensions.get('SourceIP',
                           dimensions.get('sourceIp',
                           dimensions.get('ip', None))))
                
                dest_ip = dimensions.get('dest_ip',
                         dimensions.get('destination_ip',
                         dimensions.get('target_ip',
                         dimensions.get('DestinationIP',
                         dimensions.get('destinationIp', None)))))
                
                # User information
                user_name = dimensions.get('user',
                           dimensions.get('username',
                           dimensions.get('UserName',
                           dimensions.get('User', None))))
                
                target_user = dimensions.get('target_user',
                             dimensions.get('TargetUser',
                             dimensions.get('targetUser',
                             dimensions.get('TargetUserName', None))))
                
                logon_type = dimensions.get('logon_type',
                            dimensions.get('LogonType',
                            dimensions.get('logonType',
                            dimensions.get('Type', None))))
                
                failure_reason = dimensions.get('failure_reason',
                                dimensions.get('FailureReason',
                                dimensions.get('failureReason',
                                dimensions.get('reason', None))))
                
                # Threat information
                threat_name = dimensions.get('threat_name',
                         dimensions.get('ThreatName',
                         dimensions.get('threatName',
                         dimensions.get('malware',
                         dimensions.get('Malware', None)))))
            
                threat_action = dimensions.get('threat_action',
                           dimensions.get('ThreatAction',
                           dimensions.get('action',
                           dimensions.get('Action', None))))
                # Network information
                protocol = dimensions.get('protocol',
                          dimensions.get('Protocol', None))
                
                # Port numbers with type conversion
                try:
                    source_port = int(dimensions.get('source_port',
                                 dimensions.get('SourcePort',
                                 dimensions.get('sourcePort', 0)))) or None
                except (ValueError, TypeError):
                    source_port = None
                
                try:
                    dest_port = int(dimensions.get('dest_port',
                                dimensions.get('destination_port',
                                dimensions.get('DestinationPort',
                                dimensions.get('destinationPort', 0))))) or None
                except (ValueError, TypeError):
                    dest_port = None
                
                direction = dimensions.get('direction',
                        dimensions.get('Direction', None))
                
                severity = dimensions.get('severity',
                        dimensions.get('Severity', 'medium'))
                
                # ✅ NEW: Store remaining dimensions as JSON in AdditionalData
                excluded_keys = {
                    'event_id', 'EventID', 'eventId', 'source_host', 'SourceHost', 'host',
                    'monitoring_host', 'source_ip', 'SourceIP', 'sourceIp', 'ip', 'dest_ip',
                    'destination_ip', 'target_ip', 'DestinationIP', 'destinationIp', 'user',
                    'username', 'UserName', 'User', 'target_user', 'TargetUser', 'targetUser',
                    'TargetUserName', 'logon_type', 'LogonType', 'logonType', 'Type',
                    'failure_reason', 'FailureReason', 'failureReason', 'reason',
                    'threat_name', 'ThreatName', 'threatName', 'malware', 'Malware',
                    'threat_action', 'ThreatAction', 'action', 'Action', 'protocol',
                    'Protocol', 'source_port', 'SourcePort', 'sourcePort', 'dest_port',
                    'destination_port', 'DestinationPort', 'destinationPort', 'direction',
                    'Direction', 'severity', 'Severity'
                }
                
                # Collect remaining dimensions for AdditionalData
                additional_dims = {k: v for k, v in dimensions.items() if k not in excluded_keys}
                additional_json = json.dumps(additional_dims) if additional_dims else None
                
                batch_data.append((
                    timestamp, MONITORING_HOST_NAME, event_type, windows_event_id,
                    source_host, source_ip, dest_ip,
                    user_name, target_user, logon_type, failure_reason,
                    threat_name, threat_action,
                    protocol, source_port, dest_port, direction,
                    severity, additional_json
                ))
                if threat_name or protocol or source_port:
                    with PRINT_LOCK:
                        print(f"[Database] 📊 Security Event: Type={event_type}, Threat={threat_name}, Protocol={protocol}, Port={source_port}")
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Skipping security metric due to error: {e}")
                continue
        
        if batch_data:
            try:
                cursor.fast_executemany = True
                cursor.executemany(sql, batch_data)
                with PRINT_LOCK:
                    print(f"[Database] ✅ Inserted {len(batch_data)} security events with full details")
                    # Show sample of what was inserted
                    threat_count = sum(1 for row in batch_data if row[11] is not None)
                    firewall_count = sum(1 for row in batch_data if row[13] is not None)
                    print(f"[Database]   📊 {threat_count} threat events, {firewall_count} firewall events")
            except Exception as e:
                # Fallback to individual inserts
                with PRINT_LOCK:
                    print(f"[Database] Security batch insert failed: {e}")
                    print(f"[Database] Attempting individual inserts...")
                
                success_count = 0
                for row in batch_data:
                    try:
                        cursor.execute(sql, row)
                        success_count += 1
                    except Exception as row_error:
                        with PRINT_LOCK:
                            print(f"[Database] Failed security event: {row_error}")
                
                with PRINT_LOCK:
                    print(f"[Database] Individual inserts: {success_count}/{len(batch_data)} successful")

    
    def _insert_security_events_batched(self, cursor, metrics: List[dict]):
        """Insert security events in small batches."""
        BATCH_SIZE = 100
        for i in range(0, len(metrics), BATCH_SIZE):
            batch = metrics[i:i+BATCH_SIZE]
            try:
                self._insert_security_events(cursor, batch)
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Security events batch failed: {e}")

    
    def _insert_network_metrics(self, cursor, metrics: List[dict]):
        """
        ✅ COMPLETELY REWRITTEN: Insert network metrics with FULL debugging and consolidation.
        """
        sql = """
        INSERT INTO NetworkMetrics (
            Timestamp, MonitoringHost, MetricType,
            InterfaceName, TargetHost, TargetIP,
            LatencyMS, PacketLossPct, ThroughputMbps, DNSResolutionMS, JitterMS,
            ThroughputSentMbps, ThroughputReceivedMbps,
            Direction, Severity, Status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        # Debug: Show first few raw metrics
        with PRINT_LOCK:
            print(f"\n[Database] 🔍 DEBUG: Received {len(metrics)} network metrics")
            for i, m in enumerate(metrics[:3]):
                print(f"  Metric {i+1}: {m.get('metric', 'unknown')}")
                print(f"    Dimensions: {m.get('dimensions', {})}")
        
        # Group metrics by (target, rounded_timestamp) for consolidation
        from collections import defaultdict
        consolidated = defaultdict(lambda: {
            'timestamp': None,
            'monitoring_host': MONITORING_HOST_NAME,
            'metric_type': None,
            'interface_name': None,
            'target_host': None,
            'target_ip': None,
            'latency_ms': None,
            'packet_loss_pct': None,
            'throughput_mbps': None,
            'dns_resolution_ms': None,
            'jitter_ms': None,
            'throughput_sent_mbps': None,
            'throughput_received_mbps': None,
            'direction': None,
            'severity': 'unknown',
            'status': 'unknown'
        })
        
        for metric in metrics:
            try:
                timestamp_ms = metric.get('timestamp', time.time() * 1000)
                timestamp_sec = int(timestamp_ms / 1000)
                timestamp = datetime.fromtimestamp(timestamp_sec)
                
                dimensions = metric.get('dimensions', {})
                metric_name = metric.get('metric', '')
                value = float(metric.get('value', 0))
                
                # Extract ALL possible target identifiers
                target_host = (
                    dimensions.get('target_host') or 
                    dimensions.get('target') or 
                    dimensions.get('domain') or 
                    dimensions.get('interface')
                )
                
                # ✅ CRITICAL FIX: Get target_ip from dimensions (Enhanced monitors set this!)
                target_ip = dimensions.get('target_ip')
                
                # If no IP but we have a hostname that looks like an IP, use it
                if not target_ip and target_host:
                    import re
                    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', str(target_host)):
                        target_ip = target_host
                
                # Get interface name
                interface_name = dimensions.get('interface') or dimensions.get('interface_name')
                
                # Create grouping key
                if interface_name:
                    key = (target_host, interface_name, timestamp_sec)
                else:
                    key = (target_host, timestamp_sec)
                
                # Initialize consolidated entry if first time seeing this key
                if consolidated[key]['timestamp'] is None:
                    consolidated[key]['timestamp'] = timestamp
                    consolidated[key]['target_host'] = target_host
                    consolidated[key]['target_ip'] = target_ip  # ✅ Set from dimensions
                    consolidated[key]['interface_name'] = interface_name
                
                # Update target_ip if we got a better value
                if target_ip and not consolidated[key]['target_ip']:
                    consolidated[key]['target_ip'] = target_ip
                
                # Map metric types to fields
                if 'latency' in metric_name and 'jitter' not in metric_name:
                    consolidated[key]['latency_ms'] = value
                    consolidated[key]['metric_type'] = 'latency'
                    consolidated[key]['severity'] = dimensions.get('severity', 'unknown')
                    consolidated[key]['status'] = dimensions.get('status', 'unknown')
                
                elif 'jitter' in metric_name:
                    consolidated[key]['jitter_ms'] = value
                    if not consolidated[key]['metric_type']:
                        consolidated[key]['metric_type'] = 'latency'
                
                elif 'packet_loss' in metric_name:
                    consolidated[key]['packet_loss_pct'] = value
                    if not consolidated[key]['metric_type']:
                        consolidated[key]['metric_type'] = 'packet_loss'
                    consolidated[key]['severity'] = dimensions.get('severity', 'unknown')
                    consolidated[key]['status'] = dimensions.get('status', 'unknown')
                
                elif 'throughput.sent' in metric_name:
                    consolidated[key]['throughput_sent_mbps'] = value
                    consolidated[key]['throughput_mbps'] = value
                    consolidated[key]['metric_type'] = 'throughput'
                    consolidated[key]['direction'] = dimensions.get('direction', 'outbound')
                    consolidated[key]['severity'] = dimensions.get('severity', 'unknown')
                    consolidated[key]['status'] = dimensions.get('status', 'unknown')
                
                elif 'throughput.received' in metric_name:
                    consolidated[key]['throughput_received_mbps'] = value
                    if not consolidated[key]['throughput_mbps']:
                        consolidated[key]['throughput_mbps'] = value
                    if not consolidated[key]['metric_type']:
                        consolidated[key]['metric_type'] = 'throughput'
                    consolidated[key]['direction'] = dimensions.get('direction', 'inbound')
                    consolidated[key]['severity'] = dimensions.get('severity', 'unknown')
                    consolidated[key]['status'] = dimensions.get('status', 'unknown')
                
                elif 'throughput' in metric_name and 'total' in metric_name:
                    consolidated[key]['throughput_mbps'] = value
                    if not consolidated[key]['metric_type']:
                        consolidated[key]['metric_type'] = 'throughput'
                    consolidated[key]['direction'] = dimensions.get('direction', 'bidirectional')
                
                elif 'dns' in metric_name:
                    consolidated[key]['dns_resolution_ms'] = value
                    consolidated[key]['metric_type'] = 'dns_resolution'
                    consolidated[key]['severity'] = dimensions.get('severity', 'unknown')
                    consolidated[key]['status'] = dimensions.get('status', 'unknown')
                
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] ⚠️ Skipping metric: {e}")
                continue
        
        # Debug: Show consolidated data
        with PRINT_LOCK:
            print(f"\n[Database] 📊 Consolidated into {len(consolidated)} rows")
            for i, (key, data) in enumerate(list(consolidated.items())[:3]):
                print(f"  Row {i+1}: Target={data['target_host']}, IP={data['target_ip']}, "
                      f"Latency={data['latency_ms']}, Jitter={data['jitter_ms']}, "
                      f"Direction={data['direction']}")
        
        # Convert to batch data
        batch_data = []
        for metric_data in consolidated.values():
            # Skip empty entries
            if all(v is None for k, v in metric_data.items() 
                   if k not in ['timestamp', 'monitoring_host', 'target_host', 'target_ip', 'severity', 'status']):
                continue
            
            batch_data.append((
                metric_data['timestamp'],
                metric_data['monitoring_host'],
                metric_data['metric_type'] or 'network',
                metric_data['interface_name'],
                metric_data['target_host'],
                metric_data['target_ip'],
                metric_data['latency_ms'],
                metric_data['packet_loss_pct'],
                metric_data['throughput_mbps'],
                metric_data['dns_resolution_ms'],
                metric_data['jitter_ms'],
                metric_data['throughput_sent_mbps'],
                metric_data['throughput_received_mbps'],
                metric_data['direction'],
                metric_data['severity'],
                metric_data['status']
            ))
        
        if batch_data:
            try:
                cursor.fast_executemany = True
                cursor.executemany(sql, batch_data)
                with PRINT_LOCK:
                    print(f"[Database] ✅ Inserted {len(batch_data)} network metrics")
                    
                    # Show sample of what was inserted
                    sample = batch_data[0]
                    print(f"[Database] 📋 Sample inserted row:")
                    print(f"  TargetHost={sample[4]}, TargetIP={sample[5]}")
                    print(f"  LatencyMS={sample[6]}, JitterMS={sample[10]}")
                    print(f"  Direction={sample[13]}, ThroughputSent={sample[11]}, ThroughputRecv={sample[12]}")
                    
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] ❌ Batch insert failed: {e}")
                    print(f"[Database] Attempting individual inserts...")
                
                success_count = 0
                for i, row in enumerate(batch_data):
                    try:
                        cursor.execute(sql, row)
                        success_count += 1
                    except Exception as row_error:
                        with PRINT_LOCK:
                            print(f"[Database] Row {i} failed: {row_error}")
                            print(f"  Data: {row}")
                
                with PRINT_LOCK:
                    print(f"[Database] Individual inserts: {success_count}/{len(batch_data)} successful")
    
    def _insert_network_metrics_batched(self, cursor, metrics: List[dict]):
        """Insert network metrics in small batches."""
        BATCH_SIZE = 100
        for i in range(0, len(metrics), BATCH_SIZE):
            batch = metrics[i:i+BATCH_SIZE]
            try:
                self._insert_network_metrics(cursor, batch)
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Network metrics batch failed: {e}")
    
    def _insert_certificate_metrics(self, cursor, metrics: List[dict]):
        """Insert certificate metrics with FULL certificate details."""
        sql = """
        INSERT INTO CertificateMetrics (
            Timestamp, MonitoringHost, Hostname, Port, DaysUntilExpiry, ExpiryDate,
            IssueDate, Issuer, Subject, IsSelfSigned, HasHostnameMismatch, IsValid,
            ValidationError, TLSVersion, CipherSuite, HasWeakProtocol, HasWeakCipher,
            Severity, Status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        batch_data = []
        for metric in metrics:
            try:
                timestamp = datetime.fromtimestamp(metric.get('timestamp', time.time() * 1000) / 1000)
                dimensions = metric.get('dimensions', {})
                metric_name = metric.get('metric', '')
                value = metric.get('value', 0)
                
                hostname = dimensions.get('hostname', dimensions.get('target', 'unknown'))
                port = dimensions.get('port', 443)  # Get port from dimensions or default to 443
                
                # Extract certificate details from dimensions
                days_until_expiry = dimensions.get('days_until_expiry')
                expiry_date = dimensions.get('expiry_date')
                issue_date = dimensions.get('issue_date')
                issuer = dimensions.get('issuer')
                subject = dimensions.get('subject')
                is_self_signed = dimensions.get('is_self_signed', 0)
                has_hostname_mismatch = dimensions.get('has_hostname_mismatch', 0)
                is_valid = dimensions.get('is_valid', 1 if value == 1 else 0)
                validation_error = dimensions.get('validation_error')
                tls_version = dimensions.get('tls_version')
                cipher_suite = dimensions.get('cipher_suite')
                has_weak_protocol = dimensions.get('has_weak_protocol', 0)
                has_weak_cipher = dimensions.get('has_weak_cipher', 0)
                
                severity = dimensions.get('severity', 'unknown')
                status = dimensions.get('status', 'unknown')
                
                # Convert string dates to datetime objects if provided as strings
                try:
                    if expiry_date and isinstance(expiry_date, str):
                        expiry_date = datetime.fromisoformat(expiry_date.replace('Z', '+00:00'))
                except:
                    expiry_date = None
                    
                try:
                    if issue_date and isinstance(issue_date, str):
                        issue_date = datetime.fromisoformat(issue_date.replace('Z', '+00:00'))
                except:
                    issue_date = None
                
                batch_data.append((
                    timestamp, MONITORING_HOST_NAME, hostname, port, days_until_expiry,
                    expiry_date, issue_date, issuer, subject, is_self_signed,
                    has_hostname_mismatch, is_valid, validation_error, tls_version,
                    cipher_suite, has_weak_protocol, has_weak_cipher, severity, status
                ))
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Skipping certificate metric: {e}")
                continue
        
        if batch_data:
            try:
                cursor.fast_executemany = True
                cursor.executemany(sql, batch_data)
            except Exception as e:
                # Fallback to individual inserts
                with PRINT_LOCK:
                    print(f"[Database] Certificate batch insert failed: {e}")
                    print(f"[Database] Attempting individual inserts...")
                
                success_count = 0
                for row in batch_data:
                    try:
                        cursor.execute(sql, row)
                        success_count += 1
                    except Exception as row_error:
                        with PRINT_LOCK:
                            print(f"[Database] Failed certificate for {row[2]}: {row_error}")
                
                with PRINT_LOCK:
                    print(f"[Database] Individual inserts: {success_count}/{len(batch_data)} successful")

    
    def _insert_certificate_metrics_batched(self, cursor, metrics: List[dict]):
        """Insert certificate metrics in small batches."""
        BATCH_SIZE = 50
        for i in range(0, len(metrics), BATCH_SIZE):
            batch = metrics[i:i+BATCH_SIZE]
            try:
                self._insert_certificate_metrics(cursor, batch)
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Certificate metrics batch failed: {e}")
    
    def _insert_vulnerability_findings(self, cursor, metrics: List[dict]):
        """✅ FIXED: Insert vulnerability findings with ALL FIELDS properly extracted."""
        sql = """
        INSERT INTO VulnerabilityFindings (
            ScanTimestamp, MonitoringHost,
            TargetName, TargetHostname, TargetIP,
            FindingType, Severity,
            Description, Recommendation,
            Port, Protocol, CipherSuite, TLSProtocol, MissingHeader,
            RiskScore, CVSSScore
            -- ✅ REMOVED: IsRemediated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        
        batch_data = []
        for metric in metrics:
            try:
                # Skip summary metrics (only process individual findings)
                metric_name = metric.get('metric', '')
                if 'summary' in metric_name or 'total_score' in metric_name:
                    continue
                
                timestamp = datetime.fromtimestamp(metric.get('timestamp', time.time() * 1000) / 1000)
                dimensions = metric.get('dimensions', {})
                
                # ✅ FIXED: Extract ALL fields with multiple fallback keys
                target_name = dimensions.get('target', 'Unknown')
                
                # Try multiple keys for hostname
                target_hostname = (
                    dimensions.get('target_hostname') or 
                    dimensions.get('hostname') or 
                    dimensions.get('TargetHostname') or
                    None
                )
                
                # Try multiple keys for IP
                target_ip = (
                    dimensions.get('target_ip') or 
                    dimensions.get('TargetIP') or
                    dimensions.get('ip') or
                    None
                )
                
                finding_type = dimensions.get('finding_type', 'general')
                severity = dimensions.get('severity', 'medium')
                
                description = dimensions.get('description', 'No description provided')
                recommendation = dimensions.get('recommendation', 'Review and remediate')
                
                # Extract type-specific fields
                port = None
                if 'port' in dimensions:
                    try:
                        port = int(dimensions['port'])
                    except:
                        pass
                
                protocol = dimensions.get('protocol', None)
                cipher_suite = dimensions.get('cipher_suite', None)
                tls_protocol = dimensions.get('tls_protocol', None)
                missing_header = dimensions.get('missing_header', None)
                
                # ✅ FIXED: Extract or calculate risk score
                risk_score = dimensions.get('risk_score', None)
                if risk_score is None:
                    # Calculate from severity if not provided
                    risk_score_map = {
                        'critical': 10,
                        'high': 7,
                        'medium': 4,
                        'low': 2
                    }
                    risk_score = risk_score_map.get(severity, 5)
                
                # Validate severity
                if severity not in ['critical', 'high', 'medium', 'low']:
                    severity = 'medium'
                
                # Truncate long text fields
                if description and len(description) > 4000:
                    description = description[:3997] + "..."
                if recommendation and len(recommendation) > 4000:
                    recommendation = recommendation[:3997] + "..."
                
                # IsRemediated defaults to 0 (false)
                is_remediated = 0
                
                # ✅ Ensure cipher_suite is never NULL
                cipher_suite_value = cipher_suite if cipher_suite is not None else 'Not applicable'

                batch_data.append((
                    timestamp, MONITORING_HOST_NAME,
                    target_name, target_hostname, target_ip,
                    finding_type, severity,
                    description, recommendation,
                    port, protocol, cipher_suite_value, tls_protocol, missing_header,  # ✅ Use guaranteed value
                    risk_score,
                    dimensions.get('cvss_score', 5.0),
                ))
                
                # ✅ DEBUG: Log what we're inserting
                with PRINT_LOCK:
                    print(f"[VulnInsert] 📝 Preparing: {target_name} | Hostname={target_hostname} | IP={target_ip} | Port={port} | Risk={risk_score}")
                    
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Skipping vulnerability metric: {e}")
                    print(f"[Database] Metric details: {metric}")
                continue
        
        if batch_data:
            try:
                cursor.fast_executemany = True
                cursor.executemany(sql, batch_data)
                with PRINT_LOCK:
                    print(f"[Database] ✅ Inserted {len(batch_data)} vulnerability findings with full details")
                    
                    # Show sample of what was inserted
                    sample = batch_data[0]
                    print(f"[Database] 📋 Sample row:")
                    print(f"  TargetName={sample[2]}, TargetHostname={sample[3]}, TargetIP={sample[4]}")
                    print(f"  Port={sample[9]}, Protocol={sample[10]}, RiskScore={sample[14]}")
                    
            except Exception as e:
                # If batch fails, try one by one with detailed error reporting
                with PRINT_LOCK:
                    print(f"[Database] Batch insert failed: {e}")
                    print(f"[Database] Attempting individual inserts...")
                
                success_count = 0
                for i, row in enumerate(batch_data):
                    try:
                        cursor.execute(sql, row)
                        success_count += 1
                    except Exception as row_error:
                        with PRINT_LOCK:
                            print(f"[Database] Row {i} failed: {row_error}")
                            print(f"  TargetName={row[2]}, TargetHostname={row[3]}, TargetIP={row[4]}")
                            print(f"  Port={row[9]}, Protocol={row[10]}, RiskScore={row[14]}")
                
                with PRINT_LOCK:
                    print(f"[Database] Individual inserts: {success_count}/{len(batch_data)} successful")

    def _insert_vulnerability_findings_batched(self, cursor, metrics: List[dict]):
        """Insert vulnerability findings in small batches."""
        BATCH_SIZE = 30  # Smaller batches for complex data
        for i in range(0, len(metrics), BATCH_SIZE):
            batch = metrics[i:i+BATCH_SIZE]
            try:
                self._insert_vulnerability_findings(cursor, batch)
            except Exception as e:
                with PRINT_LOCK:
                    print(f"[Database] Warning: Vulnerability findings batch failed: {e}")


# ===================================================================
#  ENHANCED NETWORK MONITORING CLASSES - COMPLETE IMPLEMENTATION
# ===================================================================

class EnhancedLatencyMonitor:
    """Enhanced latency monitoring with jitter."""
    
    def __init__(self, config: dict, database: DatabaseIngestion):
        self.config = config
        self.database = database
    
    def measure_latency_with_jitter(self, target: str, target_name: str = None, count: int = 10) -> List[dict]:
        """
        Measure latency AND jitter, return ready-to-insert metrics.
        Returns list of metrics with ALL fields populated.
        """
        metrics = []
        
        if not target_name:
            target_name = target
        
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ['ping', '-n', str(count), target],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', str(count), target],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            # Extract latencies
            if IS_WINDOWS:
                pattern = r'time[=<](\d+)ms'
            else:
                pattern = r'time=(\d+\.?\d*)\s*ms'
            
            matches = re.findall(pattern, result.stdout)
            latencies = [float(m) for m in matches]
            
            if not latencies:
                return metrics
            
            # Calculate statistics
            avg_latency = sum(latencies) / len(latencies)
            min_latency = min(latencies)
            max_latency = max(latencies)
            
            # Calculate jitter
            jitter = 0
            if len(latencies) > 1:
                deviations = [abs(latencies[i] - latencies[i-1]) for i in range(1, len(latencies))]
                jitter = sum(deviations) / len(deviations)
            
            # Get target IP
            try:
                target_ip = socket.gethostbyname(target)
            except:
                target_ip = target
            
            # Determine severity
            if avg_latency > 150:
                severity = 'critical'
                status = 'degraded'
            elif avg_latency > 100:
                severity = 'high'
                status = 'slow'
            elif avg_latency > 50:
                severity = 'medium'
                status = 'acceptable'
            else:
                severity = 'low'
                status = 'healthy'
            
            if jitter > 30:
                severity = 'critical'
                status = 'unstable'
            
            timestamp = int(time.time() * 1000)
            
            base_dims = {
                'monitoring_host': MONITORING_HOST_NAME,
                'target': target_name,
                'target_host': target_name,
                'target_ip': target_ip,
                'metric_type': 'latency',
                'severity': severity,
                'status': status
            }
            
            # Average latency
            metrics.append({
                'metric': 'network.latency.icmp.avg.ms',
                'value': round(avg_latency, 2),
                'dimensions': {**base_dims, 'latency_type': 'average'},
                'timestamp': timestamp
            })
            
            # Jitter
            metrics.append({
                'metric': 'network.latency.jitter.ms',
                'value': round(jitter, 2),
                'dimensions': base_dims,
                'timestamp': timestamp
            })
            
            # Min/Max
            metrics.append({
                'metric': 'network.latency.icmp.min.ms',
                'value': round(min_latency, 2),
                'dimensions': {**base_dims, 'latency_type': 'minimum'},
                'timestamp': timestamp
            })
            
            metrics.append({
                'metric': 'network.latency.icmp.max.ms',
                'value': round(max_latency, 2),
                'dimensions': {**base_dims, 'latency_type': 'maximum'},
                'timestamp': timestamp
            })
            
            with PRINT_LOCK:
                print(f"  📶 {target_name}: Latency={avg_latency:.2f}ms, Jitter={jitter:.2f}ms [{severity}]")
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[LatencyMonitor] Error measuring {target}: {e}")
        
        return metrics


class EnhancedPacketLossMonitor:
    """Enhanced packet loss monitoring."""
    
    def __init__(self, config: dict, database: DatabaseIngestion):
        self.config = config
        self.database = database
    
    def measure_packet_loss(self, target: str, target_name: str = None, count: int = 20) -> List[dict]:
        """
        Measure packet loss, return ready-to-insert metrics.
        Returns list of metrics with ALL fields populated.
        """
        metrics = []
        
        if not target_name:
            target_name = target
        
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ['ping', '-n', str(count), target],
                    capture_output=True,
                    text=True,
                    timeout=45
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', str(count), target],
                    capture_output=True,
                    text=True,
                    timeout=45
                )
            
            # Extract loss percentage
            match = re.search(r'(\d+)% loss', result.stdout)
            if not match:
                return metrics
            
            loss_pct = float(match.group(1))
            
            # Get target IP
            try:
                target_ip = socket.gethostbyname(target)
            except:
                target_ip = target
            
            # Extract packets sent/received
            if IS_WINDOWS:
                sent_match = re.search(r'Sent = (\d+)', result.stdout)
                recv_match = re.search(r'Received = (\d+)', result.stdout)
            else:
                sent_match = re.search(r'(\d+) packets transmitted', result.stdout)
                recv_match = re.search(r'(\d+) received', result.stdout)
            
            packets_sent = int(sent_match.group(1)) if sent_match else count
            packets_received = int(recv_match.group(1)) if recv_match else 0
            packets_lost = packets_sent - packets_received
            
            # Determine severity
            if loss_pct > 5:
                severity = 'critical'
                status = 'packet_loss_critical'
            elif loss_pct > 2:
                severity = 'high'
                status = 'packet_loss_high'
            elif loss_pct > 0.5:
                severity = 'medium'
                status = 'packet_loss_detected'
            elif loss_pct > 0:
                severity = 'low'
                status = 'minor_packet_loss'
            else:
                severity = 'low'
                status = 'healthy'
            
            timestamp = int(time.time() * 1000)
            
            base_dims = {
                'monitoring_host': MONITORING_HOST_NAME,
                'target': target_name,
                'target_host': target_name,
                'target_ip': target_ip,
                'metric_type': 'packet_loss',
                'severity': severity,
                'status': status
            }
            
            # Loss percentage
            metrics.append({
                'metric': 'network.packet_loss.icmp.pct',
                'value': loss_pct,
                'dimensions': base_dims,
                'timestamp': timestamp
            })
            
            # Packet counts
            metrics.append({
                'metric': 'network.packets.sent',
                'value': packets_sent,
                'dimensions': {**base_dims, 'packet_type': 'sent'},
                'timestamp': timestamp
            })
            
            metrics.append({
                'metric': 'network.packets.received',
                'value': packets_received,
                'dimensions': {**base_dims, 'packet_type': 'received'},
                'timestamp': timestamp
            })
            
            metrics.append({
                'metric': 'network.packets.lost',
                'value': packets_lost,
                'dimensions': {**base_dims, 'packet_type': 'lost'},
                'timestamp': timestamp
            })
            
            with PRINT_LOCK:
                status_icon = '🔴' if loss_pct > 5 else '🟡' if loss_pct > 1 else '🟢'
                print(f"  {status_icon} {target_name}: PacketLoss={loss_pct:.1f}% ({packets_lost}/{packets_sent}) [{severity}]")
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[PacketLoss] Error measuring {target}: {e}")
        
        return metrics


class EnhancedDNSMonitor:
    """Enhanced DNS resolution monitoring."""
    
    def __init__(self, config: dict, database: DatabaseIngestion):
        self.config = config
        self.database = database
    
    def measure_dns_resolution(self, domain: str, dns_server: str = None) -> List[dict]:
        """
        Measure DNS resolution time, return ready-to-insert metrics.
        Returns list of metrics with ALL fields populated.
        """
        metrics = []
        
        try:
            start_time = time.time()
            
            if dns_server:
                try:
                    import dns.resolver
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [dns_server]
                    answers = resolver.resolve(domain, 'A')
                    resolved_ips = [str(rdata) for rdata in answers]
                except ImportError:
                    resolved_ips = [socket.gethostbyname(domain)]
            else:
                resolved_ips = [socket.gethostbyname(domain)]
            
            end_time = time.time()
            resolution_time_ms = (end_time - start_time) * 1000
            
            # Determine severity
            if resolution_time_ms > 1000:
                severity = 'critical'
                status = 'dns_very_slow'
            elif resolution_time_ms > 500:
                severity = 'high'
                status = 'dns_slow'
            elif resolution_time_ms > 100:
                severity = 'medium'
                status = 'dns_acceptable'
            else:
                severity = 'low'
                status = 'healthy'
            
            timestamp = int(time.time() * 1000)
            
            base_dims = {
                'monitoring_host': MONITORING_HOST_NAME,
                'domain': domain,
                'target': domain,
                'target_host': domain,
                'target_ip': resolved_ips[0] if resolved_ips else '0.0.0.0',
                'dns_server': dns_server or 'system',
                'metric_type': 'dns_resolution',
                'severity': severity,
                'status': status
            }
            
            # DNS resolution time
            metrics.append({
                'metric': 'network.dns.resolution.ms',
                'value': round(resolution_time_ms, 2),
                'dimensions': base_dims,
                'timestamp': timestamp
            })
            
            # Success indicator
            metrics.append({
                'metric': 'network.dns.resolution.success',
                'value': 1,
                'dimensions': base_dims,
                'timestamp': timestamp
            })
            
            with PRINT_LOCK:
                severity_icon = '🔴' if severity == 'critical' else '🟡' if severity in ['high', 'medium'] else '🟢'
                print(f"  {severity_icon} {domain}: DNS={resolution_time_ms:.2f}ms [{severity}]")
        
        except socket.gaierror as e:
            timestamp = int(time.time() * 1000)
            metrics.append({
                'metric': 'network.dns.resolution.failure',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'domain': domain,
                    'target': domain,
                    'target_host': domain,
                    'target_ip': '0.0.0.0',
                    'dns_server': dns_server or 'system',
                    'metric_type': 'dns_resolution',
                    'severity': 'critical',
                    'status': 'dns_failure',
                    'error': str(e)
                },
                'timestamp': timestamp
            })
            
            with PRINT_LOCK:
                print(f"  🔴 {domain}: DNS resolution failed - {e}")
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[DNSMonitor] Error measuring {domain}: {e}")
        
        return metrics


class EnhancedThroughputMonitor:
    """Enhanced throughput monitoring with utilization."""
    
    def __init__(self, config: dict, database: DatabaseIngestion):
        self.config = config
        self.database = database
        self.last_stats = {}
        self.interface_info_cache = {}
    
    def get_interface_details(self, interface_name: str) -> dict:
        """Get interface details."""
        if interface_name in self.interface_info_cache:
            return self.interface_info_cache[interface_name]
        
        details = {
            'ip_address': 'N/A',
            'status': 'unknown',
            'speed_mbps': 0
        }
        
        try:
            addrs = psutil.net_if_addrs().get(interface_name, [])
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    details['ip_address'] = addr.address
                    break
            
            stats = psutil.net_if_stats().get(interface_name)
            if stats:
                details['status'] = 'up' if stats.isup else 'down'
                details['speed_mbps'] = stats.speed
        except:
            pass
        
        self.interface_info_cache[interface_name] = details
        return details
    
    def measure_interface_throughput(self) -> List[dict]:
        """
        Measure throughput for all interfaces.
        Returns list of metrics with ALL fields populated.
        """
        metrics = []
        timestamp = int(time.time() * 1000)
        
        try:
            net_io = psutil.net_io_counters(pernic=True)
            current_time = time.time()
            
            for interface, stats in net_io.items():
                # Skip loopback and virtual
                if interface.startswith('lo') or interface.startswith('veth'):
                    continue
                
                if_details = self.get_interface_details(interface)
                
                if interface in self.last_stats:
                    last_time, last_stats = self.last_stats[interface]
                    time_diff = current_time - last_time
                    
                    if time_diff > 0:
                        # Calculate throughput
                        bytes_sent = stats.bytes_sent - last_stats.bytes_sent
                        bytes_recv = stats.bytes_recv - last_stats.bytes_recv
                        
                        mbps_sent = (bytes_sent * 8) / (time_diff * 1_000_000)
                        mbps_recv = (bytes_recv * 8) / (time_diff * 1_000_000)
                        mbps_total = mbps_sent + mbps_recv
                        
                        # Calculate utilization
                        if if_details['speed_mbps'] > 0:
                            utilization_pct = (mbps_total / if_details['speed_mbps']) * 100
                            if utilization_pct > 90:
                                severity = 'critical'
                                status = 'saturated'
                            elif utilization_pct > 70:
                                severity = 'high'
                                status = 'high_utilization'
                            elif utilization_pct > 50:
                                severity = 'medium'
                                status = 'moderate_utilization'
                            else:
                                severity = 'low'
                                status = 'healthy'
                        else:
                            utilization_pct = 0
                            severity = 'low'
                            status = 'healthy'
                        
                        base_dims = {
                            'monitoring_host': MONITORING_HOST_NAME,
                            'interface_name': interface,
                            'interface': interface,
                            'target_host': 'N/A',
                            'target_ip': '0.0.0.0',
                            'metric_type': 'throughput',
                            'ip_address': if_details['ip_address'],
                            'interface_status': if_details['status'],
                            'interface_speed_mbps': if_details['speed_mbps'],
                            'severity': severity,
                            'status': status
                        }
                        
                        # Sent throughput
                        metrics.append({
                            'metric': 'network.throughput.sent.mbps',
                            'value': round(mbps_sent, 3),
                            'dimensions': {**base_dims, 'direction': 'outbound'},
                            'timestamp': timestamp
                        })
                        
                        # Received throughput
                        metrics.append({
                            'metric': 'network.throughput.received.mbps',
                            'value': round(mbps_recv, 3),
                            'dimensions': {**base_dims, 'direction': 'inbound'},
                            'timestamp': timestamp
                        })
                        
                        # Total throughput
                        metrics.append({
                            'metric': 'network.throughput.total.mbps',
                            'value': round(mbps_total, 3),
                            'dimensions': {**base_dims, 'direction': 'bidirectional'},
                            'timestamp': timestamp
                        })
                        
                        # Utilization
                        if if_details['speed_mbps'] > 0:
                            metrics.append({
                                'metric': 'network.interface.utilization.pct',
                                'value': round(utilization_pct, 2),
                                'dimensions': base_dims,
                                'timestamp': timestamp
                            })
                        
                        # Packet rates
                        packets_sent = stats.packets_sent - last_stats.packets_sent
                        packets_recv = stats.packets_recv - last_stats.packets_recv
                        
                        packets_sent_rate = packets_sent / time_diff
                        packets_recv_rate = packets_recv / time_diff
                        
                        metrics.append({
                            'metric': 'network.packets.sent.rate',
                            'value': round(packets_sent_rate, 2),
                            'dimensions': {**base_dims, 'direction': 'outbound'},
                            'timestamp': timestamp
                        })
                        
                        metrics.append({
                            'metric': 'network.packets.received.rate',
                            'value': round(packets_recv_rate, 2),
                            'dimensions': {**base_dims, 'direction': 'inbound'},
                            'timestamp': timestamp
                        })
                        
                        with PRINT_LOCK:
                            print(f"  📊 {interface}: ↑{mbps_sent:.2f} Mbps / ↓{mbps_recv:.2f} Mbps (Util: {utilization_pct:.1f}%)")
                
                # Store current stats
                self.last_stats[interface] = (current_time, stats)
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Throughput] Error: {e}")
        
        return metrics


# ===================================================================
#  SIMPLIFIED APPLICATION & CERTIFICATE MONITORS
# ===================================================================

class ApplicationPerformanceMonitor:
    """Application performance monitoring."""
    
    def __init__(self, config: dict, dynatrace: DatabaseIngestion):
        self.config = config
        self.database = dynatrace
    
    def test_application(self, app_config: dict) -> dict:
        """
        Test application performance with ENHANCED error handling and meaningful failure values.
        """
        url = app_config.get('url')
        name = app_config.get('name')
        criticality = app_config.get('criticality', 'unknown')
        
        results = {
            'name': name,
            'url': url,
            'criticality': criticality,
            'success': False,
            'total_time_ms': 30000.0,  # Default to timeout value for failures
            'dns_time_ms': 30000.0,    # High value indicates DNS failure
            'connect_time_ms': 0,       # 0 since connection never established
            'tls_time_ms': 0,          # 0 since TLS never started
            'first_byte_time_ms': 0,    # 0 since no data received
            'status_code': 0,           # 0 indicates connection failure
            'error': None
        }
        
        try:
            import requests
            import time
            from urllib.parse import urlparse
            import socket
            
            # Parse URL
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            is_https = parsed.scheme == 'https'
            
            # ==================================================
            # STEP 1: Measure DNS Resolution Time
            # ==================================================
            dns_start = time.time()
            try:
                ip_address = socket.gethostbyname(hostname)
                results['dns_time_ms'] = (time.time() - dns_start) * 1000
            except socket.gaierror as dns_error:
                # Enhanced DNS error handling
                error_code = dns_error.errno if hasattr(dns_error, 'errno') else 'unknown'
                results['dns_time_ms'] = 30000.0  # High value indicates DNS failure
                results['error'] = f"DNS resolution failed for '{hostname}': {dns_error.strerror if hasattr(dns_error, 'strerror') else str(dns_error)}"
                results['status_code'] = 0
                results['success'] = False
                return results  # Early return on DNS failure
            except Exception as dns_error:
                results['dns_time_ms'] = 30000.0
                results['error'] = f"DNS error for '{hostname}': {str(dns_error)}"
                results['status_code'] = 0
                results['success'] = False
                return results
            
            # Reset total time for successful DNS
            results['total_time_ms'] = 0
            
            # ==================================================
            # STEP 2: Measure TCP Connection Time (+ TLS if HTTPS)
            # ==================================================
            connect_start = time.time()
            try:
                # Create raw socket connection
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((hostname, port))
                
                # Measure pure TCP connection time
                tcp_connect_end = time.time()
                pure_tcp_time = (tcp_connect_end - connect_start) * 1000
                
                # If HTTPS, measure TLS handshake separately
                if is_https:
                    import ssl
                    tls_start = time.time()
                    
                    context = ssl.create_default_context()
                    ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
                    
                    tls_end = time.time()
                    results['tls_time_ms'] = (tls_end - tls_start) * 1000
                    results['connect_time_ms'] = pure_tcp_time
                    
                    ssl_sock.close()
                else:
                    results['connect_time_ms'] = pure_tcp_time
                    results['tls_time_ms'] = 0
                    sock.close()
                
            except socket.timeout:
                results['error'] = f"Connection timeout after 10 seconds to {hostname}:{port}"
                results['status_code'] = 0
                results['success'] = False
                return results
            except socket.error as sock_error:
                results['error'] = f"Connection failed to {hostname}:{port}: {sock_error.strerror if hasattr(sock_error, 'strerror') else str(sock_error)}"
                results['status_code'] = 0
                results['success'] = False
                return results
            except Exception as connect_error:
                results['error'] = f"Connection error to {hostname}:{port}: {str(connect_error)}"
                results['status_code'] = 0
                results['success'] = False
                return results
            
            # ==================================================
            # STEP 3: Make HTTP Request and Measure First Byte + Total Time
            # ==================================================
            request_start = time.time()
            first_byte_time = None
            
            try:
                # Use streaming to detect first byte
                response = requests.get(
                    url, 
                    timeout=30, 
                    allow_redirects=True,
                    stream=True
                )
                
                # Read first chunk to get first byte time
                for chunk in response.iter_content(chunk_size=1):
                    if first_byte_time is None:
                        first_byte_time = time.time()
                    break
                
                # Consume rest of response
                for chunk in response.iter_content(chunk_size=8192):
                    pass
                
                response.close()
                
                end_time = time.time()
                
                # Calculate timings
                results['total_time_ms'] = (end_time - request_start) * 1000
                
                if first_byte_time:
                    # Time from request start to first byte
                    total_first_byte = (first_byte_time - request_start) * 1000
                    
                    # Subtract DNS + Connect + TLS to get server processing time
                    results['first_byte_time_ms'] = max(0, 
                        total_first_byte - 
                        results['dns_time_ms'] - 
                        results['connect_time_ms'] - 
                        results['tls_time_ms']
                    )
                else:
                    # Fallback: estimate from total time
                    results['first_byte_time_ms'] = max(0,
                        results['total_time_ms'] -
                        results['dns_time_ms'] -
                        results['connect_time_ms'] -
                        results['tls_time_ms']
                    )
                
                results['status_code'] = response.status_code
                results['success'] = response.status_code == 200
                
                # Capture non-200 status codes as errors
                if response.status_code != 200:
                    results['error'] = f'HTTP {response.status_code}: {response.reason}'
                
            except requests.exceptions.Timeout:
                results['error'] = f'HTTP request timeout after 30 seconds to {url}'
                results['status_code'] = 0
                results['success'] = False
            except requests.exceptions.SSLError as ssl_err:
                results['error'] = f'SSL/TLS error for {url}: {str(ssl_err)[:200]}'
                results['status_code'] = 0
                results['success'] = False
            except requests.exceptions.ConnectionError as conn_err:
                results['error'] = f'Connection refused or reset for {url}: {str(conn_err)[:200]}'
                results['status_code'] = 0
                results['success'] = False
            except requests.exceptions.TooManyRedirects:
                results['error'] = f'Too many redirects for {url} (possible redirect loop)'
                results['status_code'] = 0
                results['success'] = False
            except Exception as e:
                results['error'] = f'HTTP request failed for {url}: {str(e)[:200]}'
                results['status_code'] = 0
                results['success'] = False
        
        except Exception as e:
            results['error'] = f'Unexpected error testing {url}: {str(e)[:200]}'
            results['success'] = False
        
        return results
    
    def generate_metrics(self, app_results: dict) -> List[dict]:
        """
        Generate application performance metrics with COMPLETE dimensions.
        """
        metrics = []
        timestamp = int(time.time() * 1000)
        
        # Determine status and severity
        if app_results['success']:
            status = 'healthy'
            severity = 'low'
        else:
            status = 'unhealthy'
            severity = 'high'
        
        # Base dimensions with ALL timing breakdown
        base_dims = {
            'monitoring_host': MONITORING_HOST_NAME,
            'application': app_results['name'],
            'url': app_results['url'],
            'criticality': app_results.get('criticality', 'unknown'),
            'status': status,
            'severity': severity,
            'status_code': app_results['status_code'],
            
            # ✅ CRITICAL: Include timing breakdown in dimensions
            'dns_time': round(app_results.get('dns_time_ms', 0), 2),
            'connect_time': round(app_results.get('connect_time_ms', 0), 2),
            'tls_time': round(app_results.get('tls_time_ms', 0), 2),
            'first_byte_time': round(app_results.get('first_byte_time_ms', 0), 2)
        }
        
        # Add error if present
        if 'error' in app_results:
            base_dims['error'] = app_results['error']
        
        # Response time metric
        metrics.append({
            'metric': 'application.response_time.ms',
            'value': round(app_results['total_time_ms'], 2),
            'dimensions': base_dims,
            'timestamp': timestamp
        })
        
        # Availability metric
        availability = 1 if app_results['success'] else 0
        metrics.append({
            'metric': 'application.availability',
            'value': availability,
            'dimensions': base_dims,
            'timestamp': timestamp
        })
        
        # Status code metric
        metrics.append({
            'metric': 'application.status_code',
            'value': app_results['status_code'],
            'dimensions': base_dims,
            'timestamp': timestamp
        })
        
        return metrics



# ===================================================================
#                       MFA HEALTH TRACKER
# ===================================================================

class MFAHealthTracker:
    """
    ✅ NEW IN v4.7: Tracks MFA (Multi-Factor Authentication) events and calculates health metrics.
    
    Monitors:
    - MFA success/failure rates
    - Per-user failure counts
    - Credential validation events
    - Overall MFA health status
    
    Event IDs Tracked:
    - 6272: MFA/PEAP Authentication Success
    - 6273: MFA/PEAP Authentication Failure
    - 4776: Credential Validation (including MFA)
    """
    
    def __init__(self):
        """Initialize MFA health tracker."""
        # Store last 15 minutes of events (900 events at 1/sec)
        self.mfa_events = deque(maxlen=900)
        
        # Track failures per user
        self.user_failures = defaultdict(lambda: deque(maxlen=900))
        
        # Health thresholds
        self.success_rate_threshold_warning = 90.0    # Warn if below 90%
        self.success_rate_threshold_critical = 85.0   # Critical if below 85%
        self.user_failure_threshold = 3               # Alert if user has 3+ failures
        
        with PRINT_LOCK:
            print("[MFATracker] ✅ MFA Health Tracker initialized")
    
    def add_mfa_event(self, event_type: str, user: str, event_id: int):
        """
        Add MFA event (success, failure, or validation).
        
        Args:
            event_type: Type of event (for logging)
            user: Username associated with event
            event_id: Windows Event ID (6272, 6273, 4776)
        """
        current_time = time.time()
        
        # Normalize event type based on Event ID
        if event_id == 6272:
            status = 'success'
        elif event_id == 6273:
            status = 'failure'
        elif event_id == 4776:
            status = 'validation'
        else:
            status = 'unknown'
        
        # Add to event history
        self.mfa_events.append({
            'status': status,
            'user': user,
            'event_id': event_id,
            'timestamp': current_time
        })
        
        # Track user failures
        if status == 'failure':
            self.user_failures[user].append(current_time)
    
    def calculate_mfa_metrics(self, monitoring_host: str) -> List[Dict]:
        """
        Calculate MFA health metrics for database storage.
        
        Args:
            monitoring_host: Name of the monitoring host
            
        Returns:
            List of metric dictionaries ready for database insertion
        """
        metrics = []
        timestamp = int(time.time() * 1000)
        
        # Handle no events case
        if not self.mfa_events:
            metrics.append({
                'metric': 'security.mfa.success_rate',
                'value': 100.0,
                'dimensions': {
                    'monitoring_host': monitoring_host,
                    'status': 'no_data',
                    'time_window': '15min'
                },
                'timestamp': timestamp
            })
            return metrics
        
        # Count events by status
        successes = sum(1 for e in self.mfa_events if e['status'] == 'success')
        failures = sum(1 for e in self.mfa_events if e['status'] == 'failure')
        validations = sum(1 for e in self.mfa_events if e['status'] == 'validation')
        
        total_mfa = successes + failures
        
        # Calculate success rate
        if total_mfa == 0:
            success_rate = 100.0
            status = 'no_mfa_events'
        else:
            success_rate = (successes / total_mfa) * 100
            
            # Determine health status
            if success_rate >= self.success_rate_threshold_warning:
                status = 'healthy'
            elif success_rate >= self.success_rate_threshold_critical:
                status = 'warning'
            else:
                status = 'critical'
        
        # Core MFA metrics
        metrics.extend([
            {
                'metric': 'security.mfa.success_rate',
                'value': round(success_rate, 2),
                'dimensions': {
                    'monitoring_host': monitoring_host,
                    'status': status,
                    'time_window': '15min'
                },
                'timestamp': timestamp
            },
            {
                'metric': 'security.mfa.failure_count',
                'value': failures,
                'dimensions': {
                    'monitoring_host': monitoring_host,
                    'status': status,
                    'time_window': '15min'
                },
                'timestamp': timestamp
            },
            {
                'metric': 'security.mfa.success_count',
                'value': successes,
                'dimensions': {
                    'monitoring_host': monitoring_host,
                    'time_window': '15min'
                },
                'timestamp': timestamp
            },
            {
                'metric': 'security.mfa.credential_validation_count',
                'value': validations,
                'dimensions': {
                    'monitoring_host': monitoring_host,
                    'time_window': '15min'
                },
                'timestamp': timestamp
            }
        ])
        
        # Per-user failure metrics (alert on high failure rates)
        for user, failures_deque in self.user_failures.items():
            user_failure_count = len(failures_deque)
            
            if user_failure_count >= self.user_failure_threshold:
                metrics.append({
                    'metric': 'security.mfa.user_failure_count',
                    'value': user_failure_count,
                    'dimensions': {
                        'monitoring_host': monitoring_host,
                        'user': user,
                        'threshold_exceeded': 'true',
                        'time_window': '15min'
                    },
                    'timestamp': timestamp
                })
        
        return metrics
    
    def get_health_status(self) -> dict:
        """
        Get current MFA health status (for display/logging).
        
        Returns:
            Dictionary with health status information
        """
        if not self.mfa_events:
            return {
                'status': 'no_data',
                'success_rate': 100.0,
                'failure_count': 0,
                'total_events': 0
            }
        
        successes = sum(1 for e in self.mfa_events if e['status'] == 'success')
        failures = sum(1 for e in self.mfa_events if e['status'] == 'failure')
        total_mfa = successes + failures
        
        if total_mfa == 0:
            success_rate = 100.0
            status = 'no_mfa_events'
        else:
            success_rate = (successes / total_mfa) * 100
            
            if success_rate >= self.success_rate_threshold_warning:
                status = 'healthy'
            elif success_rate >= self.success_rate_threshold_critical:
                status = 'warning'
            else:
                status = 'critical'
        
        return {
            'status': status,
            'success_rate': round(success_rate, 2),
            'failure_count': failures,
            'total_events': total_mfa
        }
    
    def get_user_failure_summary(self) -> List[Dict]:
        """
        Get summary of users with high failure counts.
        
        Returns:
            List of users with failure counts exceeding threshold
        """
        problematic_users = []
        
        for user, failures_deque in self.user_failures.items():
            failure_count = len(failures_deque)
            if failure_count >= self.user_failure_threshold:
                problematic_users.append({
                    'user': user,
                    'failure_count': failure_count,
                    'time_window': '15min'
                })
        
        return problematic_users

class EnhancedAuditTrailMonitor:
    """
    Monitors audit logging health - checks if logs are ACTIVELY being written.
    Tracks:
    - Security event log (failed/successful logins)
    - Windows Firewall log
    - Windows Defender log
    - Application event log
    - System event log
    
    For central logging: tracks which source hosts are sending logs.
    """
    
    def __init__(self, config: dict, database, central_connector=None):
        self.config = config
        self.database = database
        self.central_connector = central_connector
        
        # Initialize MFA tracker
        self.mfa_tracker = MFAHealthTracker()  # ✅ FIXED: Create instance instead of using undefined variable
        
        # Track last seen event times per log
        self.last_event_times = defaultdict(dict)
        
        # Track source hosts sending logs (for central logging)
        self.active_source_hosts = defaultdict(lambda: defaultdict(dict))
        
        # Alert thresholds
        self.alert_threshold_minutes = config.get('audit_monitoring', {}).get(
            'alert_if_no_events_for_minutes', 30
        )
    
    def check_logging_health(self) -> List[dict]:
        """Check if all critical logs are receiving events."""
        metrics = []
        timestamp = int(time.time() * 1000)
        
        # Logs to monitor
        logs_to_check = [
            {
                'log_name': 'Security',
                'event_ids': [4624, 4625, 4776],  # Login events
                'description': 'Security/Login Events',
                'critical': True
            },
            {
                'log_name': 'Security', 
                'event_ids': [5152, 5157],  # Firewall events
                'description': 'Firewall Events',
                'critical': True
            },
            {
                'log_name': 'Microsoft-Windows-Windows Defender/Operational',
                'event_ids': [1116, 1117, 1118, 1119],  # Defender events
                'description': 'Windows Defender',
                'critical': True
            },
            {
                'log_name': 'System',
                'event_ids': [1, 6005, 6006, 6008, 6009],  # System events
                'description': 'System Events',
                'critical': True
            }
        ]
        
        for log_config in logs_to_check:
            health_status = self._check_log_health(
                log_config['log_name'],
                log_config['event_ids'],
                log_config['description']
            )
            
            # Create metric
            metric = {
                'metric': 'audit.logging_health',
                'value': 1 if health_status['is_healthy'] else 0,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'log_name': log_config['description'],
                    'status': health_status['status'],
                    'critical': str(log_config['critical'])
                },
                'timestamp': timestamp
            }
            metrics.append(metric)
            
            # Minutes since last event metric
            if health_status['minutes_since_last_event'] is not None:
                metrics.append({
                    'metric': 'audit.minutes_since_last_event',
                    'value': health_status['minutes_since_last_event'],
                    'dimensions': {
                        'monitoring_host': MONITORING_HOST_NAME,
                        'log_name': log_config['description']
                    },
                    'timestamp': timestamp
                })
        
        # Check central logging health if enabled
        if self.central_connector:
            central_metrics = self._check_central_logging_health()
            metrics.extend(central_metrics)
        
        return metrics
    
    def _check_log_health(self, log_name: str, event_ids: List[int], 
                          description: str) -> dict:
        """Check if a specific log is receiving events."""
        if not IS_WINDOWS:
            return {
                'is_healthy': False,
                'status': 'not_windows',
                'minutes_since_last_event': None,
                'last_event_time': None
            }
        
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            # Read recent events (last 100)
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            last_event_time = None
            event_count = 0
            
            for event in events[:100]:  # Check last 100 events
                if event.EventID in event_ids:
                    event_time = event.TimeGenerated.replace(tzinfo=None)
                    if last_event_time is None or event_time > last_event_time:
                        last_event_time = event_time
                    event_count += 1
            
            win32evtlog.CloseEventLog(hand)
            
            # Calculate health
            if last_event_time:
                minutes_since = (datetime.now() - last_event_time).total_seconds() / 60
                
                # Store for tracking
                self.last_event_times[log_name][tuple(event_ids)] = last_event_time
                
                if minutes_since > self.alert_threshold_minutes:
                    status = 'stale'
                    is_healthy = False
                elif minutes_since > (self.alert_threshold_minutes / 2):
                    status = 'warning'
                    is_healthy = True
                else:
                    status = 'healthy'
                    is_healthy = True
                
                return {
                    'is_healthy': is_healthy,
                    'status': status,
                    'minutes_since_last_event': round(minutes_since, 1),
                    'last_event_time': last_event_time.isoformat(),
                    'event_count': event_count
                }
            else:
                return {
                    'is_healthy': False,
                    'status': 'no_events',
                    'minutes_since_last_event': None,
                    'last_event_time': None,
                    'event_count': 0
                }
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[AuditHealth] Error checking {description}: {e}")
            
            return {
                'is_healthy': False,
                'status': 'error',
                'minutes_since_last_event': None,
                'last_event_time': None,
                'error': str(e)
            }
    
    def _check_central_logging_health(self) -> List[dict]:
        """Check which source hosts are actively sending logs to central server."""
        metrics = []
        timestamp = int(time.time() * 1000)
        
        multi_host_config = self.config.get('security_monitoring', {}).get('multi_host', {})
        monitored_hosts = multi_host_config.get('monitored_hosts', [])
        
        for host_config in monitored_hosts:
            if not host_config.get('enabled', True):
                continue
            
            host_name = host_config.get('name', 'unknown')
            host_ip = host_config.get('ip', '')
            
            # Check if this host has sent events recently
            health = self._check_source_host_health(host_name, host_ip)
            
            # Create metric
            metrics.append({
                'metric': 'audit.source_host_logging_health',
                'value': 1 if health['is_sending_logs'] else 0,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'source_host': host_name,
                    'source_ip': host_ip,
                    'status': health['status']
                },
                'timestamp': timestamp
            })
            
            if health['minutes_since_last_event'] is not None:
                metrics.append({
                    'metric': 'audit.source_host_minutes_since_last_event',
                    'value': health['minutes_since_last_event'],
                    'dimensions': {
                        'monitoring_host': MONITORING_HOST_NAME,
                        'source_host': host_name,
                        'source_ip': host_ip
                    },
                    'timestamp': timestamp
                })
        
        return metrics
    
    def _check_source_host_health(self, host_name: str, host_ip: str) -> dict:
        """Check if a source host is sending logs."""
        try:
            # Try to collect recent events from this host
            central_server_ip = self.config.get('security_monitoring', {}).get(
                'multi_host', {}
            ).get('central_server', {}).get('ip')
            
            if not central_server_ip:
                return {'is_sending_logs': False, 'status': 'no_central_server'}
            
            # Collect recent events
            events = self.central_connector.collect_events_from_host(
                central_server_ip=central_server_ip,
                source_host=host_name,
                log_name='Security',
                event_ids=[4624, 4625, 5152],  # Common events
                lookback_minutes=self.alert_threshold_minutes
            )
            
            if events:
                # Get most recent event time
                latest_event = max(events, key=lambda e: e.get('timestamp', ''))
                event_time_str = latest_event.get('timestamp', '')
                
                try:
                    event_time = datetime.fromisoformat(event_time_str)
                    minutes_since = (datetime.now() - event_time).total_seconds() / 60
                    
                    # Update tracking
                    self.active_source_hosts[host_name]['last_seen'] = event_time
                    self.active_source_hosts[host_name]['event_count'] = len(events)
                    
                    if minutes_since < 5:
                        status = 'healthy'
                    elif minutes_since < self.alert_threshold_minutes:
                        status = 'active'
                    else:
                        status = 'stale'
                    
                    return {
                        'is_sending_logs': True,
                        'status': status,
                        'minutes_since_last_event': round(minutes_since, 1),
                        'event_count': len(events)
                    }
                except:
                    pass
            
            # No events found
            last_seen = self.active_source_hosts[host_name].get('last_seen')
            if last_seen:
                minutes_since = (datetime.now() - last_seen).total_seconds() / 60
                return {
                    'is_sending_logs': False,
                    'status': 'stopped',
                    'minutes_since_last_event': round(minutes_since, 1)
                }
            else:
                return {
                    'is_sending_logs': False,
                    'status': 'never_seen',
                    'minutes_since_last_event': None
                }
        
        except Exception as e:
            return {
                'is_sending_logs': False,
                'status': 'error',
                'error': str(e)
            }
    
    def display_audit_health(self, metrics: List[dict]):
        """Display audit health status."""
        with PRINT_LOCK:
            print(f"\n📋 AUDIT TRAIL & LOGGING HEALTH")
            print(f"{'─'*70}")
            
            # Group by local vs central
            local_metrics = []
            central_metrics = []
            
            for metric in metrics:
                if 'source_host' in metric['dimensions']:
                    central_metrics.append(metric)
                else:
                    local_metrics.append(metric)
            
            # Display local logging health
            if local_metrics:
                print(f"\n  📊 Local Event Logs (This Machine):")
                for metric in local_metrics:
                    if metric['metric'] == 'audit.logging_health':
                        log_name = metric['dimensions']['log_name']
                        status = metric['dimensions']['status']
                        is_healthy = metric['value'] == 1
                        
                        if is_healthy:
                            icon = '🟢'
                        else:
                            icon = '🔴'
                        
                        # Find corresponding time metric
                        minutes_metric = next(
                            (m for m in metrics 
                             if m['metric'] == 'audit.minutes_since_last_event' 
                             and m['dimensions']['log_name'] == log_name),
                            None
                        )
                        
                        if minutes_metric:
                            minutes = minutes_metric['value']
                            print(f"     {icon} {log_name}: {status.upper()} "
                                  f"(last event {minutes:.1f} min ago)")
                        else:
                            print(f"     {icon} {log_name}: {status.upper()}")
            
            # Display central logging health
            if central_metrics:
                print(f"\n  📡 Source Hosts (Central Log Server):")
                
                # Get unique source hosts
                source_hosts = set()
                for metric in central_metrics:
                    if metric['metric'] == 'audit.source_host_logging_health':
                        source_hosts.add(metric['dimensions']['source_host'])
                
                for host in sorted(source_hosts):
                    health_metric = next(
                        (m for m in central_metrics 
                         if m['metric'] == 'audit.source_host_logging_health'
                         and m['dimensions']['source_host'] == host),
                        None
                    )
                    
                    if health_metric:
                        is_sending = health_metric['value'] == 1
                        status = health_metric['dimensions']['status']
                        ip = health_metric['dimensions']['source_ip']
                        
                        if is_sending and status == 'healthy':
                            icon = '🟢'
                        elif is_sending:
                            icon = '🟡'
                        else:
                            icon = '🔴'
                        
                        # Find time metric
                        time_metric = next(
                            (m for m in central_metrics
                             if m['metric'] == 'audit.source_host_minutes_since_last_event'
                             and m['dimensions']['source_host'] == host),
                            None
                        )
                        
                        if time_metric:
                            minutes = time_metric['value']
                            print(f"     {icon} {host} ({ip}): {status.upper()} "
                                  f"(last event {minutes:.1f} min ago)")
                        else:
                            print(f"     {icon} {host} ({ip}): {status.upper()}")
            
            print()



class CertificateMonitor:
    """SSL/TLS certificate monitoring."""
    
    def __init__(self, config: dict, database: DatabaseIngestion):
        self.config = config
        self.database = database
    
    def check_certificate(self, hostname: str, port: int = 443) -> List[dict]:
        """Check certificate and return metrics."""
        metrics = []
        timestamp = int(time.time() * 1000)
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_der = ssock.getpeercert(binary_form=True)
                    
                    # Parse certificate dates
                    not_after = cert.get('notAfter', '')
                    not_before = cert.get('notBefore', '')
                    
                    if not_after:
                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expire_date - datetime.now()).days
                    else:
                        days_until_expiry = -1
                        expire_date = None
                    
                    if not_before:
                        issue_date = datetime.strptime(not_before, '%b %d %H:%M:%S %Y %Z')
                    else:
                        issue_date = None
                    
                    # Extract issuer and subject
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    
                    # Check if self-signed
                    is_self_signed = issuer == subject
                    
                    # Check hostname mismatch
                    has_hostname_mismatch = False
                    cert_hostnames = []
                    for field in cert.get('subjectAltName', []):
                        if field[0] == 'DNS':
                            cert_hostnames.append(field[1])
                    
                    if hostname not in cert_hostnames and subject.get('commonName') != hostname:
                        has_hostname_mismatch = True
                    
                    # Get TLS version and cipher
                    tls_version = ssock.version()
                    cipher_suite = ssock.cipher()[0] if ssock.cipher() else 'Unknown'
                    
                    # Check for weak protocols/ciphers
                    weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                    weak_ciphers = ['DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon']
                    
                    has_weak_protocol = any(proto in tls_version for proto in weak_protocols)
                    has_weak_cipher = any(cipher in cipher_suite.upper() for cipher in weak_ciphers)
                    
                    return {
                        'success': True,
                        'subject': subject,
                        'issuer': issuer,
                        'not_after': not_after,
                        'not_before': not_before,
                        'expiry_date': expire_date,
                        'issue_date': issue_date,
                        'days_until_expiry': days_until_expiry,
                        'is_self_signed': is_self_signed,
                        'has_hostname_mismatch': has_hostname_mismatch,
                        'tls_version': tls_version,
                        'cipher_suite': cipher_suite,
                        'has_weak_protocol': has_weak_protocol,
                        'has_weak_cipher': has_weak_cipher,
                        'cert_hostnames': cert_hostnames
                    }
        
        except ssl.SSLCertVerificationError as e:
            return {
                'success': False,
                'error': f"Certificate validation failed: {e}",
                'is_valid': False,
                'validation_error': str(e)
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'is_valid': False,
                'validation_error': str(e)
            }
    
    def generate_metrics(self, hostname: str, cert_data: dict) -> List[dict]:
        """Generate certificate metrics with FULL details."""
        metrics = []
        timestamp = int(time.time() * 1000)
        
        base_dims = {
            'monitoring_host': MONITORING_HOST_NAME,
            'hostname': hostname,
            'port': 443
        }
        
        if cert_data.get('success'):
            # Add all certificate details to dimensions
            base_dims.update({
                'days_until_expiry': cert_data.get('days_until_expiry', -1),
                'expiry_date': cert_data.get('expiry_date'),
                'issue_date': cert_data.get('issue_date'),
                'issuer': str(cert_data.get('issuer', {})),
                'subject': str(cert_data.get('subject', {})),
                'is_self_signed': 1 if cert_data.get('is_self_signed') else 0,
                'has_hostname_mismatch': 1 if cert_data.get('has_hostname_mismatch') else 0,
                'is_valid': 1,
                'tls_version': cert_data.get('tls_version', 'Unknown'),
                'cipher_suite': cert_data.get('cipher_suite', 'Unknown'),
                'has_weak_protocol': 1 if cert_data.get('has_weak_protocol') else 0,
                'has_weak_cipher': 1 if cert_data.get('has_weak_cipher') else 0
            })
            
            days_until_expiry = cert_data.get('days_until_expiry', -1)
            
            # Determine severity
            if days_until_expiry < 0:
                severity = 'critical'
                status = 'expired'
            elif days_until_expiry < 7:
                severity = 'critical'
                status = 'expiring_soon'
            elif days_until_expiry < 30:
                severity = 'warning'
                status = 'expiring'
            else:
                severity = 'healthy'
                status = 'valid'
            
            base_dims['severity'] = severity
            base_dims['status'] = status
            
            metrics.append({
                'metric': 'security.certificate.expiry.days',
                'value': days_until_expiry,
                'dimensions': base_dims,
                'timestamp': timestamp
            })
        
        else:
            # Certificate check failed
            base_dims.update({
                'is_valid': 0,
                'validation_error': cert_data.get('error', 'Unknown error'),
                'severity': 'critical',
                'status': 'invalid'
            })
            
            metrics.append({
                'metric': 'security.certificate.check_failed',
                'value': 1,
                'dimensions': base_dims,
                'timestamp': timestamp
            })
        
        return metrics


# ===================================================================
#  SECURITY MONITORING (Simplified - keeping core functionality)
# ===================================================================
class CentralLogServerConnector:
    """
    Connects to central Windows Event Log server to collect events from multiple hosts.
    """
    
    def __init__(self, config: dict):
        self.config = config
        multi_host_config = config.get('security_monitoring', {}).get('multi_host', {})
        central_server = multi_host_config.get('central_server', {})
        
        # Read credentials from config (plain text)
        self.credentials = {
            'user': central_server.get('username', ''),
            'password': central_server.get('password', ''),
            'domain': central_server.get('domain', '')
        }
        
        if not self.credentials['user'] or not self.credentials['password']:
            print("[WARNING] Central log server credentials not configured in config file")
    
    def collect_events_from_host(self, central_server_ip: str, source_host: str,
                                  log_name: str, event_ids: List[int],
                                  lookback_minutes: int = 5) -> List[dict]:
        """
        Collect events from a specific source host via central log server.
        """
        if not IS_WINDOWS:
            return []
        
        events = []
        
        try:
            # Initialize COM for this thread
            pythoncom.CoInitialize()
            
            # Connect to central server's WMI
            connection_string = f"\\\\{central_server_ip}\\root\\cimv2"
            c = wmi.WMI(computer=central_server_ip,
                       user=self.credentials['user'],
                       password=self.credentials['password'])
            
            # Calculate time window
            time_cutoff = datetime.now() - timedelta(minutes=lookback_minutes)
            wmi_time = time_cutoff.strftime('%Y%m%d%H%M%S.000000+000')
            
            # Query for events from specific source host
            query = f"""
                SELECT * FROM Win32_NTLogEvent
                WHERE Logfile = '{log_name}'
                AND ComputerName = '{source_host}'
                AND TimeGenerated >= '{wmi_time}'
                AND EventCode IN ({','.join(map(str, event_ids))})
            """
            
            wmi_events = c.query(query)
            
            for event in wmi_events:
                events.append({
                    'event_id': event.EventCode,
                    'source_host': event.ComputerName,
                    'central_server': central_server_ip,
                    'monitoring_host': MONITORING_HOST_NAME,
                    'timestamp': event.TimeGenerated,
                    'log_name': log_name,
                    'message': event.Message or '',
                    'event_type': event.Type,
                    'category': event.Category,
                    'user': event.User or 'N/A',
                    'insertion_strings': event.InsertionStrings or []
                })
            
            pythoncom.CoUninitialize()
            
            with PRINT_LOCK:
                print(f"[CentralLogServer] Collected {len(events)} events from {source_host} via {central_server_ip}")
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[CentralLogServer] Error collecting from {source_host}: {e}")
            try:
                pythoncom.CoUninitialize()
            except:
                pass
        
        return events


class SecurityEventMonitor:
    """Security event monitoring."""
    
    def __init__(self, config: dict, dynatrace: DatabaseIngestion, 
                 central_connector: Optional[CentralLogServerConnector] = None,
                 mfa_tracker=None):
        self.config = config
        self.database = dynatrace
        self.central_connector = central_connector
        self.mfa_tracker = mfa_tracker
        
        multi_host_config = config.get('security_monitoring', {}).get('multi_host', {})
        self.use_central_logging = multi_host_config.get('enabled', False)
        self.central_server_ip = multi_host_config.get('central_server', {}).get('ip')
        
        monitored_hosts_config = multi_host_config.get('monitored_hosts', [])
        self.monitored_hosts = [
            h.get('name', MONITORING_HOST_NAME) 
            for h in monitored_hosts_config 
            if h.get('enabled', True)
        ]
        
        if not self.monitored_hosts:
            self.monitored_hosts = [MONITORING_HOST_NAME]
    
    def collect_and_send_security_events(self):
        """Collect security events with 3-minute interval for firewall drops."""
        all_metrics = []
        
        current_time = time.time()
        
        # Check if 3 minutes have passed since last firewall collection
        with SECURITY_STATE_LOCK:
            last_firewall_time = SECURITY_STATE.get('last_firewall_collection', 0)
            should_collect_firewall = (current_time - last_firewall_time) >= 180  # 3 minutes
        
        if self.use_central_logging and self.central_connector:
            for source_host in self.monitored_hosts:
                metrics = self._collect_from_central_server(source_host, should_collect_firewall)
                all_metrics.extend(metrics)
        else:
            metrics = self._collect_local_security_events(should_collect_firewall)
            all_metrics.extend(metrics)
        
        # Update last firewall collection time if we collected firewall events
        if should_collect_firewall:
            with SECURITY_STATE_LOCK:
                SECURITY_STATE['last_firewall_collection'] = current_time
        
        if all_metrics:
            self.database.add_metrics(all_metrics)
            with PRINT_LOCK:
                print(f"[Security] Sent {len(all_metrics)} security metrics")
    
    def _collect_from_central_server(self, source_host: str, collect_firewall: bool) -> List[dict]:
        """Collect events from central server."""
        metrics = []
        
        # Always collect failed logon events
        failed_logon_events = self.central_connector.collect_events_from_host(
            central_server_ip=self.central_server_ip,
            source_host=source_host,
            log_name='Security',
            event_ids=[4625],
            lookback_minutes=5
        )
        
        for event in failed_logon_events:
            metric = self._create_failed_logon_metric(event)
            if metric:
                metrics.append(metric)
        
        # Only collect firewall events every 3 minutes
        if collect_firewall:
            firewall_events = self.central_connector.collect_events_from_host(
                central_server_ip=self.central_server_ip,
                source_host=source_host,
                log_name='Security',
                event_ids=[5152],
                lookback_minutes=3  # 3-minute lookback
            )
            
            for event in firewall_events:
                metric = self._create_firewall_drop_metric(event)
                if metric:
                    metrics.append(metric)
        
        return metrics
    
    def _collect_local_security_events(self, collect_firewall: bool) -> List[dict]:
        """Collect events from local Windows Event Log - ENHANCED with all security events."""
        if not IS_WINDOWS:
            return []
        
        metrics = []
        
        try:
            hand = win32evtlog.OpenEventLog(None, 'Security')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            time_cutoff = datetime.now() - timedelta(minutes=5)
            firewall_cutoff = datetime.now() - timedelta(minutes=3)
            
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                
                for event in events:
                    event_time = event.TimeGenerated.replace(tzinfo=None)
                    
                    # Failed Logon - Event ID 4625
                    if event.EventID == 4625 and event_time >= time_cutoff:
                        metric = self._create_failed_logon_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # Firewall drops - Only every 3 minutes
                    elif event.EventID == 5152 and collect_firewall and event_time >= firewall_cutoff:
                        metric = self._create_firewall_drop_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # Successful Logon - Event ID 4624
                    elif event.EventID == 4624 and event_time >= time_cutoff:
                        metric = self._create_successful_logon_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # Logoff - Event ID 4634
                    elif event.EventID == 4634 and event_time >= time_cutoff:
                        metric = self._create_logoff_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # User-initiated Logoff - Event ID 4647
                    elif event.EventID == 4647 and event_time >= time_cutoff:
                        metric = self._create_user_logoff_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # Privileged Logon - Event ID 4672
                    elif event.EventID == 4672 and event_time >= time_cutoff:
                        metric = self._create_privileged_logon_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # Account Management Events
                    elif event.EventID == 4720 and event_time >= time_cutoff:
                        metric = self._create_account_created_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    
                    # Track MFA events if tracker is available
                    if self.mfa_tracker:
                        if event.EventID == 6272:  # MFA success
                            event_dict = {
                                'EventID': event.EventID,
                                'TimeGenerated': str(event.TimeGenerated),
                                'SourceName': event.SourceName if hasattr(event, 'SourceName') else 'Unknown'
                            }
                            self.mfa_tracker.add_event('success', event_dict)
                        elif event.EventID == 6273:  # MFA failure
                            event_dict = {
                                'EventID': event.EventID,
                                'TimeGenerated': str(event.TimeGenerated),
                                'SourceName': event.SourceName if hasattr(event, 'SourceName') else 'Unknown'
                            }
                            self.mfa_tracker.add_event('failure', event_dict)
                        elif event.EventID == 4776:  # Credential validation
                            event_dict = {
                                'EventID': event.EventID,
                                'TimeGenerated': str(event.TimeGenerated),
                                'SourceName': event.SourceName if hasattr(event, 'SourceName') else 'Unknown'
                            }
                            self.mfa_tracker.add_event('credential_validation', event_dict)
                    elif event.EventID == 4722 and event_time >= time_cutoff:
                        metric = self._create_account_enabled_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    elif event.EventID == 4725 and event_time >= time_cutoff:
                        metric = self._create_account_disabled_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    elif event.EventID == 4726 and event_time >= time_cutoff:
                        metric = self._create_account_deleted_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    elif event.EventID == 4738 and event_time >= time_cutoff:
                        metric = self._create_account_changed_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # Password Events
                    elif event.EventID == 4723 and event_time >= time_cutoff:
                        metric = self._create_password_change_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    elif event.EventID == 4724 and event_time >= time_cutoff:
                        metric = self._create_password_reset_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # Group Membership Events
                    elif event.EventID in [4732, 4733, 4756, 4757] and event_time >= time_cutoff:
                        metric = self._create_group_membership_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # Security Group Events
                    elif event.EventID in [4751, 4752] and event_time >= time_cutoff:
                        metric = self._create_security_group_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)
                    
                    # MFA Events
                    elif event.EventID in [6272, 6273, 4776] and event_time >= time_cutoff:
                        metric = self._create_mfa_metric_from_win32(event)
                        if metric:
                            metrics.append(metric)

                            # ✅ NEW v4.7: Track in MFA Health Tracker
                            if self.mfa_tracker:
                                try:
                                    strings = self._extract_strings_from_event(event)
                                    user = self._extract_value(strings, ['TargetUserName', 'UserName'], 'SYSTEM')
                                    self.mfa_tracker.add_mfa_event(
                                        event_type='mfa_event',
                                        user=user,
                                        event_id=event.EventID
                                    )
                                except Exception as e:
                                    pass  # Silently continue if tracking fails
                    
                    if event_time < firewall_cutoff:
                        break
            
            win32evtlog.CloseEventLog(hand)
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Security] Error collecting local events: {e}")
        
        return metrics
    
    def _create_failed_logon_metric(self, event: dict) -> Optional[dict]:
        """Create COMPLETE failed logon metric with ALL fields populated."""
        try:
            strings = event.get('insertion_strings', [])
            
            if len(strings) < 20:
                return None
            
            # Extract ALL relevant fields from Event ID 4625
            target_user = strings[5] if len(strings) > 5 else 'Unknown'
            target_domain = strings[6] if len(strings) > 6 else ''
            source_ip = strings[19] if len(strings) > 19 else '0.0.0.0'
            source_port = strings[20] if len(strings) > 20 else '0'
            logon_type_code = strings[10] if len(strings) > 10 else 'Unknown'
            
            # Get failure reason from multiple possible fields
            raw_failure_reason = strings[8] if len(strings) > 8 else 'Unknown'
            status_code = strings[7] if len(strings) > 7 else None
            sub_status = strings[9] if len(strings) > 9 else None
            
            # Translate failure reason to human-readable format
            failure_reason = translate_failure_reason(raw_failure_reason)
            
            if 'Unmapped' in failure_reason and status_code:
                status_translation = translate_failure_reason(status_code)
                if 'Unmapped' not in status_translation:
                    failure_reason = status_translation
                elif sub_status:
                    sub_status_translation = translate_failure_reason(sub_status)
                    if 'Unmapped' not in sub_status_translation:
                        failure_reason = sub_status_translation
            
            logon_type_name = get_logon_type_name(logon_type_code)
            
            # Process name and workstation name
            process_name = strings[11] if len(strings) > 11 else 'N/A'
            workstation_name = strings[13] if len(strings) > 13 else 'N/A'
            
            timestamp = int(time.time() * 1000)
            
            # Build complete dimensions with NO NULL values
            full_target_user = f"{target_domain}\\{target_user}" if target_domain else target_user
            
            try:
                source_port_int = int(source_port) if source_port else None
            except:
                source_port_int = None
            
            return {
                'metric': 'security.unauthorized_access.attempt',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'source_host': event.get('source_host', MONITORING_HOST_NAME),
                    'central_server': event.get('central_server', 'local'),
                    'target_user': full_target_user,
                    'source_ip': source_ip,
                    'source_port': source_port,
                    'logon_type': logon_type_name,
                    'failure_reason': failure_reason,
                    'event_id': '4625',
                    'process_name': process_name,
                    'workstation_name': workstation_name,
                    'raw_status': raw_failure_reason,
                    'status_code': status_code if status_code else 'N/A',
                    'sub_status': sub_status if sub_status else 'N/A'
                },
                'timestamp': timestamp
            }
        # ✅ Added deduplication
            event_dict = {
                'event_id': '4625',
                'source_ip': strings[19],
                'target_user': strings[5],
                'timestamp': event.get('timestamp', '')
            }

            event_hash = create_event_hash(event_dict)

            if is_event_already_processed(None, event_hash):
                return None  # Skip duplicate

            mark_event_as_processed(None, event_hash)
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Security] Error creating failed logon metric: {e}")
            return None
            
    def _create_firewall_drop_metric(self, event: dict) -> Optional[dict]:
        """Create COMPLETE firewall drop metric with ALL fields populated."""
        try:
            strings = event.get('insertion_strings', [])
            
            if len(strings) < 8:
                return None
            
            # Extract ALL firewall drop fields from Event ID 5152
            process_id = strings[0] if len(strings) > 0 else '0'
            application = strings[1] if len(strings) > 1 else 'System'
            direction = strings[2] if len(strings) > 2 else 'Inbound'
            source_ip = strings[3] if len(strings) > 3 else '0.0.0.0'
            source_port = strings[4] if len(strings) > 4 else '0'
            dest_ip = strings[5] if len(strings) > 5 else '0.0.0.0'
            dest_port = strings[6] if len(strings) > 6 else '0'
            protocol = strings[7] if len(strings) > 7 else '6'
            
            # Additional fields if available
            filter_id = strings[8] if len(strings) > 8 else 'N/A'
            layer_name = strings[9] if len(strings) > 9 else 'N/A'
            
            protocol_map = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPv6'}
            protocol_name = protocol_map.get(protocol, f'Protocol{protocol}')
            
            try:
                source_port_int = int(source_port)
            except:
                source_port_int = 0
            
            try:
                dest_port_int = int(dest_port)
            except:
                dest_port_int = 0
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.firewall.drop',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'source_host': event.get('source_host', MONITORING_HOST_NAME),
                    'central_server': event.get('central_server', 'local'),
                    'source_ip': source_ip,
                    'source_port': str(source_port_int),
                    'dest_ip': dest_ip,
                    'dest_port': str(dest_port_int),
                    'protocol': protocol_name,
                    'direction': direction,
                    'event_id': '5152',
                    'application': application,
                    'process_id': process_id,
                    'filter_id': filter_id,
                    'layer_name': layer_name
                },
                'timestamp': timestamp
            }
            # ✅ Added deduplication with full event details
            event_dict = {
                'event_id': '5152',
                'source_ip': source_ip,
                'source_port': source_port,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'protocol': protocol,
                'timestamp': event.get('timestamp', '')
            }

            event_hash = create_event_hash(event_dict)

            if is_event_already_processed(None, event_hash):
                return None  # Skip duplicate

            mark_event_as_processed(None, event_hash)
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Security] Error creating firewall metric: {e}")
            return None
    
    def _create_failed_logon_metric_from_win32(self, event) -> Optional[dict]:
        """Helper to create metric from win32evtlog event object."""
        try:
            strings = event.StringInserts or []
            
            event_dict = {
                'event_id': event.EventID,
                'source_host': MONITORING_HOST_NAME,
                'central_server': 'local',
                'timestamp': event.TimeGenerated.isoformat(),
                'insertion_strings': list(strings)
            }
            
            return self._create_failed_logon_metric(event_dict)
            record_number = event.RecordNumber
            event_hash = create_event_hash(event_dict)

            if is_event_already_processed(record_number, event_hash):
                return None

            mark_event_as_processed(record_number, event_hash)
        except:
            return None
    
    def _create_firewall_drop_metric_from_win32(self, event) -> Optional[dict]:
        """Helper to create firewall metric from win32evtlog event object."""
        try:
            strings = event.StringInserts or []
            
            event_dict = {
                'event_id': event.EventID,
                'source_host': MONITORING_HOST_NAME,
                'central_server': 'local',
                'timestamp': event.TimeGenerated.isoformat(),
                'insertion_strings': list(strings)
            }
            
            return self._create_firewall_drop_metric(event_dict)
            # ✅ Same dual-check approach
            record_number = event.RecordNumber
            event_hash = create_event_hash(event_dict)

            if is_event_already_processed(record_number, event_hash):
                return None

            mark_event_as_processed(record_number, event_hash)
        except:
            return None
    
    def _create_successful_logon_metric_from_win32(self, event) -> Optional[dict]:
        """Create successful logon metric (Event ID 4624)."""
        try:
            strings = event.StringInserts or []
            
            if len(strings) < 20:
                return None
            
            target_user = strings[5] if len(strings) > 5 else 'Unknown'
            target_domain = strings[6] if len(strings) > 6 else ''
            logon_type_code = strings[8] if len(strings) > 8 else 'Unknown'
            source_ip = strings[18] if len(strings) > 18 else '0.0.0.0'
            workstation_name = strings[11] if len(strings) > 11 else 'N/A'
            
            logon_type_name = get_logon_type_name(logon_type_code)
            full_target_user = f"{target_domain}\\{target_user}" if target_domain else target_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.successful_logon',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'target_user': full_target_user,
                    'source_ip': source_ip,
                    'logon_type': logon_type_name,
                    'event_id': '4624',
                    'workstation_name': workstation_name
                },
                'timestamp': timestamp
            }
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Security] Error creating successful logon metric: {e}")
            return None
    
    def _create_mfa_metric_from_win32(self, event) -> Optional[dict]:
        """
        ✅ FIXED: Create MFA/Credential Validation event metric from win32evtlog event.
        
        Event ID 4776: Credential Validation (NTLM)
        Event ID 6272: MFA/PEAP Authentication Success
        Event ID 6273: MFA/PEAP Authentication Failure
        """
        try:
            strings = event.StringInserts or []
            
            # Map event IDs to event types
            event_map = {
                6272: 'mfa_success',
                6273: 'mfa_failure', 
                4776: 'credential_validation'
            }
            
            event_type = event_map.get(event.EventID, 'unknown')
            
            # Extract user information based on event type
            if event.EventID == 4776:
                # ✅ FIXED: Event 4776 String Layout:
                # String[0] = Authentication Package (e.g., "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0")
                # String[1] = Logon Account (USERNAME - this is what we need!)
                # String[2] = Source Workstation (hostname)
                # String[3] = Error Code (0x0 = success, anything else = failure)
                
                auth_package = strings[0] if len(strings) > 0 else 'Unknown'
                user = strings[1] if len(strings) > 1 else 'Unknown'  # ✅ FIXED: Was strings[0]
                source_workstation = strings[2] if len(strings) > 2 else MONITORING_HOST_NAME
                error_code = strings[3] if len(strings) > 3 else '0x0'
                
                # Determine if success or failure based on error code
                is_success = error_code in ['0x0', '0x00000000', '']
                if not is_success:
                    event_type = 'credential_validation_failure'
                    severity = 'high'
                else:
                    event_type = 'credential_validation_success'
                    severity = 'low'
                
                dimensions = {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'user': user,
                    'source_host': source_workstation,
                    'auth_package': auth_package,
                    'error_code': error_code,
                    'event_id': str(event.EventID),
                    'severity': severity
                }
                
            elif event.EventID in [6272, 6273]:
                # Event 6272/6273: PEAP Authentication
                # String[0] = User
                # String[1] = Fully Qualified Distinguished Name
                # String[2] = Authentication Server
                # String[3] = Authentication Type
                
                user = strings[0] if len(strings) > 0 else 'Unknown'
                auth_server = strings[2] if len(strings) > 2 else MONITORING_HOST_NAME
                auth_type = strings[3] if len(strings) > 3 else 'PEAP'
                
                severity = 'low' if event.EventID == 6272 else 'high'
                
                dimensions = {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'user': user,
                    'source_host': auth_server,
                    'auth_type': auth_type,
                    'event_id': str(event.EventID),
                    'severity': severity
                }
            
            else:
                # Fallback for unknown event types
                user = strings[0] if len(strings) > 0 else 'Unknown'
                dimensions = {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'user': user,
                    'event_id': str(event.EventID),
                    'severity': 'medium'
                }
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': f'security.{event_type}',
                'value': 1,
                'dimensions': dimensions,
                'timestamp': timestamp
            }
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Security] Error creating MFA metric for Event {event.EventID}: {e}")
            return None

    
    # ============================================================================
    # NEW ACCOUNT MANAGEMENT EVENT HANDLERS
    # ============================================================================
    
    def _create_logoff_metric_from_win32(self, event) -> Optional[dict]:
        """Create logoff metric (Event ID 4634)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[1] if len(strings) > 1 else 'Unknown'
            target_domain = strings[2] if len(strings) > 2 else ''
            logon_type_code = strings[4] if len(strings) > 4 else 'Unknown'
            
            logon_type_name = get_logon_type_name(logon_type_code)
            full_user = f"{target_domain}\\{target_user}" if target_domain else target_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.logoff',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'user': full_user,
                    'logon_type': logon_type_name,
                    'event_id': '4634'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_user_logoff_metric_from_win32(self, event) -> Optional[dict]:
        """Create user-initiated logoff metric (Event ID 4647)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[1] if len(strings) > 1 else 'Unknown'
            target_domain = strings[2] if len(strings) > 2 else ''
            
            full_user = f"{target_domain}\\{target_user}" if target_domain else target_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.user_logoff',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'user': full_user,
                    'event_id': '4647',
                    'logoff_type': 'user_initiated'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_privileged_logon_metric_from_win32(self, event) -> Optional[dict]:
        """Create privileged logon metric (Event ID 4672)."""
        try:
            strings = event.StringInserts or []
            
            subject_user = strings[1] if len(strings) > 1 else 'Unknown'
            subject_domain = strings[2] if len(strings) > 2 else ''
            privileges = strings[4] if len(strings) > 4 else 'N/A'
            
            full_user = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.admin_logon',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'user': full_user,
                    'privileges': privileges,
                    'event_id': '4672',
                    'severity': 'high'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_account_created_metric_from_win32(self, event) -> Optional[dict]:
        """Create account created metric (Event ID 4720)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[0] if len(strings) > 0 else 'Unknown'
            target_domain = strings[1] if len(strings) > 1 else ''
            subject_user = strings[4] if len(strings) > 4 else 'Unknown'
            subject_domain = strings[5] if len(strings) > 5 else ''
            
            full_target = f"{target_domain}\\{target_user}" if target_domain else target_user
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.account_created',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'target_user': full_target,
                    'subject_user': full_subject,
                    'event_id': '4720',
                    'severity': 'medium'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_account_enabled_metric_from_win32(self, event) -> Optional[dict]:
        """Create account enabled metric (Event ID 4722)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[0] if len(strings) > 0 else 'Unknown'
            target_domain = strings[1] if len(strings) > 1 else ''
            subject_user = strings[4] if len(strings) > 4 else 'Unknown'
            subject_domain = strings[5] if len(strings) > 5 else ''
            
            full_target = f"{target_domain}\\{target_user}" if target_domain else target_user
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.account_enabled',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'target_user': full_target,
                    'subject_user': full_subject,
                    'event_id': '4722',
                    'severity': 'medium'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_account_disabled_metric_from_win32(self, event) -> Optional[dict]:
        """Create account disabled metric (Event ID 4725)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[0] if len(strings) > 0 else 'Unknown'
            target_domain = strings[1] if len(strings) > 1 else ''
            subject_user = strings[4] if len(strings) > 4 else 'Unknown'
            subject_domain = strings[5] if len(strings) > 5 else ''
            
            full_target = f"{target_domain}\\{target_user}" if target_domain else target_user
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.account_disabled',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'target_user': full_target,
                    'subject_user': full_subject,
                    'event_id': '4725',
                    'severity': 'medium'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_account_deleted_metric_from_win32(self, event) -> Optional[dict]:
        """Create account deleted metric (Event ID 4726)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[0] if len(strings) > 0 else 'Unknown'
            target_domain = strings[1] if len(strings) > 1 else ''
            subject_user = strings[4] if len(strings) > 4 else 'Unknown'
            subject_domain = strings[5] if len(strings) > 5 else ''
            
            full_target = f"{target_domain}\\{target_user}" if target_domain else target_user
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.account_deleted',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'target_user': full_target,
                    'subject_user': full_subject,
                    'event_id': '4726',
                    'severity': 'high'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_account_changed_metric_from_win32(self, event) -> Optional[dict]:
        """Create account changed metric (Event ID 4738)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[0] if len(strings) > 0 else 'Unknown'
            target_domain = strings[1] if len(strings) > 1 else ''
            subject_user = strings[4] if len(strings) > 4 else 'Unknown'
            subject_domain = strings[5] if len(strings) > 5 else ''
            
            full_target = f"{target_domain}\\{target_user}" if target_domain else target_user
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.account_changed',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'target_user': full_target,
                    'subject_user': full_subject,
                    'event_id': '4738',
                    'severity': 'low'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_password_change_metric_from_win32(self, event) -> Optional[dict]:
        """Create password change metric (Event ID 4723)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[0] if len(strings) > 0 else 'Unknown'
            target_domain = strings[1] if len(strings) > 1 else ''
            subject_user = strings[4] if len(strings) > 4 else 'Unknown'
            subject_domain = strings[5] if len(strings) > 5 else ''
            
            full_target = f"{target_domain}\\{target_user}" if target_domain else target_user
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.password_change',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'target_user': full_target,
                    'subject_user': full_subject,
                    'event_id': '4723',
                    'severity': 'low'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_password_reset_metric_from_win32(self, event) -> Optional[dict]:
        """Create password reset metric (Event ID 4724)."""
        try:
            strings = event.StringInserts or []
            
            target_user = strings[0] if len(strings) > 0 else 'Unknown'
            target_domain = strings[1] if len(strings) > 1 else ''
            subject_user = strings[4] if len(strings) > 4 else 'Unknown'
            subject_domain = strings[5] if len(strings) > 5 else ''
            
            full_target = f"{target_domain}\\{target_user}" if target_domain else target_user
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.password_reset',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'target_user': full_target,
                    'subject_user': full_subject,
                    'event_id': '4724',
                    'severity': 'medium'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_group_membership_metric_from_win32(self, event) -> Optional[dict]:
        """Create group membership change metric (Event IDs 4732, 4733, 4756, 4757)."""
        try:
            strings = event.StringInserts or []
            
            event_map = {
                4732: 'User added to local group',
                4733: 'User removed from local group',
                4756: 'User added to domain local group',
                4757: 'User removed from domain local group'
            }
            
            action = event_map.get(event.EventID, 'Group membership changed')
            
            member_user = strings[0] if len(strings) > 0 else 'Unknown'
            group_name = strings[2] if len(strings) > 2 else 'Unknown'
            subject_user = strings[6] if len(strings) > 6 else 'Unknown'
            subject_domain = strings[7] if len(strings) > 7 else ''
            
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.group_membership',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'member_user': member_user,
                    'group_name': group_name,
                    'subject_user': full_subject,
                    'action': action,
                    'event_id': str(event.EventID),
                    'severity': 'medium'
                },
                'timestamp': timestamp
            }
        except:
            return None
    
    def _create_security_group_metric_from_win32(self, event) -> Optional[dict]:
        """Create security group event metric (Event IDs 4751, 4752)."""
        try:
            strings = event.StringInserts or []
            
            event_map = {
                4751: 'Security-enabled global group created',
                4752: 'Security-enabled global group changed'
            }
            
            action = event_map.get(event.EventID, 'Security group modified')
            
            group_name = strings[0] if len(strings) > 0 else 'Unknown'
            subject_user = strings[4] if len(strings) > 4 else 'Unknown'
            subject_domain = strings[5] if len(strings) > 5 else ''
            
            full_subject = f"{subject_domain}\\{subject_user}" if subject_domain else subject_user
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': 'security.security_group',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'group_name': group_name,
                    'subject_user': full_subject,
                    'action': action,
                    'event_id': str(event.EventID),
                    'severity': 'medium'
                },
                'timestamp': timestamp
            }
        except:
            return None

class EndpointThreatMonitor:
    """Monitors Windows Defender for endpoint threat detections."""
    
    def __init__(self, config: dict, dynatrace: DatabaseIngestion):
        self.config = config
        self.database = dynatrace
    
    def collect_threat_events(self) -> List[dict]:
        """Collect Windows Defender threat events."""
        if not IS_WINDOWS:
            return []
        
        metrics = []
        
        try:
            hand = win32evtlog.OpenEventLog(None, 'Microsoft-Windows-Windows Defender/Operational')
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            time_cutoff = datetime.now() - timedelta(minutes=5)
            
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                
                for event in events:
                    event_time = event.TimeGenerated.replace(tzinfo=None)
                    if event_time < time_cutoff:
                        break
                    
                    if event.EventID in [1116, 1117, 1118, 1119]:
                        metric = self._create_threat_metric(event)
                        if metric:
                            metrics.append(metric)
            
            win32evtlog.CloseEventLog(hand)
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[EndpointThreat] Error collecting events: {e}")
        
        return metrics
    
    def _create_threat_metric(self, event) -> Optional[dict]:
        """Create per-event threat detection metric."""
        try:
            event_id_map = {
                1116: 'detected',
                1117: 'removed',
                1118: 'not_removed',
                1119: 'defender_error'
            }
            
            threat_status = event_id_map.get(event.EventID, 'unknown')
            
            strings = event.StringInserts or []
            threat_name = strings[0] if len(strings) > 0 else 'Unknown'
            
            timestamp = int(time.time() * 1000)
            
            return {
                'metric': f'security.endpoint_threat.{threat_status}',
                'value': 1,
                'dimensions': {
                    'monitoring_host': MONITORING_HOST_NAME,
                    'threat_name': threat_name,
                    'event_id': str(event.EventID),
                    'source': 'WindowsDefender'
                },
                'timestamp': timestamp
            }
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[EndpointThreat] Error creating metric: {e}")
            return None
        
class AuditTrailMonitor:
    """
    Monitors audit logging status and health.
    """
    
    def __init__(self, config: dict, dynatrace: DatabaseIngestion):
        self.config = config
        self.database = dynatrace
    
    def collect_audit_health_metrics(self) -> List[dict]:
        """Collect audit logging health metrics."""
        metrics = []
        
        # Check audit policy configuration
        audit_status = self._check_audit_policy()
        if audit_status:
            metrics.append(audit_status)
        
        return metrics
    
    def _check_audit_policy(self) -> Optional[dict]:
        """Check Windows audit policy status."""
        if not IS_WINDOWS:
            return None
        
        try:
            # Check audit policy using auditpol command
            result = subprocess.run(
                ['auditpol', '/get', '/category:*'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Count enabled audit categories
                enabled_count = result.stdout.count('Success and Failure') + result.stdout.count('Success') + result.stdout.count('Failure')
                
                timestamp = int(time.time() * 1000)
                
                return {
                    'metric': 'security.audit_policy.enabled_categories',
                    'value': enabled_count,
                    'dimensions': {
                        'monitoring_host': MONITORING_HOST_NAME,
                        'status': 'healthy' if enabled_count > 20 else 'degraded'
                    },
                    'timestamp': timestamp
                }
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[AuditTrail] Error checking audit policy: {e}")
        
        return None


class PacketLossMonitor:
    """Comprehensive packet loss detection using ICMP ping."""
    
    def __init__(self, config: dict, dynatrace: DatabaseIngestion):
        self.config = config
        self.database = dynatrace
    
    def measure_packet_loss(self, target: str, count: int = 5) -> dict:
        """Measure packet loss using ICMP ping."""
        results = {}
        
        icmp_loss = self._measure_icmp_loss(target, count)
        if icmp_loss is not None:
            results['icmp_loss_pct'] = icmp_loss
        
        return results
    
    def _measure_icmp_loss(self, target: str, count: int) -> Optional[float]:
        """Measure packet loss using ICMP ping."""
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ['ping', '-n', str(count), target],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', str(count), target],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            match = re.search(r'(\d+)% loss', result.stdout)
            if match:
                return float(match.group(1))
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[PacketLoss] ICMP error: {e}")
        
        return None
    
    def generate_metrics(self, target: str, packet_loss_data: dict) -> List[dict]:
        """Generate metrics from packet loss data."""
        metrics = []
        timestamp = int(time.time() * 1000)
        
        base_dims = {
            'monitoring_host': MONITORING_HOST_NAME,
            'target': target
        }
        
        if 'icmp_loss_pct' in packet_loss_data:
            loss = packet_loss_data['icmp_loss_pct']
            if loss > 5:
                severity = 'critical'
            elif loss > 2:
                severity = 'high'
            elif loss > 0.5:
                severity = 'medium'
            else:
                severity = 'low'
            
            metrics.append({
                'metric': 'network.packet_loss.icmp.pct',
                'value': loss,
                'dimensions': {**base_dims, 'severity': severity},
                'timestamp': timestamp
            })
        
        return metrics

class ThroughputMonitor:
    """Network throughput monitoring using interface statistics."""
    
    def __init__(self, config: dict, dynatrace: DatabaseIngestion):
        self.config = config
        self.database = dynatrace
        self.last_stats = {}
    
    def measure_interface_throughput(self) -> List[dict]:
        """Measure throughput for all network interfaces."""
        metrics = []
        timestamp = int(time.time() * 1000)
        
        try:
            net_io = psutil.net_io_counters(pernic=True)
            current_time = time.time()
            
            for interface, stats in net_io.items():
                if interface.startswith('lo') or interface.startswith('veth'):
                    continue
                
                if interface in self.last_stats:
                    last_time, last_stats = self.last_stats[interface]
                    time_diff = current_time - last_time
                    
                    if time_diff > 0:
                        bytes_sent = stats.bytes_sent - last_stats.bytes_sent
                        bytes_recv = stats.bytes_recv - last_stats.bytes_recv
                        
                        mbps_sent = (bytes_sent * 8) / (time_diff * 1_000_000)
                        mbps_recv = (bytes_recv * 8) / (time_diff * 1_000_000)
                        
                        base_dims = {
                            'monitoring_host': MONITORING_HOST_NAME,
                            'interface': interface
                        }
                        
                        metrics.append({
                            'metric': 'network.throughput.sent.mbps',
                            'value': round(mbps_sent, 3),
                            'dimensions': base_dims,
                            'timestamp': timestamp
                        })
                        
                        metrics.append({
                            'metric': 'network.throughput.received.mbps',
                            'value': round(mbps_recv, 3),
                            'dimensions': base_dims,
                            'timestamp': timestamp
                        })
                
                self.last_stats[interface] = (current_time, stats)
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Throughput] Error: {e}")
        
        return metrics
class LatencyMonitor:
    """Network latency monitoring using ICMP ping."""
    
    def __init__(self, config: dict, dynatrace: DatabaseIngestion):
        self.config = config
        self.database = dynatrace
    
    def measure_latency(self, target: str, count: int = 5) -> Optional[float]:
        """Measure ICMP latency in milliseconds."""
        try:
            if IS_WINDOWS:
                result = subprocess.run(
                    ['ping', '-n', str(count), target],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            else:
                result = subprocess.run(
                    ['ping', '-c', str(count), target],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
            
            match = re.search(r'Average = (\d+)ms', result.stdout)
            if match:
                return float(match.group(1))
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Latency] Error: {e}")
        
        return None
    
    def generate_metric(self, target: str, latency_ms: float) -> dict:
        """Generate latency metric."""
        timestamp = int(time.time() * 1000)
        
        if latency_ms > 100:
            severity = 'high'
        elif latency_ms > 50:
            severity = 'medium'
        else:
            severity = 'low'
        
        return {
            'metric': 'network.latency.icmp.ms',
            'value': latency_ms,
            'dimensions': {
                'monitoring_host': MONITORING_HOST_NAME,
                'target': target,
                'severity': severity
            },
            'timestamp': timestamp
        }


class DNSMonitor:
    """DNS resolution performance monitoring."""
    
    def __init__(self, config: dict, dynatrace: DatabaseIngestion):
        self.config = config
        self.database = dynatrace
    
    def measure_dns_resolution(self, domain: str, dns_server: str = None) -> Optional[float]:
        """Measure DNS resolution time in milliseconds."""
        try:
            import time
            
            start_time = time.time()
            
            if dns_server:
                import dns.resolver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.resolve(domain)
            else:
                socket.gethostbyname(domain)
            
            end_time = time.time()
            return (end_time - start_time) * 1000
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[DNS] Error resolving {domain}: {e}")
        
        return None
    
    def generate_metric(self, domain: str, dns_server: str, resolution_time_ms: float) -> dict:
        """Generate DNS resolution metric."""
        timestamp = int(time.time() * 1000)
        
        if resolution_time_ms > 1000:
            severity = 'critical'
        elif resolution_time_ms > 500:
            severity = 'high'
        elif resolution_time_ms > 100:
            severity = 'medium'
        else:
            severity = 'low'
        
        return {
            'metric': 'network.dns.resolution.ms',
            'value': resolution_time_ms,
            'dimensions': {
                'monitoring_host': MONITORING_HOST_NAME,
                'domain': domain,
                'dns_server': dns_server or 'system',
                'severity': severity
            },
            'timestamp': timestamp
        }
class BankingVulnerabilityScanner:
    """
    Built-in vulnerability scanner focused on banking/financial security.
    Runs checks relevant to your environment without needing external tools.
    """
    
    def __init__(self, config: dict, dynatrace):
        self.config = config
        self.database = dynatrace
        
        # Scan configuration
        scan_config = config.get('vulnerability_scanner', {})
        self.enabled = scan_config.get('enabled', False)
        self.scan_interval_minutes = scan_config.get('scan_interval_minutes', 60)
        self.last_scan_time = None
        
        # Targets from applications config
        self.scan_targets = self._extract_scan_targets()
        
        # Dangerous ports that should NOT be open
        self.dangerous_ports = [
            21,    # FTP (unencrypted)
            23,    # Telnet (unencrypted)
            25,    # SMTP (often abused)
            135,   # Windows RPC
            139,   # NetBIOS
            445,   # SMB (common attack vector)
            1433,  # SQL Server
            3306,  # MySQL
            3389,  # RDP (should be behind VPN)
            5432,  # PostgreSQL
            5900,  # VNC
            6379,  # Redis (if exposed)
            27017, # MongoDB (if exposed)
        ]
        
        # Safe/expected ports
        self.expected_ports = [
            80,    # HTTP
            443,   # HTTPS
            22,    # SSH (acceptable if configured properly)
        ]
        
    def _calculate_cvss_score(self, finding_type: str, severity: str) -> float:
        """Calculate CVSS score based on finding type and severity."""
        # Base scores by severity
        base_scores = {
            'critical': 9.0,
            'high': 7.5,
            'medium': 5.5,
            'low': 3.0
        }
        
        cvss_score = base_scores.get(severity, 5.0)
        
        # Adjust based on finding type
        adjustments = {
            'weak_tls_protocol': 0.5,
            'weak_cipher': 0.5,
            'open_dangerous_port': 0.3,
            'certificate_expiring_soon': -0.5 if severity != 'critical' else 0,
            'self_signed_certificate': 0.2,
            'certificate_hostname_mismatch': 0.3,
            'ssl_error': 0.4,
            'missing_security_header': 0.1,
            'information_disclosure': -0.5
        }
        
        cvss_score += adjustments.get(finding_type, 0)
        
        # Ensure score is within CVSS range 0.0-10.0
        return max(0.0, min(10.0, cvss_score))
    
    def _extract_scan_targets(self) -> List[dict]:
        """Extract scan targets from applications config."""
        targets = []
        
        applications = self.config.get('applications', [])
        for app in applications:
            if not app.get('enabled', True):
                continue
            
            url = app.get('url', '')
            name = app.get('name', 'unknown')
            
            if url:
                # Parse URL
                import urllib.parse
                parsed = urllib.parse.urlparse(url)
                
                targets.append({
                    'name': name,
                    'hostname': parsed.hostname,
                    'port': parsed.port or (443 if parsed.scheme == 'https' else 80),
                    'scheme': parsed.scheme,
                    'url': url
                })
        
        return targets
    
    def should_run_scan(self) -> bool:
        """Check if it's time to run a scan."""
        if not self.enabled:
            return False
        
        if self.last_scan_time is None:
            return True
        
        minutes_since_last = (datetime.now() - self.last_scan_time).total_seconds() / 60
        return minutes_since_last >= self.scan_interval_minutes
    
    def run_full_scan(self) -> List[dict]:
        """Run comprehensive vulnerability scan."""
        if not self.should_run_scan():
            return []
        
        with PRINT_LOCK:
            print(f"\n🔍 VULNERABILITY SCAN STARTING")
            print(f"{'─'*70}")
            print(f"  Scanning {len(self.scan_targets)} targets...")
        
        all_findings = []
        
        # Run scans in parallel for efficiency
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for target in self.scan_targets:
                # Port scan
                futures.append(
                    executor.submit(self._scan_ports, target)
                )
                
                # SSL/TLS scan
                if target['scheme'] == 'https':
                    futures.append(
                        executor.submit(self._scan_ssl_tls, target)
                    )
                    futures.append(
                        executor.submit(self._scan_certificate, target)
                    )
                
                # HTTP security headers
                futures.append(
                    executor.submit(self._scan_http_headers, target)
                )
            
            # Collect results
            for future in concurrent.futures.as_completed(futures):
                try:
                    findings = future.result()
                    if findings:
                        all_findings.extend(findings)
                except Exception as e:
                    with PRINT_LOCK:
                        print(f"[VulnScan] Error: {e}")
        
        self.last_scan_time = datetime.now()
        
        # Generate metrics
        metrics = self._generate_vulnerability_metrics(all_findings)
        
        # Display findings
        self._display_findings(all_findings)
        
        return metrics
    
    def _scan_ports(self, target: dict) -> List[dict]:
        """✅ FIXED: Scan for open ports with FULL details in dimensions."""
        findings = []
        hostname = target['hostname']
        
        for port in self.dangerous_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((hostname, port))
                sock.close()
                
                if result == 0:
                    # Port is open - create finding with port number
                    findings.append({
                        'target': target['name'],
                        'hostname': hostname,
                        'type': 'open_dangerous_port',
                        'severity': 'high',
                        'port': port,
                        'protocol': 'TCP',
                        'cipher_suite': 'Not applicable',  # ✅ Port scans don't involve ciphers
                        'description': f'Dangerous port {port} is open and accessible',
                        'recommendation': f'Close port {port} or restrict access via firewall'
                    })
            except:
                pass
    
        return findings
    
    def _scan_ssl_tls(self, target: dict) -> List[dict]:
        """✅ FIXED: Scan SSL/TLS with protocol and cipher details."""
        findings = []
        hostname = target['hostname']
        port = target['port']
        
        try:
            # Check for weak protocols
            weak_protocols = [
                ('SSLv2', ssl.PROTOCOL_SSLv23),
                ('SSLv3', ssl.PROTOCOL_SSLv23),
                ('TLSv1.0', ssl.PROTOCOL_TLSv1),
                ('TLSv1.1', ssl.PROTOCOL_TLSv1_1),
            ]

            for protocol_name, protocol in weak_protocols:
                try:
                    context = ssl.SSLContext(protocol)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            # Get cipher information for this protocol
                            cipher = ssock.cipher()
                            cipher_name = cipher[0] if cipher else 'Unknown'
                            
                            findings.append({
                                'target': target['name'],
                                'hostname': hostname,
                                'type': 'weak_tls_protocol',
                                'severity': 'high',
                                'port': port,
                                'protocol': 'TLS',
                                'tls_protocol': tls_version,
                                'cipher_suite': cipher_name, 
                                'description': f'Weak protocol {protocol_name} is supported with cipher: {cipher_name}',
                                'recommendation': 'Disable weak protocols, use TLS 1.2+ only'
                            })
                except:
                    pass
            
            # Check cipher suites
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    if cipher:
                        cipher_name = cipher[0]
                        tls_version = ssock.version()
                        
                        weak_cipher_patterns = [
                            'DES', 'RC4', 'MD5', 'NULL', 'EXPORT', 'anon'
                        ]
                        
                        for weak_pattern in weak_cipher_patterns:
                            if weak_pattern in cipher_name.upper():
                                findings.append({
                                    'target': target['name'],
                                    'hostname': hostname,
                                    'type': 'weak_cipher',
                                    'severity': 'high',
                                    'port': port,  # ✅ CRITICAL
                                    'protocol': 'TLS',  # ✅ CRITICAL
                                    'cipher_suite': cipher_name,  # ✅ CRITICAL
                                    'tls_protocol': 'Not applicable',  # ✅ CRITICAL
                                    'description': f'Weak cipher suite in use: {cipher_name}',
                                    'recommendation': 'Configure strong cipher suites only'
                                })
                                break
        
        except Exception as e:
            pass
        
        return findings
    
    def _scan_certificate(self, target: dict) -> List[dict]:
        """Scan certificate configuration."""
        findings = []
        hostname = target['hostname']
        port = target['port']
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiry
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expire_date - datetime.now()).days
                        
                        if days_until_expiry < 7:
                            findings.append({
                                'target': target['name'],
                                'hostname': hostname,
                                'type': 'certificate_expiring_soon',
                                'severity': severity,
                                'port': port,
                                'protocol': 'TLS',
                                'cipher_suite': 'Not scanned',  # ✅ Certificate scan doesn't check ciphers
                                'days': days_until_expiry,
                                'description': f'Certificate expires in {days_until_expiry} days',
                                'recommendation': 'Renew certificate immediately'
                            })
                        elif days_until_expiry < 30:
                            findings.append({
                                'target': target['name'],
                                'hostname': hostname,
                                'type': 'certificate_expiring_soon',
                                'severity': severity,
                                'port': port,
                                'protocol': 'TLS',
                                'cipher_suite': 'Not scanned',  # ✅ Certificate scan doesn't check ciphers
                                'days': days_until_expiry,
                                'description': f'Certificate expires in {days_until_expiry} days',
                                'recommendation': 'Renew certificate immediately'
                            })

                    
                    # Check if self-signed
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    
                    if issuer == subject:
                        findings.append({
                            'target': target['name'],
                            'hostname': hostname,
                            'type': 'self_signed_certificate',
                            'severity': 'medium',
                            'port': port,
                            'protocol': 'TLS',
                            'cipher_suite': 'Not scanned',  # ✅ Certificate scan doesn't check ciphers
                            'description': 'Certificate is self-signed',
                            'recommendation': 'Use certificate from trusted CA'
                        })
                    
                    # Check hostname mismatch
                    cert_hostnames = []
                    for field in cert.get('subjectAltName', []):
                        if field[0] == 'DNS':
                            cert_hostnames.append(field[1])
                    
                    if hostname not in cert_hostnames and subject.get('commonName') != hostname:
                        findings.append({
                            'target': target['name'],
                            'hostname': hostname,
                            'type': 'certificate_hostname_mismatch',
                            'severity': 'high',
                            'port': port,
                            'protocol': 'TLS',
                            'cipher_suite': 'Not scanned',  # ✅ Certificate scan doesn't check ciphers
                            'description': f'Certificate not valid for {hostname}',
                            'recommendation': 'Use certificate with correct hostname'
                        })
        
        except ssl.SSLError as e:
            findings.append({
                'target': target['name'],
                'hostname': hostname,
                'type': 'ssl_error',
                'severity': 'high',
                'port': port,
                'protocol': 'TLS',
                'cipher_suite': 'Not scanned',  # ✅ Certificate scan doesn't check ciphers
                'description': f'SSL error: {str(e)}',
                'recommendation': 'Fix SSL configuration'
            })
        except Exception as e:
            pass
        
        return findings
    
    def _scan_http_headers(self, target: dict) -> List[dict]:
        """✅ FIXED: Scan HTTP security headers with ACTUAL TLS information capture."""
        findings = []
        url = target['url']
        
        try:
            # Parse URL to get components
            from urllib.parse import urlparse
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            # Initialize TLS variables
            tls_version = 'Not applicable'
            cipher_suite = 'Not applicable'
            
            # Only capture TLS details for HTTPS targets
            if parsed.scheme == 'https':
                try:
                    # Make a separate TLS connection to capture protocol and cipher details
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            tls_version = ssock.version()
                            cipher = ssock.cipher()
                            cipher_suite = cipher[0] if cipher else 'Unknown'
                            
                            # Debug output to verify TLS capture
                            with PRINT_LOCK:
                                print(f"[TLS-Debug] {target['name']}: {tls_version}, {cipher_suite}")
                except Exception as e:
                    with PRINT_LOCK:
                        print(f"[TLS-Debug] Failed to get TLS details for {hostname}: {e}")
                    tls_version = 'Unknown'
                    cipher_suite = 'Unknown'
            
            # Now make the HTTP request to check headers (with TLS details captured)
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            # Required security headers
            required_headers = {
                'Strict-Transport-Security': {
                    'severity': 'high',
                    'description': 'HSTS header missing - vulnerable to protocol downgrade attacks'
                },
                'X-Frame-Options': {
                    'severity': 'medium', 
                    'description': 'X-Frame-Options missing - vulnerable to clickjacking'
                },
                'X-Content-Type-Options': {
                    'severity': 'medium',
                    'description': 'X-Content-Type-Options missing - MIME type sniffing possible'
                },
                'Content-Security-Policy': {
                    'severity': 'medium',
                    'description': 'CSP header missing - vulnerable to XSS attacks'
                },
                'X-XSS-Protection': {
                    'severity': 'low',
                    'description': 'X-XSS-Protection missing'
                }
            }
            
            for header, details in required_headers.items():
                if header not in headers:
                    findings.append({
                        'target': target['name'],
                        'hostname': hostname,
                        'type': 'missing_security_header',
                        'severity': details['severity'],
                        'port': port,
                        'protocol': parsed.scheme.upper(),
                        'cipher_suite': cipher_suite,  # ✅ Now contains ACTUAL cipher
                        'tls_protocol': tls_version,   # ✅ Now contains ACTUAL TLS version
                        'missing_header': header,
                        'description': details['description'],
                        'recommendation': f'Add {header} security header'
                    })
            
            # Check for information disclosure
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in disclosure_headers:
                if header in headers:
                    findings.append({
                        'target': target['name'],
                        'hostname': hostname,
                        'type': 'information_disclosure',
                        'severity': 'low',
                        'port': port,
                        'protocol': parsed.scheme.upper(),
                        'cipher_suite': cipher_suite,  # ✅ Now contains ACTUAL cipher
                        'tls_protocol': tls_version,   # ✅ Now contains ACTUAL TLS version
                        'missing_header': header,  # Reuse this field for disclosed header
                        'description': f'Server information disclosed: {headers[header]}',
                        'recommendation': f'Remove or obfuscate {header} header'
                    })
        
        except Exception as e:
            # Log error but don't fail completely
            with PRINT_LOCK:
                print(f"[HTTPHeaderScan] Error scanning {url}: {e}")
        
        return findings
    
    def _generate_vulnerability_metrics(self, findings: List[dict]) -> List[dict]:
        """✅ FIXED: Generate metrics with ALL required fields populated."""
        metrics = []
        timestamp = int(time.time() * 1000)
        
        # CREATE INDIVIDUAL METRICS FOR EACH FINDING
        for finding in findings:
            # Extract all finding details
            target = finding.get('target', 'Unknown')
            hostname = finding.get('hostname', None)
            finding_type = finding.get('type', 'general')
            severity = finding.get('severity', 'medium')
            
            # ✅ CRITICAL: Extract technical details with defaults
            port = finding.get('port', None)
            protocol = finding.get('protocol', None)
            cipher_suite = finding.get('cipher_suite', 'Not detected')  # ✅ DEFAULT VALUE
            tls_protocol = finding.get('tls_protocol', None)
            missing_header = finding.get('missing_header', None)
            
            description = finding.get('description', '')
            recommendation = finding.get('recommendation', '')
            
            # ✅ CRITICAL FIX: Try to resolve hostname to IP if not provided
            target_ip = None
            if hostname:
                try:
                    target_ip = socket.gethostbyname(hostname)
                except:
                    target_ip = None
            
            # ✅ CRITICAL FIX: Calculate risk score based on severity
            risk_score_map = {
                'critical': 10,
                'high': 7,
                'medium': 4,
                'low': 2
            }
            risk_score = risk_score_map.get(severity, 5)
            
            # ✅ NEW: Calculate CVSS score
            cvss_score = self._calculate_cvss_score(finding_type, severity)
            
            # Create dimension object with ALL finding details
            dimensions = {
                'monitoring_host': MONITORING_HOST_NAME,
                'target': target,
                'target_hostname': hostname,
                'target_ip': target_ip,
                'finding_type': finding_type,
                'severity': severity,
                'description': description[:500] if description else 'No description',
                'recommendation': recommendation[:500] if recommendation else 'Review and remediate',
                'risk_score': risk_score,
                'cvss_score': round(cvss_score, 1)
            }
            
            # Add ALL technical fields with proper defaults
            dimensions['port'] = port if port is not None else 0
            dimensions['protocol'] = protocol if protocol else 'Not applicable'
            dimensions['cipher_suite'] = cipher_suite if cipher_suite and cipher_suite != 'Not detected' else 'Not applicable'
            dimensions['tls_protocol'] = tls_protocol if tls_protocol else 'Not applicable'
            dimensions['missing_header'] = missing_header if missing_header else 'Not applicable'
            
            # Create metric for this specific finding
            metrics.append({
                'metric': f'vulnerability.finding.{finding_type}',
                'value': 1,
                'dimensions': dimensions,
                'timestamp': timestamp
            })
        
        # ALSO create summary metrics (for dashboards)
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in findings:
            severity = finding.get('severity', 'medium')
            severity_counts[severity] += 1
        
        # Summary metrics
        for severity, count in severity_counts.items():
            if count > 0:
                metrics.append({
                    'metric': 'vulnerability.findings.summary',
                    'value': count,
                    'dimensions': {
                        'monitoring_host': MONITORING_HOST_NAME,
                        'severity': severity,
                        'scan_type': 'built_in'
                    },
                    'timestamp': timestamp
                })
        
        with PRINT_LOCK:
            print(f"[VulnScan] ✅ Generated {len(metrics)} metrics ({len(findings)} findings + {len(severity_counts)} summaries)")
        
        return metrics
    
    def _display_findings(self, findings: List[dict]):
        """Display vulnerability findings."""
        if not findings:
            with PRINT_LOCK:
                print(f"  ✅ No vulnerabilities found!")
            return
        
        # Group by severity
        critical = [f for f in findings if f['severity'] == 'critical']
        high = [f for f in findings if f['severity'] == 'high']
        medium = [f for f in findings if f['severity'] == 'medium']
        low = [f for f in findings if f['severity'] == 'low']
        
        with PRINT_LOCK:
            if critical:
                print(f"\n  🔴 CRITICAL FINDINGS ({len(critical)}):")
                for finding in critical[:5]:
                    print(f"     └─ {finding['target']}: {finding['description']}")
            
            if high:
                print(f"\n  🟠 HIGH SEVERITY ({len(high)}):")
                for finding in high[:5]:
                    print(f"     └─ {finding['target']}: {finding['description']}")
            
            if medium:
                print(f"\n  🟡 MEDIUM SEVERITY ({len(medium)}):")
                for finding in medium[:3]:
                    print(f"     └─ {finding['target']}: {finding['description']}")
            
            if low:
                print(f"\n  🟢 LOW SEVERITY ({len(low)}):")
                for finding in low[:3]:
                    print(f"     └─ {finding['target']}: {finding['description']}")
            
            total = len(findings)
            vuln_score = (
                len(critical) * 10 +
                len(high) * 5 +
                len(medium) * 2 +
                len(low) * 1
            )
            
            print(f"\n  📊 Total Findings: {total} | Vulnerability Score: {vuln_score}")
            print()

# ===================================================================
#                    MAIN ENHANCED EDGE AGENT
# ===================================================================

# ===================================================================
#                    MAIN ENHANCED EDGE AGENT - COMPLETE
# ===================================================================

class EnhancedEdgeAgent:
    """
    ✅ COMPLETE Enhanced Edge Agent v4.6
    Uses Enhanced Network Monitors for full metric collection
    """
    
    def __init__(self, config_file: str):
        print(f"[EdgeAgent] Initializing Enhanced Edge Agent v4.6")
        
        # Load configuration with proper encoding
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f)
            print(f"[Config] ✅ Configuration loaded successfully")
        except UnicodeDecodeError:
            # Try with different encoding if UTF-8 fails
            try:
                with open(config_file, 'r', encoding='cp1252') as f:
                    self.config = yaml.safe_load(f)
                print(f"[Config] ✅ Configuration loaded with cp1252 encoding")
            except Exception as e:
                print(f"[Config] ❌ Failed to load config: {e}")
                sys.exit(1)
        except Exception as e:
            print(f"[Config] ❌ Failed to load config: {e}")
            sys.exit(1)
        
        # Initialize SQL Server Database integration
        self.database = DatabaseIngestion(self.config)
        
        # Initialize central log connector if multi-host enabled
        multi_host_config = self.config.get('security_monitoring', {}).get('multi_host', {})
        if multi_host_config.get('enabled', False):
            self.central_connector = CentralLogServerConnector(self.config)
        else:
            self.central_connector = None
        
        # Initialize security monitors
        self.mfa_tracker = MFAHealthTracker()  # ✅ NEW v4.7
        
        self.security_monitor = SecurityEventMonitor(
            self.config, 
            self.database, 
            self.central_connector,
            mfa_tracker=self.mfa_tracker  # ✅ NEW v4.7
        )
        self.endpoint_threat_monitor = EndpointThreatMonitor(self.config, self.database)
        self.audit_monitor = AuditTrailMonitor(self.config, self.database)
        self.enhanced_audit_monitor = EnhancedAuditTrailMonitor(self.config, self.database, self.central_connector)
        
        # Initialize vulnerability scanner
        self.vuln_scanner = BankingVulnerabilityScanner(self.config, self.database)
        
        # ✅ CRITICAL FIX: Initialize ENHANCED network monitors (not simple ones)
        # These monitors provide complete metrics with target_ip, jitter, direction, etc.
        self.enhanced_latency_monitor = EnhancedLatencyMonitor(self.config, self.database)
        self.enhanced_packet_loss_monitor = EnhancedPacketLossMonitor(self.config, self.database)
        self.enhanced_dns_monitor = EnhancedDNSMonitor(self.config, self.database)
        self.enhanced_throughput_monitor = EnhancedThroughputMonitor(self.config, self.database)
        
        # Initialize certificate and application monitors
        self.cert_monitor = CertificateMonitor(self.config, self.database)
        self.app_monitor = ApplicationPerformanceMonitor(self.config, self.database)
        
        # Monitoring state
        self.running = False
        self.cycle_count = 0
        
        print(f"[EdgeAgent] ✅ Initialization complete")
        print(f"[EdgeAgent] 📊 Using Enhanced Network Monitors (Latency, Packet Loss, DNS, Throughput)")
    
    def run_monitoring_cycle(self):
        """Execute one complete monitoring cycle with ENHANCED monitors."""
        self.cycle_count += 1
        
        with PRINT_LOCK:
            print(f"\n{'='*80}")
            print(f"[Cycle {self.cycle_count}] Starting monitoring cycle at {datetime.now()}")
            print(f"{'='*80}")
        
        # PRIORITY 1: Security Event Monitoring
        try:
            with PRINT_LOCK:
                print(f"\n🔐 SECURITY EVENT MONITORING")
                print(f"{'─'*80}")
            self.security_monitor.collect_and_send_security_events()
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Security] ❌ Error in security monitoring: {e}")
        
        # PRIORITY 2: Endpoint Threat Detection
        try:
            threat_metrics = self.endpoint_threat_monitor.collect_threat_events()
            if threat_metrics:
                self.database.add_metrics(threat_metrics)
                with PRINT_LOCK:
                    print(f"[EndpointThreat] ✅ Collected {len(threat_metrics)} threat events")
        except Exception as e:
            with PRINT_LOCK:
                print(f"[EndpointThreat] ❌ Error: {e}")
        
        # PRIORITY 3: Application Performance Monitoring
        try:
            applications = self.config.get('applications', [])
            with PRINT_LOCK:
                print(f"\n🌐 APPLICATION PERFORMANCE MONITORING")
                print(f"{'─'*80}")
            
            app_metrics = []
            for app in applications:
                if app.get('enabled', True):
                    app_results = self.app_monitor.test_application(app)
                    metrics = self.app_monitor.generate_metrics(app_results)
                    app_metrics.extend(metrics)
                    
                    # Display results
                    with PRINT_LOCK:
                        status_icon = "✅" if app_results['success'] else "❌"
                        print(f"  {status_icon} {app_results['name']}")
                        print(f"     URL: {app_results['url']}")
                        print(f"     Response Time: {app_results['total_time_ms']:.2f}ms")
                        print(f"     Status Code: {app_results['status_code']}")
                        if 'error' in app_results:
                            print(f"     Error: {app_results['error']}")
                        print()
            
            if app_metrics:
                with PRINT_LOCK:
                    print(f"[AppMonitor] 📤 Sending {len(app_metrics)} application metrics...")
                self.database.add_metrics(app_metrics)
                self.database.flush()
                with PRINT_LOCK:
                    print(f"[AppMonitor] ✅ Application metrics sent successfully!")
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[AppMonitor] ❌ Error: {e}")
        
        

        # =================================================================================
        # PRIORITY 3.5: INFRASTRUCTURE HEALTH MONITORING (✅ NEW v4.7)
        # =================================================================================
        try:
            with PRINT_LOCK:
                print(f"\n🏗️  INFRASTRUCTURE HEALTH MONITORING")
                print(f"{'─'*80}")
            
            # Get infrastructure targets from configuration
            internet_config = self.config.get('internet', {})
            infrastructure_targets = internet_config.get('infrastructure_targets', [])
            
            # Filter enabled targets only
            active_targets = [t for t in infrastructure_targets if t.get('enabled', True)]
            
            if not active_targets:
                with PRINT_LOCK:
                    print(f"  ℹ️  No infrastructure targets enabled in configuration")
            else:
                with PRINT_LOCK:
                    print(f"  📊 Monitoring {len(active_targets)} infrastructure target(s)")
            
            infrastructure_metrics = []
            
            # Monitor each infrastructure device
            for target_config in active_targets:
                try:
                    target_ip = target_config.get('ip')
                    target_name = target_config.get('name', 'Unknown')
                    
                    if not target_ip:
                        with PRINT_LOCK:
                            print(f"  ⚠️  Skipping {target_name} - no IP address configured")
                        continue
                    
                    with PRINT_LOCK:
                        print(f"  🔍 Monitoring {target_name} ({target_ip})...")
                    
                    # Measure latency and jitter
                    latency_metrics = self.enhanced_latency_monitor.measure_latency_with_jitter(
                        target_ip, target_name, count=5
                    )
                    infrastructure_metrics.extend(latency_metrics)
                    
                    # Measure packet loss
                    packet_loss_metrics = self.enhanced_packet_loss_monitor.measure_packet_loss(
                        target_ip, target_name, count=5
                    )
                    infrastructure_metrics.extend(packet_loss_metrics)
                    
                    # ✅ ADDED: Measure DNS resolution for infrastructure targets
                    if target_config.get('dns_measurement', True):
                        dns_metrics = self.enhanced_dns_monitor.measure_dns_resolution(target_ip)
                        infrastructure_metrics.extend(dns_metrics)
                    
                except Exception as e:
                    with PRINT_LOCK:
                        print(f"  ❌ Error monitoring {target_config.get('name', 'Unknown')}: {e}")
            
            # ✅ ADDED: Measure local interface throughput (separate from infrastructure targets)
            try:
                with PRINT_LOCK:
                    print(f"  📊 Measuring local interface throughput...")
                
                throughput_metrics = self.enhanced_throughput_monitor.measure_interface_throughput()
                if throughput_metrics:
                    infrastructure_metrics.extend(throughput_metrics)
                    with PRINT_LOCK:
                        print(f"  ✅ Collected {len(throughput_metrics)} throughput metrics")
                else:
                    with PRINT_LOCK:
                        print(f"  ⚠️  No throughput metrics collected (first run)")
            except Exception as e:
                with PRINT_LOCK:
                    print(f"  ❌ Error measuring throughput: {e}")
            
            # Send ALL infrastructure metrics
            if infrastructure_metrics:
                with PRINT_LOCK:
                    print(f"  📤 Sending {len(infrastructure_metrics)} infrastructure metrics...")
                    # Show breakdown of what we're sending
                    latency_count = sum(1 for m in infrastructure_metrics if 'latency' in m.get('metric', ''))
                    packet_loss_count = sum(1 for m in infrastructure_metrics if 'packet_loss' in m.get('metric', ''))
                    throughput_count = sum(1 for m in infrastructure_metrics if 'throughput' in m.get('metric', ''))
                    dns_count = sum(1 for m in infrastructure_metrics if 'dns' in m.get('metric', ''))
                    print(f"  📊 Breakdown: {latency_count} latency, {packet_loss_count} packet_loss, {throughput_count} throughput, {dns_count} DNS")
                
                self.database.add_metrics(infrastructure_metrics)
                with PRINT_LOCK:
                    print(f"  ✅ Infrastructure metrics sent successfully!")
            
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Infrastructure] ❌ Error: {e}")
            traceback.print_exc()
    
    
        # PRIORITY 4: Enhanced Network Monitoring
        try:
            with PRINT_LOCK:
                print(f"\n📡 ENHANCED NETWORK MONITORING")
                print(f"{'─'*80}")
            
            all_network_metrics = []
            
            # ✅ ENHANCED Latency & Jitter Monitoring
            with PRINT_LOCK:
                print(f"\n⏱️  LATENCY & JITTER MONITORING")
                print(f"{'─'*80}")
            
            latency_targets = [
                ('8.8.8.8', 'Google DNS'),
                ('1.1.1.1', 'Cloudflare DNS')
            ]
            
            for target_ip, target_name in latency_targets:
                latency_metrics = self.enhanced_latency_monitor.measure_latency_with_jitter(
                    target=target_ip,
                    target_name=target_name,
                    count=10
                )
                all_network_metrics.extend(latency_metrics)
            
            # ✅ ENHANCED Packet Loss Monitoring
            with PRINT_LOCK:
                print(f"\n📉 PACKET LOSS MONITORING")
                print(f"{'─'*80}")
            
            for target_ip, target_name in latency_targets:
                packet_loss_metrics = self.enhanced_packet_loss_monitor.measure_packet_loss(
                    target=target_ip,
                    target_name=target_name,
                    count=20
                )
                all_network_metrics.extend(packet_loss_metrics)
            
            # ✅ ENHANCED Throughput & Utilization Monitoring
            with PRINT_LOCK:
                print(f"\n📊 THROUGHPUT & UTILIZATION MONITORING")
                print(f"{'─'*80}")
            
            throughput_metrics = self.enhanced_throughput_monitor.measure_interface_throughput()
            all_network_metrics.extend(throughput_metrics)
            
            # ✅ ENHANCED DNS Resolution Monitoring
            with PRINT_LOCK:
                print(f"\n🔍 DNS RESOLUTION MONITORING")
                print(f"{'─'*80}")
            
            dns_domains = ['google.com', 'microsoft.com']
            for domain in dns_domains:
                dns_metrics = self.enhanced_dns_monitor.measure_dns_resolution(domain)
                all_network_metrics.extend(dns_metrics)
            
            # Certificate Monitoring
            with PRINT_LOCK:
                print(f"\n🔒 SSL/TLS CERTIFICATE MONITORING")
                print(f"{'─'*80}")
            
            for app in applications:
                if app.get('enabled', True):
                    url = app.get('url', '')
                    if url.startswith('https://'):
                        hostname = url.split('//')[1].split('/')[0]
                        cert_data = self.cert_monitor.check_certificate(hostname)
                        cert_metrics = self.cert_monitor.generate_metrics(hostname, cert_data)
                        all_network_metrics.extend(cert_metrics)
                        
                        # Display certificate info
                        with PRINT_LOCK:
                            if cert_data.get('success'):
                                days = cert_data.get('days_until_expiry', -1)
                                if days < 7:
                                    icon = '🔴'
                                    status = 'CRITICAL'
                                elif days < 30:
                                    icon = '🟡'
                                    status = 'WARNING'
                                else:
                                    icon = '🟢'
                                    status = 'HEALTHY'
                                print(f"  {icon} {hostname}: {days} days until expiry [{status}]")
                            else:
                                print(f"  ❌ {hostname}: Certificate check failed")
            
            # Send all network metrics
            if all_network_metrics:
                with PRINT_LOCK:
                    print(f"\n[Network] 📤 Sending {len(all_network_metrics)} enhanced network metrics...")
                self.database.add_metrics(all_network_metrics)
                self.database.flush()
                with PRINT_LOCK:
                    print(f"[Network] ✅ Network metrics sent successfully!")
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[Network] ❌ Error in network monitoring: {e}")
                import traceback
                traceback.print_exc()
        
        # PRIORITY 5: Audit Trail & Logging Health Monitoring
        try:
            audit_metrics = self.enhanced_audit_monitor.check_logging_health()
            if audit_metrics:
                self.enhanced_audit_monitor.display_audit_health(audit_metrics)
                self.database.add_metrics(audit_metrics)
        except Exception as e:
            with PRINT_LOCK:
                print(f"[AuditHealth] ❌ Error: {e}")
        

        # =================================================================================
        # PRIORITY 5.5: MFA HEALTH METRICS COLLECTION (✅ NEW v4.7)
        # =================================================================================
        try:
            if self.mfa_tracker:
                with PRINT_LOCK:
                    print(f"\n🔐 MFA HEALTH MONITORING")
                    print(f"{'─'*80}")
                
                # Calculate MFA metrics from tracker
                mfa_metrics = self.mfa_tracker.calculate_mfa_metrics(MONITORING_HOST_NAME)
                
                if mfa_metrics:
                    # Get health status for display
                    health_status = self.mfa_tracker.get_health_status()
                    
                    # Determine status icon
                    status_icon = {
                        'healthy': '🟢',
                        'warning': '🟡',
                        'critical': '🔴',
                        'no_data': '⚪',
                        'no_mfa_events': '⚪'
                    }.get(health_status['status'], '⚪')
                    
                    # Display MFA health status
                    with PRINT_LOCK:
                        print(f"  {status_icon} MFA Health Status: {health_status['status'].upper()}")
                        print(f"     Success Rate: {health_status['success_rate']:.2f}%")
                        print(f"     Failure Count: {health_status['failure_count']}")
                        print(f"     Total MFA Events: {health_status['total_events']} (15min window)")
                        
                        if health_status['status'] == 'healthy':
                            print(f"     ✅ MFA system is operating normally")
                        elif health_status['status'] == 'warning':
                            print(f"     ⚠️  MFA success rate below optimal threshold")
                        elif health_status['status'] == 'critical':
                            print(f"     🚨 CRITICAL: MFA success rate critically low!")
                    
                    # Check for problematic users
                    problematic_users = self.mfa_tracker.get_user_failure_summary()
                    
                    if problematic_users:
                        with PRINT_LOCK:
                            print(f"\n  ⚠️  Users with High Failure Rates:")
                            for user_info in problematic_users:
                                user = user_info['user']
                                count = user_info['failure_count']
                                print(f"     🔴 {user}: {count} failures in 15min window")
                    
                    # Display metrics breakdown
                    with PRINT_LOCK:
                        print(f"\n  📊 MFA Metrics Generated: {len(mfa_metrics)} metrics")
                    
                    # Send metrics to database
                    with PRINT_LOCK:
                        print(f"[MFA] 📤 Sending {len(mfa_metrics)} MFA health metrics to database...")
                    
                    self.database.add_metrics(mfa_metrics)
                    self.database.flush()
                    
                    with PRINT_LOCK:
                        print(f"[MFA] ✅ MFA metrics sent successfully!")
        
        except Exception as e:
            with PRINT_LOCK:
                print(f"[MFA] ❌ Critical error in MFA health monitoring: {e}")
                import traceback
                traceback.print_exc()
        # PRIORITY 6: Vulnerability Scanning (runs periodically)
        try:
            if self.vuln_scanner.should_run_scan():
                vuln_metrics = self.vuln_scanner.run_full_scan()
                if vuln_metrics:
                    self.database.add_metrics(vuln_metrics)
        except Exception as e:
            with PRINT_LOCK:
                print(f"[VulnScan] ❌ Error: {e}")
        
        # Final flush of any remaining metrics
        self.database.flush()
        
        with PRINT_LOCK:
            print(f"\n{'='*80}")
            print(f"[Cycle {self.cycle_count}] ✅ Monitoring cycle completed")
            print(f"{'='*80}\n")
    
    def start(self):
        """Start the main monitoring loop."""
        self.running = True
        
        print(f"\n{'='*80}")
        print(f"[EdgeAgent] 🚀 Starting Enhanced Edge Agent v4.6")
        print(f"[EdgeAgent] Monitoring Host: {MONITORING_HOST_NAME} ({MONITORING_HOST_IP})")
        print(f"[EdgeAgent] Database: SQL Server Integration Enabled")
        print(f"[EdgeAgent] Enhanced Monitors: Latency+Jitter, Packet Loss, DNS, Throughput")
        print(f"[EdgeAgent] Press Ctrl+C to stop")
        print(f"{'='*80}\n")
        
        # Load persistent state on startup
        load_state_from_file()
        
        # Schedule periodic state cleanup and saving
        import threading
        
        def periodic_maintenance():
            """Background thread for state maintenance."""
            while self.running:
                time.sleep(3600)  # Every hour
                cleanup_old_state()
                save_state_to_file()
        
        maintenance_thread = threading.Thread(target=periodic_maintenance, daemon=True)
        maintenance_thread.start()
        
        try:
            while self.running:
                cycle_start = time.time()
                
                self.run_monitoring_cycle()
                
                # Calculate sleep time to maintain interval
                cycle_time = time.time() - cycle_start
                interval = self.config.get('monitoring', {}).get('interval_seconds', 60)
                sleep_time = max(1, interval - cycle_time)
                
                with PRINT_LOCK:
                    print(f"⏳ Sleeping for {sleep_time:.1f} seconds until next cycle...\n")
                
                time.sleep(sleep_time)
        
        except KeyboardInterrupt:
            print(f"\n[EdgeAgent] ℹ️  Shutting down gracefully...")
        except Exception as e:
            print(f"\n[EdgeAgent] ❌ Fatal error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # Save state before exiting
            save_state_to_file()
            self.running = False
            print(f"[EdgeAgent] 👋 Shutdown complete")


# ===================================================================
#                           MAIN ENTRY POINT
# ===================================================================

def main():
    """Main entry point."""
    if len(sys.argv) != 2:
        print("Usage: python Edge_agent_database.py <config_file.yaml>")
        sys.exit(1)

    config_file = sys.argv[1]

    if not os.path.exists(config_file):
        print(f"Error: Config file '{config_file}' not found")
        sys.exit(1)

    agent = EnhancedEdgeAgent(config_file)
    agent.start()


if __name__ == "__main__":
    main()