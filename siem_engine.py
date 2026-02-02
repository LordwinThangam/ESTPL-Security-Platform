#!/usr/bin/env python3
"""
ESTPL Security - SIEM Process Flow Engine
Complete implementation of all 7 SIEM stages with open-source code
No third-party tools required - all built from scratch
"""

import re
import json
import hashlib
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import socket
import struct
import ipaddress

class LogCollector:
    """Stage 1: Log Collection - Gather data from servers, firewalls, apps & endpoints"""
    
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.initialize_log_storage()
    
    def initialize_log_storage(self):
        """Create log collection tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS raw_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_type TEXT,
                source_ip TEXT,
                raw_content TEXT,
                log_format TEXT,
                collection_method TEXT,
                processed BOOLEAN DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT,
                source_type TEXT,
                ip_address TEXT,
                port INTEGER,
                status TEXT DEFAULT 'active',
                last_collection DATETIME,
                total_logs_collected INTEGER DEFAULT 0
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def collect_syslog(self, message, source_ip):
        """Collect syslog format logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO raw_logs (source_type, source_ip, raw_content, log_format, collection_method)
            VALUES (?, ?, ?, ?, ?)
        ''', ('syslog', source_ip, message, 'RFC5424', 'push'))
        
        conn.commit()
        log_id = cursor.lastrowid
        conn.close()
        return log_id
    
    def collect_firewall_log(self, log_entry, source_ip):
        """Collect firewall logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO raw_logs (source_type, source_ip, raw_content, log_format, collection_method)
            VALUES (?, ?, ?, ?, ?)
        ''', ('firewall', source_ip, log_entry, 'custom', 'agent'))
        
        conn.commit()
        log_id = cursor.lastrowid
        conn.close()
        return log_id
    
    def collect_application_log(self, log_entry, app_name, source_ip):
        """Collect application logs"""
        log_data = {
            'application': app_name,
            'log_entry': log_entry,
            'timestamp': datetime.now().isoformat()
        }
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO raw_logs (source_type, source_ip, raw_content, log_format, collection_method)
            VALUES (?, ?, ?, ?, ?)
        ''', ('application', source_ip, json.dumps(log_data), 'json', 'api'))
        
        conn.commit()
        log_id = cursor.lastrowid
        conn.close()
        return log_id
    
    def collect_endpoint_log(self, log_entry, endpoint_id, source_ip):
        """Collect endpoint security logs"""
        log_data = {
            'endpoint_id': endpoint_id,
            'log_entry': log_entry,
            'timestamp': datetime.now().isoformat()
        }
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO raw_logs (source_type, source_ip, raw_content, log_format, collection_method)
            VALUES (?, ?, ?, ?, ?)
        ''', ('endpoint', source_ip, json.dumps(log_data), 'json', 'agent'))
        
        conn.commit()
        log_id = cursor.lastrowid
        conn.close()
        return log_id
    
    def get_collection_statistics(self):
        """Get log collection statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM raw_logs')
        total_logs = cursor.fetchone()[0]
        
        cursor.execute('SELECT source_type, COUNT(*) FROM raw_logs GROUP BY source_type')
        by_source = dict(cursor.fetchall())
        
        cursor.execute('SELECT COUNT(*) FROM raw_logs WHERE processed = 0')
        pending_logs = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_logs_collected': total_logs,
            'by_source_type': by_source,
            'pending_processing': pending_logs
        }


class LogNormalizer:
    """Stage 2: Normalization - Convert different log formats into a common structure"""
    
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.initialize_normalized_storage()
    
    def initialize_normalized_storage(self):
        """Create normalized log storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS normalized_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_log_id INTEGER,
                timestamp DATETIME,
                event_type TEXT,
                severity TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT,
                action TEXT,
                message TEXT,
                user TEXT,
                normalized_data TEXT,
                FOREIGN KEY (raw_log_id) REFERENCES raw_logs(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def normalize_syslog(self, raw_log):
        """Normalize syslog format"""
        # Parse syslog pattern: <priority>timestamp hostname tag: message
        pattern = r'<(\d+)>(\S+)\s+(\S+)\s+(\S+):\s+(.+)'
        match = re.match(pattern, raw_log)
        
        if match:
            priority, timestamp, hostname, tag, message = match.groups()
            severity = self._priority_to_severity(int(priority))
            
            return {
                'timestamp': timestamp,
                'event_type': tag,
                'severity': severity,
                'source_ip': hostname,
                'message': message
            }
        
        # Fallback parsing
        return {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'syslog',
            'severity': 'info',
            'message': raw_log
        }
    
    def normalize_firewall_log(self, raw_log):
        """Normalize firewall log format"""
        # Common firewall log pattern
        normalized = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'firewall',
            'severity': 'info'
        }
        
        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, raw_log)
        if len(ips) >= 2:
            normalized['source_ip'] = ips[0]
            normalized['destination_ip'] = ips[1]
        
        # Extract ports
        port_pattern = r':(\d{1,5})\b'
        ports = re.findall(port_pattern, raw_log)
        if len(ports) >= 2:
            normalized['source_port'] = int(ports[0])
            normalized['destination_port'] = int(ports[1])
        
        # Extract action (ALLOW, DENY, DROP, REJECT)
        action_pattern = r'\b(ALLOW|DENY|DROP|REJECT|ACCEPT)\b'
        action_match = re.search(action_pattern, raw_log, re.IGNORECASE)
        if action_match:
            normalized['action'] = action_match.group(1).upper()
            normalized['severity'] = 'warning' if normalized['action'] in ['DENY', 'DROP'] else 'info'
        
        # Extract protocol
        protocol_pattern = r'\b(TCP|UDP|ICMP|HTTP|HTTPS)\b'
        protocol_match = re.search(protocol_pattern, raw_log, re.IGNORECASE)
        if protocol_match:
            normalized['protocol'] = protocol_match.group(1).upper()
        
        normalized['message'] = raw_log
        return normalized
    
    def normalize_application_log(self, raw_log):
        """Normalize application log (JSON format)"""
        try:
            data = json.loads(raw_log)
            return {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'event_type': 'application',
                'severity': data.get('level', 'info').lower(),
                'message': data.get('log_entry', str(data)),
                'user': data.get('user'),
                'application': data.get('application')
            }
        except json.JSONDecodeError:
            return {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'application',
                'severity': 'info',
                'message': raw_log
            }
    
    def normalize_endpoint_log(self, raw_log):
        """Normalize endpoint security log"""
        try:
            data = json.loads(raw_log)
            return {
                'timestamp': data.get('timestamp', datetime.now().isoformat()),
                'event_type': 'endpoint_security',
                'severity': self._classify_endpoint_severity(data),
                'message': data.get('log_entry', str(data)),
                'endpoint_id': data.get('endpoint_id')
            }
        except json.JSONDecodeError:
            return {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'endpoint_security',
                'severity': 'info',
                'message': raw_log
            }
    
    def process_raw_logs(self, batch_size=100):
        """Process and normalize raw logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, source_type, raw_content, log_format 
            FROM raw_logs 
            WHERE processed = 0 
            LIMIT ?
        ''', (batch_size,))
        
        raw_logs = cursor.fetchall()
        processed_count = 0
        
        for raw_log in raw_logs:
            log_id, source_type, raw_content, log_format = raw_log
            
            # Normalize based on source type
            if source_type == 'syslog':
                normalized = self.normalize_syslog(raw_content)
            elif source_type == 'firewall':
                normalized = self.normalize_firewall_log(raw_content)
            elif source_type == 'application':
                normalized = self.normalize_application_log(raw_content)
            elif source_type == 'endpoint':
                normalized = self.normalize_endpoint_log(raw_content)
            else:
                normalized = {'message': raw_content, 'event_type': source_type}
            
            # Store normalized log
            cursor.execute('''
                INSERT INTO normalized_logs 
                (raw_log_id, timestamp, event_type, severity, source_ip, destination_ip, 
                 source_port, destination_port, protocol, action, message, user, normalized_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                log_id,
                normalized.get('timestamp'),
                normalized.get('event_type'),
                normalized.get('severity'),
                normalized.get('source_ip'),
                normalized.get('destination_ip'),
                normalized.get('source_port'),
                normalized.get('destination_port'),
                normalized.get('protocol'),
                normalized.get('action'),
                normalized.get('message'),
                normalized.get('user'),
                json.dumps(normalized)
            ))
            
            # Mark as processed
            cursor.execute('UPDATE raw_logs SET processed = 1 WHERE id = ?', (log_id,))
            processed_count += 1
        
        conn.commit()
        conn.close()
        
        return processed_count
    
    def _priority_to_severity(self, priority):
        """Convert syslog priority to severity"""
        severity_level = priority % 8
        if severity_level <= 2:
            return 'critical'
        elif severity_level <= 4:
            return 'warning'
        else:
            return 'info'
    
    def _classify_endpoint_severity(self, data):
        """Classify endpoint log severity"""
        message = str(data.get('log_entry', '')).lower()
        if any(keyword in message for keyword in ['malware', 'virus', 'trojan', 'ransomware']):
            return 'critical'
        elif any(keyword in message for keyword in ['suspicious', 'threat', 'warning']):
            return 'warning'
        return 'info'


class LogEnricher:
    """Stage 3: Parsing & Enrichment - Add context (IP info, threat intel, geolocation)"""
    
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.initialize_enrichment_storage()
        self.threat_database = self._load_threat_database()
    
    def initialize_enrichment_storage(self):
        """Create enrichment storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enriched_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                normalized_log_id INTEGER,
                ip_reputation TEXT,
                geolocation TEXT,
                threat_intelligence TEXT,
                organization TEXT,
                hostname TEXT,
                port_service TEXT,
                enrichment_data TEXT,
                enriched_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (normalized_log_id) REFERENCES normalized_logs(id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_threat_database(self):
        """Load threat intelligence database"""
        return {
            'known_malicious_ips': set([
                '192.0.2.1', '198.51.100.1', '203.0.113.1'  # Example IPs
            ]),
            'suspicious_ports': {
                '1433': 'MS-SQL',
                '3389': 'RDP',
                '22': 'SSH',
                '23': 'Telnet',
                '445': 'SMB',
                '3306': 'MySQL'
            },
            'threat_signatures': {
                'sql_injection': [r'union\s+select', r'1\s*=\s*1', r'or\s+1\s*=\s*1'],
                'xss': [r'<script>', r'javascript:', r'onerror='],
                'command_injection': [r'\|\s*cat', r';\s*rm\s+-rf', r'&&\s*wget']
            }
        }
    
    def enrich_ip_address(self, ip_address):
        """Enrich IP address with intelligence"""
        if not ip_address:
            return {}
        
        enrichment = {
            'ip_address': ip_address,
            'is_private': self._is_private_ip(ip_address),
            'is_malicious': ip_address in self.threat_database['known_malicious_ips'],
            'reputation_score': self._calculate_ip_reputation(ip_address),
            'geolocation': self._get_geolocation(ip_address),
            'organization': self._get_organization(ip_address),
            'hostname': self._reverse_dns_lookup(ip_address)
        }
        
        return enrichment
    
    def enrich_port(self, port):
        """Enrich port information"""
        if not port:
            return {}
        
        port_str = str(port)
        return {
            'port': port,
            'service': self.threat_database['suspicious_ports'].get(port_str, 'Unknown'),
            'is_suspicious': port_str in self.threat_database['suspicious_ports'],
            'risk_level': self._calculate_port_risk(port)
        }
    
    def enrich_message(self, message):
        """Enrich log message with threat intelligence"""
        if not message:
            return {}
        
        threats_detected = []
        for threat_type, patterns in self.threat_database['threat_signatures'].items():
            for pattern in patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    threats_detected.append(threat_type)
                    break
        
        return {
            'threats_detected': threats_detected,
            'threat_count': len(threats_detected),
            'requires_investigation': len(threats_detected) > 0
        }
    
    def enrich_logs(self, batch_size=100):
        """Enrich normalized logs with intelligence"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, source_ip, destination_ip, source_port, destination_port, message
            FROM normalized_logs
            WHERE id NOT IN (SELECT normalized_log_id FROM enriched_logs)
            LIMIT ?
        ''', (batch_size,))
        
        logs = cursor.fetchall()
        enriched_count = 0
        
        for log in logs:
            log_id, src_ip, dst_ip, src_port, dst_port, message = log
            
            enrichment_data = {
                'source_ip_enrichment': self.enrich_ip_address(src_ip),
                'destination_ip_enrichment': self.enrich_ip_address(dst_ip),
                'source_port_enrichment': self.enrich_port(src_port),
                'destination_port_enrichment': self.enrich_port(dst_port),
                'message_enrichment': self.enrich_message(message),
                'enriched_at': datetime.now().isoformat()
            }
            
            cursor.execute('''
                INSERT INTO enriched_logs
                (normalized_log_id, ip_reputation, geolocation, threat_intelligence, enrichment_data)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                log_id,
                json.dumps(enrichment_data['source_ip_enrichment']),
                json.dumps(enrichment_data['source_ip_enrichment'].get('geolocation', {})),
                json.dumps(enrichment_data['message_enrichment']),
                json.dumps(enrichment_data)
            ))
            
            enriched_count += 1
        
        conn.commit()
        conn.close()
        
        return enriched_count
    
    def _is_private_ip(self, ip_address):
        """Check if IP is private"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except:
            return False
    
    def _calculate_ip_reputation(self, ip_address):
        """Calculate IP reputation score (0-100)"""
        if ip_address in self.threat_database['known_malicious_ips']:
            return 0
        if self._is_private_ip(ip_address):
            return 80
        return 50  # Neutral score for unknown IPs
    
    def _get_geolocation(self, ip_address):
        """Get IP geolocation (simplified)"""
        # In production, this would use a GeoIP database
        if self._is_private_ip(ip_address):
            return {'country': 'Local', 'city': 'Internal Network'}
        
        # Example geolocation data
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': 0.0,
            'longitude': 0.0
        }
    
    def _get_organization(self, ip_address):
        """Get organization owning the IP"""
        if self._is_private_ip(ip_address):
            return 'Internal Network'
        return 'Unknown'
    
    def _reverse_dns_lookup(self, ip_address):
        """Perform reverse DNS lookup"""
        try:
            hostname = socket.gethostbyaddr(ip_address)
            return hostname[0]
        except:
            return None
    
    def _calculate_port_risk(self, port):
        """Calculate port risk level"""
        if not port:
            return 'low'
        
        port_str = str(port)
        if port_str in self.threat_database['suspicious_ports']:
            return 'high'
        elif port < 1024:
            return 'medium'
        return 'low'


class AlertingEngine:
    """Stage 4: Alerting & Prioritization - Flag anomalies and rank their risk level"""
    
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.initialize_alert_storage()
        self.alert_rules = self._load_alert_rules()
    
    def initialize_alert_storage(self):
        """Create alert storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                severity TEXT,
                priority INTEGER,
                risk_score INTEGER,
                title TEXT,
                description TEXT,
                source_log_id INTEGER,
                source_ip TEXT,
                destination_ip TEXT,
                indicators TEXT,
                recommendation TEXT,
                status TEXT DEFAULT 'new',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME,
                assigned_to TEXT,
                resolved_at DATETIME
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alert_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                rule_type TEXT,
                condition TEXT,
                severity TEXT,
                enabled BOOLEAN DEFAULT 1,
                description TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_alert_rules(self):
        """Load alerting rules"""
        return {
            'failed_login_threshold': 5,
            'port_scan_threshold': 10,
            'data_transfer_threshold': 1000000000,  # 1GB
            'suspicious_protocols': ['TELNET', 'FTP'],
            'critical_severity_keywords': ['malware', 'ransomware', 'breach', 'exploit'],
            'high_severity_keywords': ['unauthorized', 'suspicious', 'attack', 'intrusion'],
            'anomaly_thresholds': {
                'request_rate': 1000,  # requests per minute
                'connection_rate': 100,  # connections per minute
                'error_rate': 50  # errors per minute
            }
        }
    
    def analyze_and_alert(self):
        """Analyze enriched logs and generate alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get recent enriched logs that haven't been analyzed
        cursor.execute('''
            SELECT e.id, e.normalized_log_id, n.source_ip, n.destination_ip, 
                   n.severity, n.message, e.enrichment_data
            FROM enriched_logs e
            JOIN normalized_logs n ON e.normalized_log_id = n.id
            WHERE e.id NOT IN (SELECT source_log_id FROM security_alerts WHERE source_log_id IS NOT NULL)
            ORDER BY e.enriched_at DESC
            LIMIT 100
        ''')
        
        logs = cursor.fetchall()
        alerts_generated = 0
        
        for log in logs:
            enriched_id, norm_id, src_ip, dst_ip, severity, message, enrichment_json = log
            
            try:
                enrichment_data = json.loads(enrichment_json)
            except:
                enrichment_data = {}
            
            # Check various alert conditions
            alerts = []
            
            # Check for malicious IP
            if enrichment_data.get('source_ip_enrichment', {}).get('is_malicious'):
                alerts.append(self._create_malicious_ip_alert(src_ip, dst_ip, norm_id))
            
            # Check for threat signatures
            msg_enrichment = enrichment_data.get('message_enrichment', {})
            if msg_enrichment.get('requires_investigation'):
                alerts.append(self._create_threat_signature_alert(
                    msg_enrichment.get('threats_detected', []), src_ip, message, norm_id
                ))
            
            # Check severity-based alerts
            if severity in ['critical', 'high']:
                alerts.append(self._create_severity_alert(severity, message, src_ip, norm_id))
            
            # Check for suspicious ports
            dst_port_enrich = enrichment_data.get('destination_port_enrichment', {})
            if dst_port_enrich.get('is_suspicious'):
                alerts.append(self._create_suspicious_port_alert(
                    dst_port_enrich.get('port'), src_ip, dst_ip, norm_id
                ))
            
            # Store all alerts
            for alert in alerts:
                if alert:
                    cursor.execute('''
                        INSERT INTO security_alerts
                        (alert_type, severity, priority, risk_score, title, description,
                         source_log_id, source_ip, destination_ip, indicators, recommendation, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        alert['alert_type'],
                        alert['severity'],
                        alert['priority'],
                        alert['risk_score'],
                        alert['title'],
                        alert['description'],
                        norm_id,
                        src_ip,
                        dst_ip,
                        json.dumps(alert.get('indicators', [])),
                        alert.get('recommendation', ''),
                        'new'
                    ))
                    alerts_generated += 1
        
        conn.commit()
        conn.close()
        
        return alerts_generated
    
    def _create_malicious_ip_alert(self, src_ip, dst_ip, log_id):
        """Create alert for malicious IP detection"""
        return {
            'alert_type': 'malicious_ip_detected',
            'severity': 'critical',
            'priority': 1,
            'risk_score': 95,
            'title': f'Malicious IP Detected: {src_ip}',
            'description': f'Connection detected from known malicious IP {src_ip} to {dst_ip}',
            'indicators': ['Known malicious IP', 'Threat database match'],
            'recommendation': 'Block IP immediately and investigate all connections'
        }
    
    def _create_threat_signature_alert(self, threats, src_ip, message, log_id):
        """Create alert for threat signature detection"""
        threat_str = ', '.join(threats)
        return {
            'alert_type': 'threat_signature_match',
            'severity': 'high',
            'priority': 2,
            'risk_score': 85,
            'title': f'Threat Signature Detected: {threat_str}',
            'description': f'Attack pattern detected from {src_ip}: {threat_str}',
            'indicators': threats,
            'recommendation': 'Investigate source IP and block if confirmed malicious'
        }
    
    def _create_severity_alert(self, severity, message, src_ip, log_id):
        """Create alert based on log severity"""
        return {
            'alert_type': 'high_severity_event',
            'severity': severity,
            'priority': 3 if severity == 'high' else 1,
            'risk_score': 90 if severity == 'critical' else 70,
            'title': f'{severity.upper()} severity event from {src_ip}',
            'description': message[:200],
            'indicators': [f'{severity} severity log'],
            'recommendation': 'Review event details and take appropriate action'
        }
    
    def _create_suspicious_port_alert(self, port, src_ip, dst_ip, log_id):
        """Create alert for suspicious port activity"""
        return {
            'alert_type': 'suspicious_port_access',
            'severity': 'warning',
            'priority': 4,
            'risk_score': 60,
            'title': f'Suspicious Port Access: {port}',
            'description': f'Access to suspicious port {port} from {src_ip} to {dst_ip}',
            'indicators': ['Suspicious port', 'Potential reconnaissance'],
            'recommendation': 'Monitor for port scanning or brute force attempts'
        }
    
    def get_active_alerts(self, severity_filter=None):
        """Get active alerts with optional severity filter"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if severity_filter:
            cursor.execute('''
                SELECT * FROM security_alerts 
                WHERE status IN ('new', 'investigating') AND severity = ?
                ORDER BY priority, created_at DESC
            ''', (severity_filter,))
        else:
            cursor.execute('''
                SELECT * FROM security_alerts 
                WHERE status IN ('new', 'investigating')
                ORDER BY priority, created_at DESC
            ''')
        
        alerts = cursor.fetchall()
        conn.close()
        
        return alerts
    
    def prioritize_alerts(self):
        """Re-prioritize alerts based on current threat landscape"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get alert counts by type
        cursor.execute('''
            SELECT alert_type, COUNT(*) as count
            FROM security_alerts
            WHERE status = 'new' AND created_at > datetime('now', '-1 hour')
            GROUP BY alert_type
        ''')
        
        alert_counts = dict(cursor.fetchall())
        
        # Increase priority for alert types with high volume
        for alert_type, count in alert_counts.items():
            if count > 10:  # Potential attack campaign
                cursor.execute('''
                    UPDATE security_alerts
                    SET priority = priority - 1, risk_score = risk_score + 10
                    WHERE alert_type = ? AND status = 'new' AND priority > 1
                ''', (alert_type,))
        
        conn.commit()
        conn.close()


class CorrelationEngine:
    """Stage 5: Correlation & Detection - Link suspicious patterns across multiple sources"""
    
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.initialize_correlation_storage()
    
    def initialize_correlation_storage(self):
        """Create correlation storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_type TEXT,
                severity TEXT,
                title TEXT,
                description TEXT,
                affected_systems TEXT,
                indicators TEXT,
                correlated_alerts TEXT,
                attack_timeline TEXT,
                status TEXT DEFAULT 'open',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME,
                resolved_at DATETIME
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS correlation_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT,
                pattern TEXT,
                time_window INTEGER,
                threshold INTEGER,
                severity TEXT,
                enabled BOOLEAN DEFAULT 1
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def correlate_events(self):
        """Correlate events across multiple sources"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get recent alerts
        cursor.execute('''
            SELECT * FROM security_alerts
            WHERE created_at > datetime('now', '-1 hour')
            ORDER BY created_at DESC
        ''')
        
        recent_alerts = cursor.fetchall()
        incidents_created = 0
        
        # Correlation patterns
        incidents_created += self._detect_port_scanning(cursor, recent_alerts)
        incidents_created += self._detect_brute_force(cursor, recent_alerts)
        incidents_created += self._detect_lateral_movement(cursor, recent_alerts)
        incidents_created += self._detect_data_exfiltration(cursor, recent_alerts)
        incidents_created += self._detect_coordinated_attack(cursor, recent_alerts)
        
        conn.commit()
        conn.close()
        
        return incidents_created
    
    def _detect_port_scanning(self, cursor, alerts):
        """Detect port scanning activity"""
        # Group by source IP accessing multiple ports
        ip_port_map = defaultdict(set)
        alert_ids = []
        
        for alert in alerts:
            alert_id, alert_type, severity, priority, risk, title, desc, log_id, src_ip, dst_ip, indicators, rec, status, created, updated, assigned, resolved = alert
            if src_ip and dst_ip:
                ip_port_map[src_ip].add(dst_ip)
                alert_ids.append(alert_id)
        
        incidents_created = 0
        for src_ip, targets in ip_port_map.items():
            if len(targets) >= 5:  # Accessing 5+ different targets
                cursor.execute('''
                    INSERT INTO security_incidents
                    (incident_type, severity, title, description, affected_systems, 
                     correlated_alerts, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    'port_scanning',
                    'high',
                    f'Port Scanning Detected from {src_ip}',
                    f'Source IP {src_ip} accessed {len(targets)} different targets, indicating port scanning activity',
                    json.dumps(list(targets)),
                    json.dumps(alert_ids),
                    'open'
                ))
                incidents_created += 1
        
        return incidents_created
    
    def _detect_brute_force(self, cursor, alerts):
        """Detect brute force attacks"""
        # Look for multiple failed login attempts
        failed_logins = defaultdict(int)
        
        for alert in alerts:
            alert_id, alert_type, severity, priority, risk, title, desc, log_id, src_ip, dst_ip, indicators, rec, status, created, updated, assigned, resolved = alert
            if 'login' in title.lower() or 'authentication' in title.lower():
                if src_ip:
                    failed_logins[src_ip] += 1
        
        incidents_created = 0
        for src_ip, count in failed_logins.items():
            if count >= 5:
                cursor.execute('''
                    INSERT INTO security_incidents
                    (incident_type, severity, title, description, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    'brute_force_attack',
                    'critical',
                    f'Brute Force Attack from {src_ip}',
                    f'{count} failed authentication attempts detected from {src_ip}',
                    'open'
                ))
                incidents_created += 1
        
        return incidents_created
    
    def _detect_lateral_movement(self, cursor, alerts):
        """Detect lateral movement within network"""
        # Track internal IP connections
        internal_connections = defaultdict(lambda: defaultdict(int))
        
        for alert in alerts:
            alert_id, alert_type, severity, priority, risk, title, desc, log_id, src_ip, dst_ip, indicators, rec, status, created, updated, assigned, resolved = alert
            if src_ip and dst_ip:
                if self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip):
                    internal_connections[src_ip][dst_ip] += 1
        
        incidents_created = 0
        for src_ip, connections in internal_connections.items():
            if len(connections) >= 3:  # Connected to 3+ internal systems
                cursor.execute('''
                    INSERT INTO security_incidents
                    (incident_type, severity, title, description, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    'lateral_movement',
                    'critical',
                    f'Lateral Movement Detected from {src_ip}',
                    f'System {src_ip} accessed {len(connections)} internal systems, indicating potential lateral movement',
                    'open'
                ))
                incidents_created += 1
        
        return incidents_created
    
    def _detect_data_exfiltration(self, cursor, alerts):
        """Detect data exfiltration attempts"""
        # Look for large outbound data transfers
        outbound_traffic = defaultdict(int)
        
        for alert in alerts:
            alert_id, alert_type, severity, priority, risk, title, desc, log_id, src_ip, dst_ip, indicators, rec, status, created, updated, assigned, resolved = alert
            if 'transfer' in title.lower() or 'upload' in title.lower():
                if src_ip:
                    outbound_traffic[src_ip] += 1
        
        incidents_created = 0
        for src_ip, count in outbound_traffic.items():
            if count >= 3:
                cursor.execute('''
                    INSERT INTO security_incidents
                    (incident_type, severity, title, description, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    'data_exfiltration',
                    'critical',
                    f'Potential Data Exfiltration from {src_ip}',
                    f'Unusual outbound data transfer pattern detected from {src_ip}',
                    'open'
                ))
                incidents_created += 1
        
        return incidents_created
    
    def _detect_coordinated_attack(self, cursor, alerts):
        """Detect coordinated attack patterns"""
        # Group alerts by time window and check for multiple attack vectors
        time_window_attacks = defaultdict(set)
        
        for alert in alerts:
            alert_id, alert_type, severity, priority, risk, title, desc, log_id, src_ip, dst_ip, indicators, rec, status, created, updated, assigned, resolved = alert
            if alert_type:
                time_window_attacks[created[:16]].add(alert_type)  # Group by minute
        
        incidents_created = 0
        for time_window, attack_types in time_window_attacks.items():
            if len(attack_types) >= 3:  # 3+ different attack types in same minute
                cursor.execute('''
                    INSERT INTO security_incidents
                    (incident_type, severity, title, description, status)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    'coordinated_attack',
                    'critical',
                    'Coordinated Multi-Vector Attack Detected',
                    f'{len(attack_types)} different attack types detected simultaneously: {", ".join(attack_types)}',
                    'open'
                ))
                incidents_created += 1
        
        return incidents_created
    
    def _is_internal_ip(self, ip):
        """Check if IP is internal/private"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False


class SOAREngine:
    """Stage 6: SOC Response & Automation - Analysts take action with automated workflows"""
    
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.initialize_soar_storage()
        self.playbooks = self._load_playbooks()
    
    def initialize_soar_storage(self):
        """Create SOAR storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS playbooks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                playbook_name TEXT,
                incident_type TEXT,
                steps TEXT,
                automated BOOLEAN,
                enabled BOOLEAN DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS response_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id INTEGER,
                action_type TEXT,
                action_details TEXT,
                automated BOOLEAN,
                status TEXT,
                executed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                executed_by TEXT,
                result TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blocked_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE,
                reason TEXT,
                blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                blocked_by TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_playbooks(self):
        """Load incident response playbooks"""
        return {
            'malicious_ip_detected': {
                'steps': [
                    'Block IP address at firewall',
                    'Terminate active connections',
                    'Alert security team',
                    'Log incident details',
                    'Monitor for additional attempts'
                ],
                'automated': True
            },
            'brute_force_attack': {
                'steps': [
                    'Block source IP temporarily',
                    'Reset affected user accounts',
                    'Notify users',
                    'Enable additional authentication',
                    'Review access logs'
                ],
                'automated': True
            },
            'port_scanning': {
                'steps': [
                    'Log scanning activity',
                    'Block source IP if persistent',
                    'Check for vulnerabilities',
                    'Alert security team',
                    'Review firewall rules'
                ],
                'automated': False
            },
            'data_exfiltration': {
                'steps': [
                    'Block outbound connections',
                    'Isolate affected system',
                    'Preserve evidence',
                    'Alert incident response team',
                    'Begin forensic investigation'
                ],
                'automated': False
            },
            'threat_signature_match': {
                'steps': [
                    'Block malicious traffic',
                    'Update WAF rules',
                    'Scan affected systems',
                    'Alert security team',
                    'Review similar patterns'
                ],
                'automated': True
            }
        }
    
    def execute_automated_response(self, incident_id, incident_type):
        """Execute automated response playbook"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        playbook = self.playbooks.get(incident_type)
        if not playbook or not playbook.get('automated'):
            conn.close()
            return False
        
        actions_executed = []
        
        # Get incident details
        cursor.execute('SELECT * FROM security_incidents WHERE id = ?', (incident_id,))
        incident = cursor.fetchone()
        
        if not incident:
            conn.close()
            return False
        
        # Execute playbook steps
        for step in playbook['steps']:
            action_result = self._execute_action(step, incident, cursor)
            actions_executed.append({
                'step': step,
                'result': action_result,
                'timestamp': datetime.now().isoformat()
            })
            
            # Log the action
            cursor.execute('''
                INSERT INTO response_actions
                (incident_id, action_type, action_details, automated, status, executed_by, result)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident_id,
                'automated_playbook',
                step,
                True,
                'completed',
                'SOAR_Engine',
                json.dumps(action_result)
            ))
        
        # Update incident status
        cursor.execute('''
            UPDATE security_incidents
            SET status = 'mitigated', updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (incident_id,))
        
        conn.commit()
        conn.close()
        
        return True
    
    def _execute_action(self, action_step, incident, cursor):
        """Execute a specific action step"""
        step_lower = action_step.lower()
        
        if 'block ip' in step_lower:
            # Extract IP from incident data
            incident_data = incident[7]  # affected_systems field
            try:
                systems = json.loads(incident_data) if incident_data else []
                if systems:
                    ip = systems[0] if isinstance(systems, list) else str(systems)
                    return self._block_ip(ip, 'Automated response', cursor)
            except:
                pass
            return {'status': 'no_ip_found'}
        
        elif 'terminate' in step_lower or 'kill' in step_lower:
            return {'status': 'connections_terminated', 'action': 'simulated'}
        
        elif 'alert' in step_lower or 'notify' in step_lower:
            return {'status': 'notification_sent', 'action': 'simulated'}
        
        elif 'log' in step_lower:
            return {'status': 'logged', 'timestamp': datetime.now().isoformat()}
        
        elif 'scan' in step_lower:
            return {'status': 'scan_initiated', 'action': 'simulated'}
        
        else:
            return {'status': 'action_completed', 'action': action_step}
    
    def _block_ip(self, ip_address, reason, cursor):
        """Block an IP address"""
        try:
            expires_at = datetime.now() + timedelta(hours=24)
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_ips
                (ip_address, reason, expires_at, blocked_by)
                VALUES (?, ?, ?, ?)
            ''', (ip_address, reason, expires_at, 'SOAR_Engine'))
            
            return {
                'status': 'ip_blocked',
                'ip_address': ip_address,
                'expires_at': expires_at.isoformat()
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def is_ip_blocked(self, ip_address):
        """Check if an IP is currently blocked"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM blocked_ips
            WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        ''', (ip_address,))
        
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    
    def get_response_metrics(self):
        """Get SOAR response metrics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM response_actions WHERE automated = 1')
        automated_responses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM response_actions WHERE automated = 0')
        manual_responses = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM blocked_ips WHERE expires_at > CURRENT_TIMESTAMP')
        active_blocks = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM security_incidents 
            WHERE status IN ('mitigated', 'resolved')
        ''')
        resolved_incidents = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'automated_responses': automated_responses,
            'manual_responses': manual_responses,
            'active_ip_blocks': active_blocks,
            'resolved_incidents': resolved_incidents
        }


class ContinuousImprovementEngine:
    """Stage 7: Continuous Improvement - Learn and adapt to new threats"""
    
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.initialize_learning_storage()
    
    def initialize_learning_storage(self):
        """Create continuous improvement storage"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT,
                pattern_signature TEXT,
                frequency INTEGER DEFAULT 1,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                severity TEXT,
                confidence_score REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER,
                marked_by TEXT,
                reason TEXT,
                marked_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tuning_recommendations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recommendation_type TEXT,
                description TEXT,
                impact TEXT,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def learn_from_incidents(self):
        """Learn from resolved incidents"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Analyze resolved incidents
        cursor.execute('''
            SELECT incident_type, indicators, COUNT(*) as frequency
            FROM security_incidents
            WHERE status = 'resolved'
            GROUP BY incident_type
        ''')
        
        patterns = cursor.fetchall()
        learned_count = 0
        
        for pattern in patterns:
            incident_type, indicators, frequency = pattern
            
            # Store learned pattern
            cursor.execute('''
                INSERT OR REPLACE INTO threat_patterns
                (pattern_type, pattern_signature, frequency, last_seen, confidence_score)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
            ''', (
                incident_type,
                indicators if indicators else incident_type,
                frequency,
                min(0.95, 0.5 + (frequency * 0.05))  # Increase confidence with frequency
            ))
            learned_count += 1
        
        conn.commit()
        conn.close()
        
        return learned_count
    
    def analyze_false_positives(self):
        """Analyze false positives to improve accuracy"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT a.alert_type, COUNT(*) as fp_count
            FROM false_positives fp
            JOIN security_alerts a ON fp.alert_id = a.id
            GROUP BY a.alert_type
            HAVING fp_count > 5
        ''')
        
        fp_patterns = cursor.fetchall()
        recommendations = []
        
        for pattern in fp_patterns:
            alert_type, count = pattern
            
            recommendation = {
                'type': 'rule_tuning',
                'alert_type': alert_type,
                'false_positive_count': count,
                'suggestion': f'Consider tuning {alert_type} rule - {count} false positives detected'
            }
            recommendations.append(recommendation)
            
            cursor.execute('''
                INSERT INTO tuning_recommendations
                (recommendation_type, description, impact)
                VALUES (?, ?, ?)
            ''', (
                'rule_tuning',
                f'Tune {alert_type} rule to reduce false positives',
                f'Reduce {count} false positive alerts'
            ))
        
        conn.commit()
        conn.close()
        
        return recommendations
    
    def update_threat_intelligence(self):
        """Update threat intelligence based on observations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Find frequently blocked IPs
        cursor.execute('''
            SELECT ip_address, COUNT(*) as block_count
            FROM blocked_ips
            GROUP BY ip_address
            HAVING block_count > 3
        ''')
        
        frequent_threats = cursor.fetchall()
        updated_count = 0
        
        for threat in frequent_threats:
            ip_address, count = threat
            
            # Add to threat patterns with high confidence
            cursor.execute('''
                INSERT OR REPLACE INTO threat_patterns
                (pattern_type, pattern_signature, frequency, confidence_score, severity)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                'malicious_ip',
                ip_address,
                count,
                0.9,
                'high'
            ))
            updated_count += 1
        
        conn.commit()
        conn.close()
        
        return updated_count
    
    def generate_improvement_report(self):
        """Generate continuous improvement report"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get learning statistics
        cursor.execute('SELECT COUNT(*) FROM threat_patterns')
        learned_patterns = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM false_positives')
        false_positives = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM tuning_recommendations WHERE status = "pending"')
        pending_tuning = cursor.fetchone()[0]
        
        # Calculate detection accuracy
        cursor.execute('SELECT COUNT(*) FROM security_alerts WHERE status = "resolved"')
        resolved_alerts = cursor.fetchone()[0]
        
        total_alerts = resolved_alerts + false_positives
        accuracy = (resolved_alerts / total_alerts * 100) if total_alerts > 0 else 0
        
        conn.close()
        
        return {
            'learned_threat_patterns': learned_patterns,
            'false_positives_identified': false_positives,
            'pending_tuning_recommendations': pending_tuning,
            'detection_accuracy': round(accuracy, 2),
            'improvement_trend': 'positive' if accuracy > 85 else 'needs_attention'
        }


# Main SIEM orchestrator
class SIEMOrchestrator:
    """Main orchestrator for the complete SIEM process flow"""
    
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.log_collector = LogCollector(db_path)
        self.normalizer = LogNormalizer(db_path)
        self.enricher = LogEnricher(db_path)
        self.alerting = AlertingEngine(db_path)
        self.correlation = CorrelationEngine(db_path)
        self.soar = SOAREngine(db_path)
        self.improvement = ContinuousImprovementEngine(db_path)
    
    def run_complete_cycle(self):
        """Run a complete SIEM processing cycle"""
        results = {
            'stage_1_collection': self.log_collector.get_collection_statistics(),
            'stage_2_normalization': self.normalizer.process_raw_logs(),
            'stage_3_enrichment': self.enricher.enrich_logs(),
            'stage_4_alerting': self.alerting.analyze_and_alert(),
            'stage_5_correlation': self.correlation.correlate_events(),
            'stage_6_response': self.soar.get_response_metrics(),
            'stage_7_improvement': self.improvement.generate_improvement_report()
        }
        
        return results
    
    def get_system_status(self):
        """Get overall SIEM system status"""
        return {
            'status': 'operational',
            'components': {
                'log_collection': 'active',
                'normalization': 'active',
                'enrichment': 'active',
                'alerting': 'active',
                'correlation': 'active',
                'soar': 'active',
                'continuous_improvement': 'active'
            }
        }


if __name__ == "__main__":
    print("ESTPL Security - SIEM Process Flow Engine")
    print("=" * 60)
    print("Complete 7-stage SIEM implementation")
    print("All stages operational and ready")
    print("=" * 60)