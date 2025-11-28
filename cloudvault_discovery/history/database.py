"""
SQLite Database for Scan History
Async database operations using aiosqlite
"""

import aiosqlite
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


DB_PATH = Path.home() / '.cloudvault' / 'history.db'


async def init_database():
    """Initialize database schema"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    async with aiosqlite.connect(DB_PATH) as db:
        # Scans table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                avg_risk_score REAL DEFAULT 0,
                config TEXT,
                duration_seconds REAL
            )
        ''')
        
        # Findings table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                finding_id TEXT NOT NULL,
                severity TEXT,
                provider TEXT,
                bucket_name TEXT,
                risk_score REAL,
                is_public INTEGER,
                finding_data TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        ''')
        
        # Trends table
        await db.execute('''
            CREATE TABLE IF NOT EXISTS trends (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                metric TEXT NOT NULL,
                value REAL NOT NULL
            )
        ''')
        
        # Indexes
        await db.execute('CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)')
        await db.execute('CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)')
        await db.execute('CREATE INDEX IF NOT EXISTS idx_trends_date ON trends(date)')
        
        await db.commit()


async def save_scan(findings: List[Dict[str, Any]], 
                    config: Optional[Dict] = None,
                    duration: float = 0) -> int:
    """
    Save scan results to database.
    
    Args:
        findings: List of findings
        config: Scan configuration
        duration: Scan duration in seconds
        
    Returns:
        Scan ID
    """
    await init_database()
    
    # Calculate stats
    total = len(findings)
    critical = sum(1 for f in findings if f.get('severity') == 'CRITICAL')
    high = sum(1 for f in findings if f.get('severity') == 'HIGH')
    medium = sum(1 for f in findings if f.get('severity') == 'MEDIUM')
    low = sum(1 for f in findings if f.get('severity') == 'LOW')
    
    risk_scores = [f.get('risk_score', 0) for f in findings]
    avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
    
    async with aiosqlite.connect(DB_PATH) as db:
        # Insert scan
        cursor = await db.execute('''
            INSERT INTO scans (timestamp, total_findings, critical_count, high_count,
                             medium_count, low_count, avg_risk_score, config, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.utcnow().isoformat(),
            total,
            critical,
            high,
            medium,
            low,
            avg_risk,
            json.dumps(config) if config else None,
            duration
        ))
        
        scan_id = cursor.lastrowid
        
        # Insert findings
        for finding in findings:
            await db.execute('''
                INSERT INTO findings (scan_id, finding_id, severity, provider,
                                    bucket_name, risk_score, is_public, finding_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                finding.get('id', ''),
                finding.get('severity', ''),
                finding.get('provider', ''),
                finding.get('bucket_name', ''),
                finding.get('risk_score', 0),
                1 if finding.get('is_public', False) else 0,
                json.dumps(finding)
            ))
        
        # Update trends
        date = datetime.utcnow().date().isoformat()
        await db.execute('''
            INSERT INTO trends (date, metric, value)
            VALUES (?, 'total_findings', ?)
        ''', (date, total))
        
        await db.execute('''
            INSERT INTO trends (date, metric, value)
            VALUES (?, 'avg_risk_score', ?)
        ''', (date, avg_risk))
        
        await db.commit()
        return scan_id


async def get_scan_history(limit: int = 10) -> List[Dict[str, Any]]:
    """
    Get scan history.
    
    Args:
        limit: Maximum number of scans to return
        
    Returns:
        List of scan summaries
    """
    await init_database()
    
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        async with db.execute('''
            SELECT * FROM scans 
            ORDER BY timestamp DESC 
            LIMIT ?
        ''', (limit,)) as cursor:
            rows = await cursor.fetchall()
            
            return [dict(row) for row in rows]


async def get_trends(days: int = 30) -> Dict[str, List]:
    """
    Get trends over time.
    
    Args:
        days: Number of days to look back
        
    Returns:
        Dictionary of trends by metric
    """
    await init_database()
    
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        async with db.execute('''
            SELECT date, metric, AVG(value) as avg_value
            FROM trends
            WHERE date >= date('now', '-' || ? || ' days')
            GROUP BY date, metric
            ORDER BY date DESC
        ''', (days,)) as cursor:
            rows = await cursor.fetchall()
            
            trends = {}
            for row in rows:
                metric = row['metric']
                if metric not in trends:
                    trends[metric] = []
                trends[metric].append({
                    'date': row['date'],
                    'value': row['avg_value']
                })
            
            return trends


__all__ = ['init_database', 'save_scan', 'get_scan_history', 'get_trends']
