"""
Filter Implementation
Apply parsed filters to findings
"""

from typing import List, Dict, Any
from .query_parser import FilterExpression, parse_query


def apply_filters(findings: List[Dict[str, Any]], 
                  filter_query: str,
                  exclude_query: str = None) -> List[Dict[str, Any]]:
    """
    Apply filter and exclude queries to findings.
    
    Args:
        findings: List of findings
        filter_query: Include filter (e.g., "severity=CRITICAL,HIGH")
        exclude_query: Exclude filter (e.g., "bucket_name~.*-test-.*")
        
    Returns:
        Filtered list of findings
    """
    if not findings:
        return []
    
    result = findings
    
    # Apply include filter
    if filter_query:
        expressions = parse_query(filter_query)
        if expressions:
            result = [f for f in result if _matches_any(f, expressions)]
    
    # Apply exclude filter
    if exclude_query:
        expressions = parse_query(exclude_query)
        if expressions:
            result = [f for f in result if not _matches_any(f, expressions)]
    
    return result


def _matches_any(finding: Dict[str, Any], expressions: List[FilterExpression]) -> bool:
    """Check if finding matches any expression (OR logic)"""
    if not expressions:
        return True
    
    # Group expressions by field for OR logic
    by_field = {}
    for expr in expressions:
        if expr.field not in by_field:
            by_field[expr.field] = []
        by_field[expr.field].append(expr)
    
    # All field groups must match (AND between fields)
    for field_expressions in by_field.values():
        # At least one expression per field must match (OR within field)
        if not any(expr.evaluate(finding) for expr in field_expressions):
            return False
    
    return True


def filter_by_severity(findings: List[Dict[str, Any]], 
                       severities: List[str]) -> List[Dict[str, Any]]:
    """
    Quick severity filter.
    
    Args:
        findings: List of findings
        severities: List of severity levels (e.g., ['CRITICAL', 'HIGH'])
        
    Returns:
        Filtered findings
    """
    if not severities:
        return findings
    
    severities = [s.upper() for s in severities]
    return [f for f in findings if f.get('severity', '').upper() in severities]


def filter_by_provider(findings: List[Dict[str, Any]], 
                       providers: List[str]) -> List[Dict[str, Any]]:
    """
    Quick provider filter.
    
    Args:
        findings: List of findings
        providers: List of providers (e.g., ['aws', 'gcp'])
        
    Returns:
        Filtered findings
    """
    if not providers:
        return findings
    
    providers = [p.lower() for  p in providers]
    return [f for f in findings if f.get('provider', '').lower() in providers]


def filter_by_risk_score(findings: List[Dict[str, Any]], 
                         min_score: float = None,
                         max_score: float = None) -> List[Dict[str, Any]]:
    """
    Filter by risk score range.
    
    Args:
        findings: List of findings
        min_score: Minimum risk score
        max_score: Maximum risk score
        
    Returns:
        Filtered findings
    """
    result = findings
    
    if min_score is not None:
        result = [f for f in result if f.get('risk_score', 0) >= min_score]
    
    if max_score is not None:
        result = [f for f in result if f.get('risk_score', 0) <= max_score]
    
    return result


def filter_public_only(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter to public buckets only.
    
    Args:
        findings: List of findings
        
    Returns:
        Public findings only
    """
    return [f for f in findings if f.get('is_public', False)]


__all__ = [
    'apply_filters',
    'FilterExpression',
    'filter_by_severity',
    'filter_by_provider',
    'filter_by_risk_score',
    'filter_public_only'
]
