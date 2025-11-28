"""
Query Parser
Parse complex filter queries with Boolean logic

Examples:
  severity=CRITICAL,HIGH
  provider=aws AND is_public=true
  risk_score>=75
  bucket_name~regex:.*-prod-.*
  (severity=CRITICAL OR severity=HIGH) AND provider=aws
"""

import re
from typing import Dict, Any, List, Tuple, Optional


class FilterExpression:
    """Represents a single filter expression"""
    
    def __init__(self, field: str, operator: str, value: Any):
        self.field = field
        self.operator = operator
        self.value = value
    
    def evaluate(self, obj: Dict[str, Any]) -> bool:
        """Evaluate expression against object"""
        field_value = obj.get(self.field)
        
        if field_value is None:
            return False
        
        # Normalize string comparisons
        if isinstance(field_value, str):
            field_value = field_value.lower()
        if isinstance(self.value, str):
            value = self.value.lower()
        else:
            value = self.value
        
        if self.operator == '=':
            return field_value == value
        elif self.operator == '!=':
            return field_value != value
        elif self.operator == '>':
            return field_value > value
        elif self.operator == '>=':
            return field_value >= value
        elif self.operator == '<':
            return field_value < value
        elif self.operator == '<=':
            return field_value <= value
        elif self.operator == '~':  # Regex
            if isinstance(field_value, str):
                return bool(re.search(value, field_value, re.IGNORECASE))
            return False
        elif self.operator == 'in':  # List contains
            if isinstance(value, list):
                return field_value in value
            return False
        
        return False
    
    def __repr__(self):
        return f"FilterExpression({self.field} {self.operator} {self.value})"


def parse_query(query: str) -> List[FilterExpression]:
    """
    Parse filter query string into filter expressions.
    
    Supported formats:
      - field=value
      - field!=value
      - field>value, field>=value, field<value, field<=value
      - field~regex:pattern
      - field1=value1,value2  (OR logic for same field)
      - field1=val1 AND field2=val2  (AND logic)
      
    Args:
        query: Filter query string
        
    Returns:
        List of FilterExpression objects
    """
    if not query:
        return []
    
    expressions = []
    
    # Split by AND (case-insensitive)
    and_parts = re.split(r'\s+AND\s+', query, flags=re.IGNORECASE)
    
    for part in and_parts:
        part = part.strip()
        
        # Parse expression: field operator value
        # Match: field (optional spaces) operator (optional spaces) value
        match = re.match(r'(\w+)\s*(=|!=|>=|<=|>|<|~)\s*(.+)', part)
        
        if not match:
            continue
        
        field = match.group(1)
        operator = match.group(2)
        value_str = match.group(3).strip()
        
        # Handle regex operator
        if operator == '~':
            if value_str.startswith('regex:'):
                value = value_str[6:]  # Remove 'regex:' prefix
            else:
                value = value_str
            expressions.append(FilterExpression(field, operator, value))
            continue
        
        # Handle comma-separated values (OR logic for same field)
        if ',' in value_str:
            values = [v.strip() for v in value_str.split(',')]
            for val in values:
                parsed_val = _parse_value(val)
                expressions.append(FilterExpression(field, operator, parsed_val))
        else:
            parsed_val = _parse_value(value_str)
            expressions.append(FilterExpression(field, operator, parsed_val))
    
    return expressions


def _parse_value(value_str: str) -> Any:
    """Parse value string to appropriate type"""
    value_str = value_str.strip()
    
    # Boolean
    if value_str.lower() == 'true':
        return True
    elif value_str.lower() == 'false':
        return False
    
    # Number
    try:
        if '.' in value_str:
            return float(value_str)
        else:
            return int(value_str)
    except ValueError:
        pass
    
    # String (remove quotes if present)
    if value_str.startswith('"') and value_str.endswith('"'):
        return value_str[1:-1]
    if value_str.startswith("'") and value_str.endswith("'"):
        return value_str[1:-1]
    
    return value_str


__all__ = ['FilterExpression', 'parse_query']
