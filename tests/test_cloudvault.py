"""
Test Suite for CloudVault
Basic tests for critical functionality
"""

import pytest
import json
from cloudvault_discovery.filtering.query_parser import parse_query, FilterExpression
from cloudvault_discovery.filtering.filters import apply_filters
from cloudvault_discovery.analysis.risk_scorer import calculate_risk_score
from cloudvault_discovery.core.domain_processor import DomainProcessor


class TestFilterParser:
    """Test filter query parser"""
    
    def test_simple_equality(self):
        """Test simple equality filter"""
        expressions = parse_query("severity=CRITICAL")
        assert len(expressions) == 1
        assert expressions[0].field == "severity"
        assert expressions[0].operator == "="
        assert expressions[0].value == "critical"
    
    def test_multiple_values(self):
        """Test comma-separated OR values"""
        expressions = parse_query("severity=CRITICAL,HIGH")
        assert len(expressions) == 2
        assert all(e.field == "severity" for e in expressions)
    
    def test_comparison_operators(self):
        """Test comparison operators"""
        expressions = parse_query("risk_score>=75")
        assert len(expressions) == 1
        assert expressions[0].operator == ">="
        assert expressions[0].value == 75
    
    def test_regex(self):
        """Test regex filter"""
        expressions = parse_query("bucket_name~regex:.*-prod-.*")
        assert len(expressions) == 1
        assert expressions[0].operator == "~"
        assert "prod" in expressions[0].value


class TestFilters:
    """Test filter application"""
    
    @pytest.fixture
    def sample_findings(self):
        return [
            {"severity": "CRITICAL", "provider": "aws", "risk_score": 95, "is_public": True},
            {"severity": "HIGH", "provider": "gcp", "risk_score": 80, "is_public": True},
            {"severity": "MEDIUM", "provider": "azure", "risk_score": 50, "is_public": False},
        ]
    
    def test_severity_filter(self, sample_findings):
        """Test severity filtering"""
        result = apply_filters(sample_findings, "severity=CRITICAL,HIGH")
        assert len(result) == 2
        assert all(f['severity'] in ['CRITICAL', 'HIGH'] for f in result)
    
    def test_risk_score_filter(self, sample_findings):
        """Test risk score filtering"""
        result = apply_filters(sample_findings, "risk_score>=75")
        assert len(result) == 2
        assert all(f['risk_score'] >= 75 for f in result)
    
    def test_exclude_filter(self, sample_findings):
        """Test exclude logic"""
        result = apply_filters(sample_findings, None, "provider=azure")
        assert len(result) == 2
        assert all(f['provider'] != 'azure' for f in result)


class TestRiskScorer:
    """Test risk scoring"""
    
    def test_public_critical_bucket(self):
        """Test risk score for public bucket"""
        finding = {
            "severity": "CRITICAL",
            "is_public": True,
            "permissions": ["READ", "WRITE"]
        }
        score = calculate_risk_score(finding)
        assert score > 80
    
    def test_private_bucket(self):
        """Test risk score for private bucket"""
        finding = {
            "severity": "INFO",
            "is_public": False,
            "permissions": []
        }
        score = calculate_risk_score(finding)
        assert score < 30


class TestDomainProcessor:
    """Test domain processing"""
    
    def test_domain_to_buckets(self):
        """Test bucket name generation"""
        processor = DomainProcessor()
        buckets = processor.process_domain("example.com")
        
        assert len(buckets) > 0
        assert "example-com" in buckets
        assert any("backup" in b for b in buckets)
    
    def test_bucket_name_validation(self):
        """Test bucket name validation"""
        processor = DomainProcessor()
        
        # Valid
        assert processor._is_valid_bucket_name("my-bucket-123")
        assert processor._is_valid_bucket_name("example.com")
        
        # Invalid
        assert not processor._is_valid_bucket_name("AB")  # Too short
        assert not processor._is_valid_bucket_name("-invalid")  # Starts with dash
        assert not processor._is_valid_bucket_name("invalid..name")  # Consecutive dots


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
