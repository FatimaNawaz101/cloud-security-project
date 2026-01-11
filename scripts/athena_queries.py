"""
Athena Queries for Security Analytics
Reusable SQL queries for the dashboard
Author: Fatima Nawaz
Date: January 2026
"""

# Query templates for security analytics

QUERIES = {
    "total_events": """
        SELECT COUNT(*) as total_events 
        FROM security_analytics.security_events
    """,
    
    "risk_distribution": """
        SELECT 
            risk_level,
            COUNT(*) as count
        FROM security_analytics.security_events
        GROUP BY risk_level
    """,
    
    "top_users": """
        SELECT 
            user_name,
            COUNT(*) as event_count,
            SUM(is_sensitive_action) as sensitive_actions,
            SUM(has_error) as errors,
            ROUND(AVG(risk_score_normalized), 2) as avg_risk_score
        FROM security_analytics.security_events
        GROUP BY user_name
        ORDER BY event_count DESC
        LIMIT 10
    """,
    
    "high_risk_events": """
        SELECT 
            user_name,
            source_ip,
            event_name,
            event_time,
            risk_level,
            risk_score_normalized
        FROM security_analytics.security_events
        WHERE risk_level IN ('high', 'critical')
        ORDER BY risk_score_normalized DESC
        LIMIT 50
    """,
    
    "hourly_pattern": """
        SELECT 
            hour,
            COUNT(*) as event_count,
            SUM(CASE WHEN is_anomaly_original = true THEN 1 ELSE 0 END) as anomaly_count
        FROM security_analytics.security_events
        GROUP BY hour
        ORDER BY hour
    """,
    
    "anomaly_summary": """
        SELECT 
            anomaly_type_original,
            COUNT(*) as count
        FROM security_analytics.security_events
        WHERE is_anomaly_original = true
        GROUP BY anomaly_type_original
    """,
    
    "suspicious_ips": """
        SELECT 
            source_ip,
            COUNT(*) as event_count,
            COUNT(DISTINCT user_name) as unique_users,
            SUM(has_error) as error_count
        FROM security_analytics.security_events
        WHERE is_suspicious_ip = 1
        GROUP BY source_ip
        ORDER BY event_count DESC
    """,
    
    "sensitive_actions": """
        SELECT 
            event_name,
            user_name,
            source_ip,
            event_time,
            risk_score_normalized
        FROM security_analytics.security_events
        WHERE is_sensitive_action = 1
        ORDER BY event_time DESC
        LIMIT 50
    """
}


def get_query(query_name):
    """Get a query by name."""
    return QUERIES.get(query_name, None)


def list_queries():
    """List all available queries."""
    return list(QUERIES.keys())


if __name__ == "__main__":
    print("Available queries:")
    for name in list_queries():
        print(f"  - {name}")