"""
CloudTrail Log Parser
Parses CloudTrail JSON logs and extracts security-relevant features
Author: Fatima Nawaz
Date: January 2026
"""

#This is a log parser file which extracts security relevant fields from CloudTrailJSON
#which include user identity, timestamps, source IPs and error codes
#transforms nested JSON into a flat CSV structure suitable for ML

import json
import csv
import os
from datetime import datetime

# Configuration
#file path setup for input and output
CONFIG = {
    "input_file": "../data/cloudtrail_events.json",
    "output_csv": "../data/parsed_events.csv",
    "output_json": "../data/parsed_events.json"
}

# Sensitive actions that should be flagged
SENSITIVE_ACTIONS = [
    "CreateUser", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
    "AddUserToGroup", "CreateRole", "StopLogging", "DeleteTrail",
    "UpdateTrail", "DeleteBucket", "CreateDBSnapshot", "CopyDBSnapshot",
    "ListSecrets", "GetSecretValue"
]

# List of Known suspicious IPs (in real world, this would be a threat intelligence feed)
SUSPICIOUS_IPS = [
    "45.227.255.206", "103.75.118.91", "185.220.101.34",
    "91.240.118.172", "23.94.188.246"
]
#Prevents crashes when accessing nested JSON which might have missing keys
def safe_get(dictionary, *keys, default=None):
    """
    Safely get nested dictionary values.
    Returns None if any key doesn't exist instead of crashing.
    """
    result = dictionary
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key, default)
        else:
            return default
    return result if result is not None else default

#extracts time based features from json data like hour, day and business hours
def parse_timestamp(timestamp_str):
    """
    Parse CloudTrail timestamp and extract useful features.
    Input: '2026-01-05T14:30:00Z'
    Output: datetime object and extracted features
    """
    try:
        dt = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
        return {
            "datetime": dt,
            "hour": dt.hour,
            "day_of_week": dt.weekday(),  # 0=Monday, 6=Sunday
            "is_business_hours": 9 <= dt.hour <= 18,
            "is_weekend": dt.weekday() >= 5
        }
    except (ValueError, TypeError):
        return {
            "datetime": None,
            "hour": None,
            "day_of_week": None,
            "is_business_hours": None,
            "is_weekend": None
        }

#It checks and flags dangerous operations
def is_sensitive_action(event_name):
    """Check if the event is a sensitive/risky action."""
    return event_name in SENSITIVE_ACTIONS

#This function checks if there is a bad IP which is part of the suspicious ips list
def is_suspicious_ip(ip_address):
    """Check if the IP is in our suspicious list."""
    return ip_address in SUSPICIOUS_IPS

#Combines different factors into a risk score
def classify_event_risk(event):
    """
    Assign a risk score based on multiple factors.
    Returns: low, medium, high, critical
    """
    risk_score = 0
    
    # Check sensitive action (+2)
    if is_sensitive_action(safe_get(event, 'eventName', default='')):
        risk_score += 2
    
    # Check suspicious IP (+2)
    if is_suspicious_ip(safe_get(event, 'sourceIPAddress', default='')):
        risk_score += 2
    
    # Check for errors - could indicate attack attempts (+1)
    if safe_get(event, 'errorCode'):
        risk_score += 1
    
    # Check unusual hours (+1)
    time_info = parse_timestamp(safe_get(event, 'eventTime', default=''))
    if time_info['hour'] is not None:
        if not time_info['is_business_hours']:
            risk_score += 1
        if time_info['is_weekend']:
            risk_score += 1
    
    # Classify based on score
    if risk_score >= 4:
        return "critical"
    elif risk_score >= 3:
        return "high"
    elif risk_score >= 1:
        return "medium"
    else:
        return "low"
    
#Main parse function
#Takes one cloudtrail event and extracts all relevant fields into a flat dictionary
def parse_event(event):
    """
    Parse a single CloudTrail event and extract relevant fields.
    Returns a flat dictionary suitable for CSV/ML.
    """
    # Parse timestamp
    time_info = parse_timestamp(safe_get(event, 'eventTime', default=''))
    
    # Extract fields
    parsed = {
        # Event identification
        "event_id": safe_get(event, 'eventID', default=''),
        "event_time": safe_get(event, 'eventTime', default=''),
        "event_source": safe_get(event, 'eventSource', default=''),
        "event_name": safe_get(event, 'eventName', default=''),
        "aws_region": safe_get(event, 'awsRegion', default=''),
        
        # User information
        "user_type": safe_get(event, 'userIdentity', 'type', default=''),
        "user_name": safe_get(event, 'userIdentity', 'userName', default='Unknown'),
        "user_arn": safe_get(event, 'userIdentity', 'arn', default=''),
        "account_id": safe_get(event, 'userIdentity', 'accountId', default=''),
        
        # Network information
        "source_ip": safe_get(event, 'sourceIPAddress', default=''),
        "user_agent": safe_get(event, 'userAgent', default=''),
        
        # Status
        "error_code": safe_get(event, 'errorCode', default=''),
        "error_message": safe_get(event, 'errorMessage', default=''),
        
        # Time-based features (for ML)
        "hour_of_day": time_info['hour'],
        "day_of_week": time_info['day_of_week'],
        "is_business_hours": time_info['is_business_hours'],
        "is_weekend": time_info['is_weekend'],
        
        # Security features (for ML)
        "is_sensitive_action": is_sensitive_action(safe_get(event, 'eventName', default='')),
        "is_suspicious_ip": is_suspicious_ip(safe_get(event, 'sourceIPAddress', default='')),
        "has_error": safe_get(event, 'errorCode') is not None,
        "risk_level": classify_event_risk(event),
        
        # Training labels (only present in our generated data)
        "is_anomaly": safe_get(event, 'is_anomaly', default=None),
        "anomaly_type": safe_get(event, 'anomaly_type', default=None)
    }
    
    return parsed

#This function reads the JSON file and parses all events in it
def parse_cloudtrail_file(input_path):
    """
    Parse an entire CloudTrail log file.
    Returns list of parsed events.
    """
    print(f"Reading CloudTrail logs from: {input_path}")
    
    with open(input_path, 'r') as f:
        data = json.load(f)
    
    # CloudTrail logs have events in 'Records' array
    events = data.get('Records', [])
    print(f"Found {len(events)} events to parse")
    
    parsed_events = []
    for i, event in enumerate(events):
        parsed = parse_event(event)
        parsed_events.append(parsed)
        
        if (i + 1) % 200 == 0:
            print(f"  Parsed {i + 1}/{len(events)} events...")
    
    print(f"Successfully parsed {len(parsed_events)} events")
    return parsed_events

#Exports the parsed data to a csv file
def save_to_csv(events, output_path):
    """Save parsed events to CSV file."""
    if not events:
        print("No events to save!")
        return
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Get field names from first event
    fieldnames = events[0].keys()
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(events)
    
    print(f"Saved {len(events)} events to CSV: {output_path}")

#Export the events to JSON format
def save_to_json(events, output_path):
    """Save parsed events to JSON file."""
    if not events:
        print("No events to save!")
        return
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(events, f, indent=2, default=str)
    
    print(f"Saved {len(events)} events to JSON: {output_path}")

#Shows a summary of useful information extracted from the data
def print_summary(events):
    """Print summary statistics of parsed events."""
    print("\n" + "=" * 60)
    print("PARSING SUMMARY")
    print("=" * 60)
    
    total = len(events)
    print(f"\nTotal events parsed: {total}")
    
    # Risk level distribution
    print("\nRisk Level Distribution:")
    risk_counts = {}
    for event in events:
        risk = event['risk_level']
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
    
    for risk in ['low', 'medium', 'high', 'critical']:
        count = risk_counts.get(risk, 0)
        percentage = (count / total) * 100 if total > 0 else 0
        bar = "█" * int(percentage / 2)
        print(f"  {risk.upper():8} : {count:4} ({percentage:5.1f}%) {bar}")
    
    # Anomaly distribution (if present)
    anomaly_count = sum(1 for e in events if e['is_anomaly'] is True)
    normal_count = sum(1 for e in events if e['is_anomaly'] is False)
    
    if anomaly_count + normal_count > 0:
        print(f"\nAnomaly Distribution:")
        print(f"  Normal events:    {normal_count}")
        print(f"  Anomalous events: {anomaly_count}")
    
    # Top event types
    print("\nTop 10 Event Types:")
    event_counts = {}
    for event in events:
        name = event['event_name']
        event_counts[name] = event_counts.get(name, 0) + 1
    
    sorted_events = sorted(event_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    for name, count in sorted_events:
        print(f"  {name}: {count}")
    
    # Unique users
    unique_users = set(e['user_name'] for e in events)
    print(f"\nUnique users: {len(unique_users)}")
    for user in sorted(unique_users):
        user_events = sum(1 for e in events if e['user_name'] == user)
        print(f"  {user}: {user_events} events")
    
    # Sensitive actions found
    sensitive_count = sum(1 for e in events if e['is_sensitive_action'])
    print(f"\nSensitive actions detected: {sensitive_count}")
    
    # Suspicious IPs found
    suspicious_ip_count = sum(1 for e in events if e['is_suspicious_ip'])
    print(f"Suspicious IP events: {suspicious_ip_count}")
    
    # Events with errors
    error_count = sum(1 for e in events if e['has_error'])
    print(f"Events with errors: {error_count}")

def main():
    """Main entry point for the parser."""
    print("=" * 60)
    print("CloudTrail Log Parser")
    print("=" * 60)
    print()
    
    # Check if input file exists
    if not os.path.exists(CONFIG['input_file']):
        print(f"ERROR: Input file not found: {CONFIG['input_file']}")
        print("Please run generate_cloudtrail_data.py first!")
        return
    
    # Parse the CloudTrail logs
    #Runs the parser
    parsed_events = parse_cloudtrail_file(CONFIG['input_file'])
    
    # Save outputs
    #Saves to both CSV and JSON
    save_to_csv(parsed_events, CONFIG['output_csv'])
    save_to_json(parsed_events, CONFIG['output_json'])
    
    # Print useful summary statistics
    print_summary(parsed_events)
    
    # Show sample parsed event
    print("\n" + "=" * 60)
    print("SAMPLE PARSED EVENT")
    print("=" * 60)
    
    sample = parsed_events[0]
    for key, value in sample.items():
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 60)
    print("Parsing complete!")
    print("=" * 60)
    print(f"\nOutput files:")
    print(f"  CSV: {CONFIG['output_csv']}")
    print(f"  JSON: {CONFIG['output_json']}")


if __name__ == "__main__":
    main()