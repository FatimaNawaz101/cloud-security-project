"""
Feature Engineering Pipeline for CloudTrail Security Analytics
Transforms raw CloudTrail events into ML-ready features
Author: Fatima Nawaz
Date: January 2026
"""

import json
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict
import os
import warnings

warnings.filterwarnings('ignore')
#Configuration
#Setting up configuration for input output paths
CONFIG = {
    "input_file": "../data/cloudtrail_events.json",
    "output_file": "../data/processed/features.csv",
    "output_summary": "../data/processed/feature_summary.json"
}

# Security-relevant constants
#Defining secruity relevant action categories
SENSITIVE_ACTIONS = [
    "CreateUser", "CreateAccessKey", "AttachUserPolicy", "PutUserPolicy",
    "AddUserToGroup", "CreateRole", "DeleteUser", "DeleteAccessKey",
    "StopLogging", "DeleteTrail", "UpdateTrail", "DeleteBucket",
    "CreateDBSnapshot", "CopyDBSnapshot", "ListSecrets", "GetSecretValue",
    "PutBucketPolicy", "DeleteBucketPolicy", "CreateLoginProfile"
]

RECON_ACTIONS = [
    "ListUsers", "ListRoles", "ListBuckets", "ListAccessKeys",
    "DescribeInstances", "DescribeDBInstances", "ListSecrets",
    "GetAccountSummary", "ListGroups", "ListPolicies"
]

DATA_ACCESS_ACTIONS = [
    "GetObject", "PutObject", "DeleteObject", "CopyObject",
    "GetBucketAcl", "GetObjectAcl"
]

#Listing known suspicious IPs and user agents
SUSPICIOUS_IPS = [
    "45.227.255.206", "103.75.118.91", "185.220.101.34",
    "91.240.118.172", "23.94.188.246"
]

SUSPICIOUS_USER_AGENTS = [
    "kali", "parrot", "pentoo", "blackarch",  # Security distros
    "sqlmap", "nikto", "nmap", "masscan",      # Hacking tools
    "curl", "wget", "python-requests"          # Scripting (suspicious in some contexts)
]

print("Feature Engineering Pipeline initialized")
print(f"Input: {CONFIG['input_file']}")
print(f"Output: {CONFIG['output_file']}")

# DATA LOADING
#Reads JSON file and extracts events from it and we return those events so they can be used in another function
def load_cloudtrail_data(filepath):
    """
    Extract: Load raw CloudTrail JSON data.
    """
    print(f"\n{'='*60}")
    print("EXTRACT PHASE: Loading raw data")
    print('='*60)
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Input file not found: {filepath}")
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    # CloudTrail format has events in 'Records' array
    events = data.get('Records', [])
    
    print(f"✓ Loaded {len(events)} raw events")
    return events

#Transforms or flattens the JSON formatted events into flat pandas Dataframe
def events_to_dataframe(events):
    """
    Convert list of event dictionaries to a pandas DataFrame.
    Flattens nested structures.
    """
    rows = []
    
    for event in events:
        row = {
            # Event identification
            'event_id': event.get('eventID', ''),
            'event_time': event.get('eventTime', ''),
            'event_source': event.get('eventSource', ''),
            'event_name': event.get('eventName', ''),
            'aws_region': event.get('awsRegion', ''),
            
            # User information (nested)
            'user_type': event.get('userIdentity', {}).get('type', ''),
            'user_name': event.get('userIdentity', {}).get('userName', 'Unknown'),
            'user_arn': event.get('userIdentity', {}).get('arn', ''),
            'account_id': event.get('userIdentity', {}).get('accountId', ''),
            
            # Network information
            'source_ip': event.get('sourceIPAddress', ''),
            'user_agent': event.get('userAgent', ''),
            
            # Status
            'error_code': event.get('errorCode', ''),
            'error_message': event.get('errorMessage', ''),
            
            # Original labels (from our generated data)
            'is_anomaly_original': event.get('is_anomaly', None),
            'anomaly_type_original': event.get('anomaly_type', None)
        }
        rows.append(row)
    
    df = pd.DataFrame(rows)
    
    # Convert event_time to datetime
    df['event_time'] = pd.to_datetime(df['event_time'], format='%Y-%m-%dT%H:%M:%SZ', errors='coerce')
    
    print(f"✓ Converted to DataFrame with {len(df)} rows and {len(df.columns)} columns")
    return df

#This function extracts hour,day and month from timestamps
#Create flags for business hours, weekends and latenight
def engineer_time_features(df):
    """
    Engineer time-based features from event timestamps.
    These help detect unusual activity patterns.
    """
    print("\nEngineering time-based features...")
    
    # Basic time extraction
    df['hour'] = df['event_time'].dt.hour
    df['day_of_week'] = df['event_time'].dt.dayofweek  # 0=Monday, 6=Sunday
    df['day_of_month'] = df['event_time'].dt.day
    df['month'] = df['event_time'].dt.month
    df['minute'] = df['event_time'].dt.minute
    
    # Business hours flag (9 AM - 6 PM)
    df['is_business_hours'] = df['hour'].apply(lambda x: 1 if 9 <= x <= 18 else 0)
    
    # Weekend flag
    df['is_weekend'] = df['day_of_week'].apply(lambda x: 1 if x >= 5 else 0)
    
    # Late night flag (midnight to 5 AM) - suspicious!
    df['is_late_night'] = df['hour'].apply(lambda x: 1 if 0 <= x <= 5 else 0)
    
    # Time period categories
    #categorise time into periods
    def get_time_period(hour):
        if 6 <= hour < 12:
            return 'morning'
        elif 12 <= hour < 17:
            return 'afternoon'
        elif 17 <= hour < 21:
            return 'evening'
        else:
            return 'night'
    
    df['time_period'] = df['hour'].apply(get_time_period)
    
    # Encode time period as numeric
    time_period_map = {'morning': 0, 'afternoon': 1, 'evening': 2, 'night': 3}
    df['time_period_encoded'] = df['time_period'].map(time_period_map)
    
    print(f"  ✓ Added 10 time-based features")
    return df

#User behaviour feature engineering
#Step1: Count total events per user
#Step2: Counts unique IPs per user as multiple IPS -> attackers
#Step3: calculate error rater per user as high errors->possible attack
#Step5: Flag new users with limited history
def engineer_user_features(df):
    """
    Engineer user behavior features.
    These help establish baseline behavior and detect anomalies.
    """
    print("\nEngineering user behavior features...")
    
    # Sort by time for accurate calculations
    df = df.sort_values('event_time').reset_index(drop=True)
    
    # Count events per user
    user_event_counts = df.groupby('user_name').size().to_dict()
    df['user_total_events'] = df['user_name'].map(user_event_counts)
    
    # Count unique IPs per user (multiple IPs = suspicious)
    user_unique_ips = df.groupby('user_name')['source_ip'].nunique().to_dict()
    df['user_unique_ips'] = df['user_name'].map(user_unique_ips)
    
    # Count unique event types per user
    user_unique_events = df.groupby('user_name')['event_name'].nunique().to_dict()
    df['user_unique_event_types'] = df['user_name'].map(user_unique_events)
    
    # Error rate per user
    user_errors = df.groupby('user_name')['error_code'].apply(lambda x: (x != '').sum()).to_dict()
    df['user_error_count'] = df['user_name'].map(user_errors)
    df['user_error_rate'] = df['user_error_count'] / df['user_total_events']
    
    # Is this a new user? (fewer than 5 events)
    df['is_new_user'] = df['user_total_events'].apply(lambda x: 1 if x < 5 else 0)
    
    # User activity diversity score (unique events / total events)
    df['user_activity_diversity'] = df['user_unique_event_types'] / df['user_total_events']
    
    print(f"  ✓ Added 7 user behavior features")
    return df

#This function first flags sensitive, reconnaissance and data access actions 
def engineer_event_features(df):
    """
    Engineer features based on event types and patterns.
    """
    print("\nEngineering event-based features...")
    
    # Is this a sensitive/risky action?
    df['is_sensitive_action'] = df['event_name'].apply(
        lambda x: 1 if x in SENSITIVE_ACTIONS else 0
    )
    
    # Is this a reconnaissance action?
    df['is_recon_action'] = df['event_name'].apply(
        lambda x: 1 if x in RECON_ACTIONS else 0
    )
    
    # Is this a data access action?
    df['is_data_access'] = df['event_name'].apply(
        lambda x: 1 if x in DATA_ACCESS_ACTIONS else 0
    )
    
    # Does this event have an error?
    df['has_error'] = df['error_code'].apply(lambda x: 1 if x != '' else 0)
    
    # Is this an AccessDenied error? (possible attack attempt)
    df['is_access_denied'] = df['error_code'].apply(
        lambda x: 1 if 'AccessDenied' in str(x) or 'Unauthorized' in str(x) else 0
    )
    
    # Event source category (which AWS service)
    #Step 1: categorise AWS services based on what they are designed to do -> identity, storage and compute
    #Step 2: Identify rare event types as unusual means potentially suspicious
    def categorize_event_source(source):
        if 'iam' in source.lower():
            return 'identity'
        elif 's3' in source.lower():
            return 'storage'
        elif 'ec2' in source.lower():
            return 'compute'
        elif 'rds' in source.lower():
            return 'database'
        elif 'lambda' in source.lower():
            return 'serverless'
        elif 'cloudtrail' in source.lower():
            return 'audit'
        else:
            return 'other'
    
    df['service_category'] = df['event_source'].apply(categorize_event_source)
    
    # Encode service category as numeric
    service_map = {
        'identity': 0, 'storage': 1, 'compute': 2, 
        'database': 3, 'serverless': 4, 'audit': 5, 'other': 6
    }
    df['service_category_encoded'] = df['service_category'].map(service_map)
    
    # Count events of this type in the dataset
    event_type_counts = df['event_name'].value_counts().to_dict()
    df['event_type_frequency'] = df['event_name'].map(event_type_counts)
    
    # Is this a rare event type? (fewer than 10 occurrences)
    df['is_rare_event'] = df['event_type_frequency'].apply(lambda x: 1 if x < 10 else 0)
    
    print(f"  ✓ Added 10 event-based features")
    return df

#This function flags suspicious and internal IPs
#Then we count events and unique users per IP
#then we try to detect suspicious user agents which could be any hacking tools
#lastly we try to identify if its a console or progammatic access
def engineer_network_features(df):
    """
    Engineer features based on network information (IPs, user agents).
    """
    print("\nEngineering network features...")
    
    # Is this a suspicious IP?
    df['is_suspicious_ip'] = df['source_ip'].apply(
        lambda x: 1 if x in SUSPICIOUS_IPS else 0
    )
    
    # Is this an internal IP? (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
    def is_internal_ip(ip):
        if pd.isna(ip) or ip == '':
            return 0
        if ip.startswith('192.168.') or ip.startswith('10.'):
            return 1
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return 1
            except:
                pass
        return 0
    
    df['is_internal_ip'] = df['source_ip'].apply(is_internal_ip)
    
    # Is this an AWS internal IP?
    df['is_aws_internal'] = df['source_ip'].apply(
        lambda x: 1 if 'amazonaws.com' in str(x) or 'aws.internal' in str(x) else 0
    )
    
    # Count events from this IP
    ip_event_counts = df.groupby('source_ip').size().to_dict()
    df['ip_event_count'] = df['source_ip'].map(ip_event_counts)
    
    # Count unique users from this IP
    ip_unique_users = df.groupby('source_ip')['user_name'].nunique().to_dict()
    df['ip_unique_users'] = df['source_ip'].map(ip_unique_users)
    
    # Is this IP used by multiple users? (possible shared malicious infrastructure)
    df['is_shared_ip'] = df['ip_unique_users'].apply(lambda x: 1 if x > 1 else 0)
    
    # Suspicious user agent detection
    def is_suspicious_user_agent(ua):
        if pd.isna(ua):
            return 0
        ua_lower = str(ua).lower()
        for suspicious in SUSPICIOUS_USER_AGENTS:
            if suspicious in ua_lower:
                return 1
        return 0
    
    df['is_suspicious_user_agent'] = df['user_agent'].apply(is_suspicious_user_agent)
    
    # Is this from console vs CLI/SDK?
    df['is_console_access'] = df['user_agent'].apply(
        lambda x: 1 if 'console' in str(x).lower() else 0
    )
    
    print(f"  ✓ Added 9 network features")
    return df

#This function calculates time between events
#It detcts any rapid fire events which could be scripted attacks
#It also identifies burst activity patterns
#Any unusually active users are flagged
def engineer_temporal_patterns(df):
    """
    Engineer features based on temporal patterns and sequences.
    These capture burst activity and unusual timing patterns.
    """
    print("\nEngineering temporal pattern features...")
    
    # Sort by time
    df = df.sort_values('event_time').reset_index(drop=True)
    
    # Time since previous event (in seconds)
    df['time_since_prev_event'] = df['event_time'].diff().dt.total_seconds().fillna(0)
    
    # Is this a rapid event? (less than 1 second since previous)
    df['is_rapid_event'] = df['time_since_prev_event'].apply(lambda x: 1 if 0 < x < 1 else 0)
    
    # Events in the same minute (burst detection)
    df['event_minute'] = df['event_time'].dt.floor('min')
    minute_counts = df.groupby('event_minute').size().to_dict()
    df['events_this_minute'] = df['event_minute'].map(minute_counts)
    
    # Is this part of a burst? (more than 10 events in a minute)
    df['is_burst_activity'] = df['events_this_minute'].apply(lambda x: 1 if x > 10 else 0)
    
    # Events in the same hour by same user
    df['event_hour_key'] = df['event_time'].dt.floor('h').astype(str) + '_' + df['user_name']
    user_hour_counts = df.groupby('event_hour_key').size().to_dict()
    df['user_events_this_hour'] = df['event_hour_key'].map(user_hour_counts)
    
    # Is this user unusually active this hour? (more than 20 events)
    df['is_unusual_user_activity'] = df['user_events_this_hour'].apply(lambda x: 1 if x > 20 else 0)
    
    # Clean up temporary columns
    df = df.drop(columns=['event_minute', 'event_hour_key'])
    
    print(f"  ✓ Added 6 temporal pattern features")
    return df


#This function combines multiple risk factors into a single score
#Then it normalizes the score to 1-100 scale
#then categorizes it into low/medium/high/critical
def calculate_risk_score(df):
    """
    Calculate a composite risk score based on multiple factors.
    """
    print("\nCalculating risk scores...")
    
    # Initialize risk score
    df['risk_score'] = 0
    
    # Add points for various risk factors
    df['risk_score'] += df['is_sensitive_action'] * 3      # High risk
    df['risk_score'] += df['is_recon_action'] * 2          # Medium risk
    df['risk_score'] += df['is_suspicious_ip'] * 3         # High risk
    df['risk_score'] += df['is_suspicious_user_agent'] * 2 # Medium risk
    df['risk_score'] += df['is_late_night'] * 1            # Low risk
    df['risk_score'] += df['is_weekend'] * 1               # Low risk
    df['risk_score'] += df['has_error'] * 1                # Low risk
    df['risk_score'] += df['is_access_denied'] * 2         # Medium risk
    df['risk_score'] += df['is_burst_activity'] * 2        # Medium risk
    df['risk_score'] += df['is_new_user'] * 1              # Low risk
    df['risk_score'] += df['is_rare_event'] * 1            # Low risk
    
    # Normalize to 0-100 scale
    max_possible_score = 3 + 2 + 3 + 2 + 1 + 1 + 1 + 2 + 2 + 1 + 1  # = 19
    df['risk_score_normalized'] = (df['risk_score'] / max_possible_score * 100).round(2)
    
    # Categorize risk level
    def categorize_risk(score):
        if score >= 70:
            return 'critical'
        elif score >= 50:
            return 'high'
        elif score >= 25:
            return 'medium'
        else:
            return 'low'
    
    df['risk_level'] = df['risk_score_normalized'].apply(categorize_risk)
    
    # Encode risk level as numeric
    risk_map = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
    df['risk_level_encoded'] = df['risk_level'].map(risk_map)
    
    print(f"  ✓ Added 4 risk scoring features")
    return df


def run_feature_engineering_pipeline(input_file, output_file):
    """
    Run the complete feature engineering pipeline.
    """
    print("\n" + "=" * 60)
    print("FEATURE ENGINEERING PIPELINE")
    print("=" * 60)
    
    # EXTRACT
    events = load_cloudtrail_data(input_file)
    
    # TRANSFORM
    print(f"\n{'='*60}")
    print("TRANSFORM PHASE: Engineering features")
    print('='*60)
    
    df = events_to_dataframe(events)
    df = engineer_time_features(df)
    df = engineer_user_features(df)
    df = engineer_event_features(df)
    df = engineer_network_features(df)
    df = engineer_temporal_patterns(df)
    df = calculate_risk_score(df)
    
    # LOAD
    print(f"\n{'='*60}")
    print("LOAD PHASE: Saving processed data")
    print('='*60)
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Save to CSV
    df.to_csv(output_file, index=False)
    print(f"✓ Saved {len(df)} rows to {output_file}")
    
    return df


def print_feature_summary(df):
    """
    Print summary statistics of engineered features.
    """
    print("\n" + "=" * 60)
    print("FEATURE SUMMARY")
    print("=" * 60)
    
    print(f"\nDataset shape: {df.shape[0]} rows × {df.shape[1]} columns")
    
    # List all features
    print(f"\nAll features ({len(df.columns)}):")
    for i, col in enumerate(df.columns, 1):
        print(f"  {i:2}. {col}")
    
    # Risk distribution
    print("\nRisk Level Distribution:")
    risk_dist = df['risk_level'].value_counts()
    for level in ['low', 'medium', 'high', 'critical']:
        count = risk_dist.get(level, 0)
        pct = count / len(df) * 100
        bar = '█' * int(pct / 2)
        print(f"  {level.upper():8}: {count:4} ({pct:5.1f}%) {bar}")
    
    # Anomaly comparison (if original labels exist)
    if 'is_anomaly_original' in df.columns and df['is_anomaly_original'].notna().any():
        print("\nOriginal Anomaly Distribution:")
        anomaly_dist = df['is_anomaly_original'].value_counts()
        for label, count in anomaly_dist.items():
            pct = count / len(df) * 100
            print(f"  {str(label):8}: {count:4} ({pct:5.1f}%)")
    
    # Top users by event count
    print("\nTop 5 Users by Event Count:")
    top_users = df.groupby('user_name').size().nlargest(5)
    for user, count in top_users.items():
        print(f"  {user}: {count} events")
    
    # Feature statistics
    print("\nKey Feature Statistics:")
    key_features = [
        'risk_score_normalized', 'user_total_events', 'user_error_rate',
        'time_since_prev_event', 'events_this_minute'
    ]
    for feat in key_features:
        if feat in df.columns:
            print(f"  {feat}:")
            print(f"    Mean: {df[feat].mean():.2f}, Std: {df[feat].std():.2f}")
            print(f"    Min: {df[feat].min():.2f}, Max: {df[feat].max():.2f}")


def save_feature_summary(df, output_path):
    """
    Save feature summary as JSON for documentation.
    """
    summary = {
        "total_events": len(df),
        "total_features": len(df.columns),
        "features": list(df.columns),
        "risk_distribution": df['risk_level'].value_counts().to_dict(),
        "unique_users": df['user_name'].nunique(),
        "unique_ips": df['source_ip'].nunique(),
        "date_range": {
            "start": str(df['event_time'].min()),
            "end": str(df['event_time'].max())
        },
        "sensitive_action_count": int(df['is_sensitive_action'].sum()),
        "suspicious_ip_count": int(df['is_suspicious_ip'].sum()),
        "error_count": int(df['has_error'].sum())
    }
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"✓ Saved feature summary to {output_path}")


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    print("=" * 60)
    print("CloudTrail Feature Engineering Pipeline")
    print("=" * 60)
    
    # Run pipeline
    df = run_feature_engineering_pipeline(
        CONFIG['input_file'],
        CONFIG['output_file']
    )
    
    # Print summary
    print_feature_summary(df)
    
    # Save summary
    save_feature_summary(df, CONFIG['output_summary'])
    
    print("\n" + "=" * 60)
    print("PIPELINE COMPLETE!")
    print("=" * 60)
    print(f"\nOutput files:")
    print(f"  Features CSV: {CONFIG['output_file']}")
    print(f"  Summary JSON: {CONFIG['output_summary']}")
    print(f"\nTotal features engineered: {len(df.columns)}")
    print(f"Ready for anomaly detection!")


if __name__ == "__main__":
    main()
