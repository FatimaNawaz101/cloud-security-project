"""
CloudTrail Sample Data Generator
Generates realistic AWS CloudTrail events for ML training
Author: Fatima Nawaz
Date: January 2026
"""
import json # For creating JSON-formatted events
import random #For generating random but realistic data
from datetime import datetime,timedelta #For creating timestamps
import os # For file path handling

#CONFIG is the Central place for all settings
CONFIG={
    "account_id":"797923186700",
    "total_events": 1000,
    "anomaly_percentage": 10,
    "output_file": "../data/cloudtrail_events.json",
    "days_of_data": 30
}

#Define normal activity patterns
#Defining 5 fake employees with consistent IPs as people work from same locations
#Simulated users in "our company"
NORMAL_USERS=[
    {"userName": "john.doe","role": "developer", "ip": "192.168.1.100"},
    {"userName": "jane.smith", "role": "developer", "ip": "192.168.1.101"},
    {"userName": "mike.wilson", "role": "analyst", "ip": "192.168.1.102"},
    {"userName": "sarah.jones", "role": "admin", "ip": "192.168.1.103"},
    {"userName": "cloud-security-dev", "role": "developer", "ip": "192.168.1.104"},
]

#What each role typically does
#Maps job roles to typical AWS actions
ROLE_ACTIONS = {
    "developer": [
        ("s3.amazonaws.com", "ListBuckets"),
        ("s3.amazonaws.com", "GetObject"),
        ("s3.amazonaws.com", "PutObject"),
        ("lambda.amazonaws.com", "ListFunctions"),
        ("lambda.amazonaws.com", "InvokeFunction"),
        ("logs.amazonaws.com", "DescribeLogGroups"),
        ("ec2.amazonaws.com", "DescribeInstances"),
    ],
    "analyst": [
        ("s3.amazonaws.com", "ListBuckets"),
        ("s3.amazonaws.com", "GetObject"),
        ("rds.amazonaws.com", "DescribeDBInstances"),
        ("cloudwatch.amazonaws.com", "GetMetricData"),
        ("athena.amazonaws.com", "StartQueryExecution"),
    ],
    "admin": [
        ("iam.amazonaws.com", "ListUsers"),
        ("iam.amazonaws.com", "GetUser"),
        ("s3.amazonaws.com", "ListBuckets"),
        ("ec2.amazonaws.com", "DescribeInstances"),
        ("cloudtrail.amazonaws.com", "DescribeTrails"),
        ("organizations.amazonaws.com", "ListAccounts"),
    ]
}

#Normal working hours (9AM - 6PM)
BUSINESS_HOURS=(9,18)

#Common user agents for normal activity
#Lists normal browser/CLI user agents
NORMAL_USER_AGENTS=[
    "aws-cli/2.15.0 Python/3.11.0 Windows/10",
    "aws-sdk-python/1.34.0 Python/3.11.0",
    "console.amazonaws.com",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
]

#Anomalous/attack patterns
#Define IPs that would look suspicious from foreign countries
SUSPICIOUS_IPS=[
    "45.227.255.206",   # South America
    "103.75.118.91",    # Asia
    "185.220.101.34",   # Europe (Tor exit node pattern)
    "91.240.118.172",   # Eastern Europe
    "23.94.188.246",    # VPN/Proxy
]

#Actions that could indicate potential attacks
#Lists actions that attackers typically perform which creates credentials and disables logging etc
SENSITIVE_ACTIONS=[
    #Privilege escalation
    ("iam.amazonaws.com", "CreateUser"),
    ("iam.amazonaws.com", "CreateAccessKey"),
    ("iam.amazonaws.com", "AttachUserPolicy"),
    ("iam.amazonaws.com", "PutUserPolicy"),
    ("iam.amazonaws.com", "AddUserToGroup"),
    ("iam.amazonaws.com", "CreateRole"),

    #Covering tracks
    ("cloudtrail.amazonaws.com", "StopLogging"),
     ("cloudtrail.amazonaws.com", "DeleteTrail"),
    ("cloudtrail.amazonaws.com", "UpdateTrail"),
    ("s3.amazonaws.com", "DeleteBucket"),

     # Data Exfiltration
    ("s3.amazonaws.com", "GetObject"),
    ("rds.amazonaws.com", "CreateDBSnapshot"),
    ("rds.amazonaws.com", "CopyDBSnapshot"),
    
    # Reconnaissance
    ("iam.amazonaws.com", "ListUsers"),
    ("iam.amazonaws.com", "ListRoles"),
    ("iam.amazonaws.com", "ListAccessKeys"),
    ("s3.amazonaws.com", "ListBuckets"),
    ("ec2.amazonaws.com", "DescribeInstances"),
    ("secretsmanager.amazonaws.com", "ListSecrets"),
]

#Anomaly types we will generate
#categorising different types of anomalies
ANOMALY_TYPES =[
    "unusual_time",             # Activity at 3 AM
    "unusual_ip",               # Login from foreign IP
     "privilege_escalation",   # Creating users/keys
    "failed_attempts",        # Multiple auth failures
    "sensitive_action",       # Deleting trails, accessing secrets
    "rapid_enumeration",      # Fast scanning of resources
]

# User agents that look suspicious
SUSPICIOUS_USER_AGENTS = [
    "python-requests/2.28.0",  # Script, not interactive
    "curl/7.84.0",             # Command-line tool
    "aws-cli/2.15.0 Python/3.11.0 Linux/5.4.0-kali",  # Kali Linux!
    "Boto3/1.26.0 Python/3.9.0",  # Automated script
]

#helper functions
#Creates realistic times as anomalies usually happen at night
def generate_timestamp(is_anomaly=False, anomaly_type=None):
    """Generate a realistic timestamp."""
    # Random day within our data range
    base_date = datetime.now() - timedelta(days=random.randint(0, CONFIG["days_of_data"]))
    
    if is_anomaly and anomaly_type == "unusual_time":
        # Anomaly: Activity at unusual hours (midnight to 5 AM)
        hour = random.randint(0, 5)
    else:
        # Normal: Activity during business hours with some variance
        hour = random.randint(BUSINESS_HOURS[0], BUSINESS_HOURS[1])
    
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    
    timestamp = base_date.replace(hour=hour, minute=minute, second=second, microsecond=0)
    return timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")

#Generates fake but realistic looking AWS IDs
def generate_principal_id():
    """Generate a fake AWS principal ID."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "AIDA" + "".join(random.choices(chars, k=16))

#generates a unique identifier for each event
def generate_event_id():
    """Generate a unique event ID."""
    import uuid
    return str(uuid.uuid4())

#Creates the JSON structure matching real CloudTrail
def create_base_event(user, event_source, event_name, timestamp, source_ip, user_agent, error_code=None):
    """Create a CloudTrail event with the standard structure."""
    event = {
        "eventVersion": "1.08",
        "eventID": generate_event_id(),
        "eventTime": timestamp,
        "eventSource": event_source,
        "eventName": event_name,
        "awsRegion": "us-east-1",
        "sourceIPAddress": source_ip,
        "userAgent": user_agent,
        "userIdentity": {
            "type": "IAMUser",
            "principalId": generate_principal_id(),
            "arn": f"arn:aws:iam::{CONFIG['account_id']}:user/{user['userName']}",
            "accountId": CONFIG["account_id"],
            "userName": user["userName"]
        },
        "requestParameters": {},
        "responseElements": {},
        "errorCode": error_code,
        "errorMessage": f"Access Denied for {event_name}" if error_code else None,
    }
    return event

#Event generators for anomaly detection
#Creates boring everyday monotonous activity
def generate_normal_event():
    """Generate a normal, non-suspicious event."""
    # Pick a random user
    user = random.choice(NORMAL_USERS)
    
    # Pick an action appropriate for their role
    event_source, event_name = random.choice(ROLE_ACTIONS[user["role"]])
    
    # Use their normal IP
    source_ip = user["ip"]
    
    # Normal timestamp (business hours)
    timestamp = generate_timestamp(is_anomaly=False)
    
    # Normal user agent
    user_agent = random.choice(NORMAL_USER_AGENTS)
    
    # Low error rate for normal users (5%)
    error_code = "AccessDenied" if random.random() < 0.05 else None
    
    # Create the event
    event = create_base_event(user, event_source, event_name, timestamp, source_ip, user_agent, error_code)
    
    # Add our training labels
    event["is_anomaly"] = False
    event["anomaly_type"] = None
    
    return event

#This function creates different types of attacks based on anomaly_type
#each anomaly has realistic characterstics like failed logins have error codes
def generate_anomalous_event():
    """Generate a suspicious/attack event."""
    # Pick anomaly type
    anomaly_type = random.choice(ANOMALY_TYPES)
    
    # Usually a compromised legitimate user or unknown attacker
    if random.random() < 0.7:
        user = random.choice(NORMAL_USERS)  # Compromised account
    else:
        user = {"userName": "unknown_actor", "role": "admin", "ip": "0.0.0.0"}
    
    # Select event characteristics based on anomaly type
    if anomaly_type == "unusual_time":
        event_source, event_name = random.choice(ROLE_ACTIONS.get(user.get("role", "admin"), ROLE_ACTIONS["admin"]))
        source_ip = user.get("ip", random.choice(SUSPICIOUS_IPS))
        timestamp = generate_timestamp(is_anomaly=True, anomaly_type="unusual_time")
        error_code = None
        
    elif anomaly_type == "unusual_ip":
        event_source, event_name = random.choice(ROLE_ACTIONS.get(user.get("role", "admin"), ROLE_ACTIONS["admin"]))
        source_ip = random.choice(SUSPICIOUS_IPS)  # Foreign IP!
        timestamp = generate_timestamp(is_anomaly=False)
        error_code = None
        
    elif anomaly_type == "privilege_escalation":
        # Pick from privilege escalation actions
        priv_esc_actions = [a for a in SENSITIVE_ACTIONS if "Create" in a[1] or "Attach" in a[1] or "Put" in a[1]]
        event_source, event_name = random.choice(priv_esc_actions)
        source_ip = random.choice(SUSPICIOUS_IPS) if random.random() < 0.5 else user.get("ip", "192.168.1.100")
        timestamp = generate_timestamp(is_anomaly=True, anomaly_type="unusual_time") if random.random() < 0.5 else generate_timestamp()
        error_code = None
        
    elif anomaly_type == "failed_attempts":
        event_source = "signin.amazonaws.com"
        event_name = "ConsoleLogin"
        source_ip = random.choice(SUSPICIOUS_IPS)
        timestamp = generate_timestamp(is_anomaly=False)
        error_code = "AccessDenied"  # Failed login!
        
    elif anomaly_type == "sensitive_action":
        # Pick from covering tracks or data exfiltration
        sensitive = [a for a in SENSITIVE_ACTIONS if "Delete" in a[1] or "Stop" in a[1] or "Snapshot" in a[1]]
        event_source, event_name = random.choice(sensitive)
        source_ip = user.get("ip", random.choice(SUSPICIOUS_IPS))
        timestamp = generate_timestamp(is_anomaly=True, anomaly_type="unusual_time")
        error_code = None
        
    elif anomaly_type == "rapid_enumeration":
        # Reconnaissance - listing everything
        recon_actions = [a for a in SENSITIVE_ACTIONS if "List" in a[1] or "Describe" in a[1]]
        event_source, event_name = random.choice(recon_actions)
        source_ip = random.choice(SUSPICIOUS_IPS)
        timestamp = generate_timestamp(is_anomaly=False)
        error_code = None
    
    else:
        # Default anomaly
        event_source, event_name = random.choice(SENSITIVE_ACTIONS)
        source_ip = random.choice(SUSPICIOUS_IPS)
        timestamp = generate_timestamp(is_anomaly=True, anomaly_type="unusual_time")
        error_code = None
    
    # Use suspicious user agent for anomalies
    user_agent = random.choice(SUSPICIOUS_USER_AGENTS)
    
    # Create the event
    event = create_base_event(user, event_source, event_name, timestamp, source_ip, user_agent, error_code)
    
    # Add our training labels
    event["is_anomaly"] = True
    event["anomaly_type"] = anomaly_type
    
    return event

#Main generator function
#This generates the right mix of normal which is 90% and anomalous events which is 10% of alal the events
def generate_dataset():
    """Generate the complete dataset of CloudTrail events."""
    events = []
    
    total_events = CONFIG["total_events"]
    num_anomalies = int(total_events * CONFIG["anomaly_percentage"] / 100)
    num_normal = total_events - num_anomalies
    
    print(f"Generating {total_events} CloudTrail events...")
    print(f"  - Normal events: {num_normal} ({100 - CONFIG['anomaly_percentage']}%)")
    print(f"  - Anomalous events: {num_anomalies} ({CONFIG['anomaly_percentage']}%)")
    print()
    
    # Generate normal events
    print("Generating normal events...")
    for i in range(num_normal):
        events.append(generate_normal_event())
        if (i + 1) % 100 == 0:
            print(f"  Generated {i + 1}/{num_normal} normal events")
    
    # Generate anomalous events
    print("\nGenerating anomalous events...")
    for i in range(num_anomalies):
        events.append(generate_anomalous_event())
        if (i + 1) % 20 == 0:
            print(f"  Generated {i + 1}/{num_anomalies} anomalous events")
    
    # Shuffle to mix normal and anomalous events
    print("\nShuffling events...")
    random.shuffle(events)
    
    # Sort by timestamp to simulate realistic log order
    print("Sorting by timestamp...")
    events.sort(key=lambda x: x["eventTime"])
    
    return events

#Writes to JSON and prints statistics
def save_events(events, filepath):
    """Save events to a JSON file."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    
    # Save as JSON (same format as CloudTrail)
    output = {"Records": events}
    
    with open(filepath, "w") as f:
        json.dump(output, f, indent=2)
    
    print(f"\nSaved {len(events)} events to {filepath}")
    
    # Print summary statistics
    anomaly_counts = {}
    for event in events:
        if event["is_anomaly"]:
            atype = event["anomaly_type"]
            anomaly_counts[atype] = anomaly_counts.get(atype, 0) + 1
    
    print("\nAnomaly type distribution:")
    for atype, count in sorted(anomaly_counts.items()):
        print(f"  - {atype}: {count}")

#This function brings everything together and shows a sample output
def main():
    """Main entry point."""
    print("=" * 60)
    print("CloudTrail Sample Data Generator")
    print("=" * 60)
    print()
    
    # Generate events
    events = generate_dataset()
    
    # Save to file
    save_events(events, CONFIG["output_file"])
    
    print("\n" + "=" * 60)
    print("Generation complete!")
    print("=" * 60)
    
    # Print sample events
    print("\nSample NORMAL event:")
    normal_sample = next(e for e in events if not e["is_anomaly"])
    print(json.dumps(normal_sample, indent=2)[:500] + "...")
    
    print("\nSample ANOMALOUS event:")
    anomaly_sample = next(e for e in events if e["is_anomaly"])
    print(json.dumps(anomaly_sample, indent=2)[:500] + "...")


#best practice in python for runnable scripts
if __name__ == "__main__":
    main()
