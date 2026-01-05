# Cloud Security Analytics & Threat Detection System

A cloud security platform that monitors AWS CloudTrail logs in real-time and uses machine learning to detect security anomalies.

## Architecture

```
CloudTrail → S3 → Lambda (Parse) → RDS PostgreSQL → Lambda (ML Detection) → SNS Alerts
                                          ↓
                                   Streamlit Dashboard
```

## Features

- **Real-time Monitoring**: Automated ingestion of CloudTrail events via Lambda
- **ML-based Detection**: Isolation Forest and One-Class SVM models identify anomalies
- **Threat Classification**: Detects privilege escalation, unusual access patterns, data exfiltration attempts
- **Alerting**: SNS notifications for high-severity threats
- **Dashboard**: Interactive Streamlit interface for security analytics

## Tech Stack

**Cloud**: AWS (CloudTrail, S3, Lambda, RDS, SNS, EventBridge)  
**Backend**: Python, PostgreSQL  
**ML**: scikit-learn (Isolation Forest, One-Class SVM)  
**Frontend**: Streamlit, Plotly

## Project Structure

```
├── scripts/
│   ├── generate_cloudtrail_data.py   # Training data generator
│   ├── parse_cloudtrail.py           # Log parsing utilities
│   └── feature_extraction.py         # ML feature engineering
├── models/                           # Trained ML models
├── lambda/                           # AWS Lambda functions
├── dashboard/                        # Streamlit application
└── data/                             # Sample and processed data
```

## Quick Start

```bash
# Clone and setup
git clone https://github.com/FatimaNawaz101/cloud-security-project.git
cd cloud-security-project
pip install -r requirements.txt

# Configure AWS
aws configure

# Generate sample data
python scripts/generate_cloudtrail_data.py

# Run dashboard
streamlit run dashboard/app.py
```

## Detection Capabilities

| Threat Type | Detection Method |
|-------------|------------------|
| Privilege Escalation | CreateUser, CreateAccessKey, AttachPolicy events |
| Unusual Access | Off-hours activity, foreign IP addresses |
| Failed Attacks | Multiple authentication failures |
| Data Exfiltration | Unusual S3 GetObject patterns |
| Log Tampering | StopLogging, DeleteTrail attempts |

## ML Approach

The system uses unsupervised anomaly detection to identify threats without requiring labeled attack data:

- **Isolation Forest**: Efficiently isolates anomalies in high-dimensional event data
- **One-Class SVM**: Learns decision boundary around normal behavior patterns

Features extracted include temporal patterns, user behavior metrics, action sensitivity scores, and network indicators.

## Results

- **Dataset**: 1000+ CloudTrail events (90% normal, 10% anomalous)
- **Model Performance**: Precision, recall, and F1 scores evaluated on held-out test data
- **False Positive Rate**: Minimized through dual-model consensus approach

## Author

**Fatima Nawaz**  
