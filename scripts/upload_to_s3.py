"""
S3 Upload Script
Uploads local data files to S3 bucket for analytics
Author: Fatima Nawaz
Date: January 2026
"""

import boto3
import os
from botocore.exceptions import ClientError

# Configuration
CONFIG = {
    "bucket_name": "cloud-security-analytics-797923186700",  # Your bucket name
    "region": "us-east-1",
    "files_to_upload": [
        {
            "local_path": "../data/cloudtrail_events.json",
            "s3_key": "raw/cloudtrail_events.json"
        },
        {
            "local_path": "../data/processed/features.csv",
            "s3_key": "processed/features.csv"
        },
        {
            "local_path": "../data/processed/feature_summary.json",
            "s3_key": "processed/feature_summary.json"
        },
        {
        "local_path": "../data/results/anomaly_predictions.csv",
        "s3_key": "results/anomaly_predictions.csv"
    },
    {
        "local_path": "../data/results/detection_summary.json",
        "s3_key": "results/detection_summary.json"
    }
    ]
}


def get_s3_client():
    """Create an S3 client."""
    return boto3.client('s3', region_name=CONFIG['region'])


def check_bucket_exists(s3_client, bucket_name):
    """Check if the S3 bucket exists and we have access."""
    try:
        s3_client.head_bucket(Bucket=bucket_name)
        print(f"✓ Bucket '{bucket_name}' exists and is accessible")
        return True
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == '404':
            print(f"✗ Bucket '{bucket_name}' does not exist")
        elif error_code == '403':
            print(f"✗ Access denied to bucket '{bucket_name}'")
        else:
            print(f"✗ Error accessing bucket: {e}")
        return False


def upload_file(s3_client, local_path, bucket_name, s3_key):
    """Upload a single file to S3."""
    # Check if local file exists
    if not os.path.exists(local_path):
        print(f"  ✗ Local file not found: {local_path}")
        return False
    
    try:
        # Get file size for progress info
        file_size = os.path.getsize(local_path)
        file_size_kb = file_size / 1024
        
        print(f"  Uploading: {local_path} ({file_size_kb:.1f} KB)")
        print(f"  To: s3://{bucket_name}/{s3_key}")
        
        # Upload the file
        s3_client.upload_file(local_path, bucket_name, s3_key)
        
        print(f"  ✓ Upload successful!")
        return True
        
    except ClientError as e:
        print(f"  ✗ Upload failed: {e}")
        return False


def list_bucket_contents(s3_client, bucket_name):
    """List all objects in the bucket."""
    print(f"\nContents of s3://{bucket_name}/")
    print("-" * 50)
    
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        
        if 'Contents' not in response:
            print("  (empty)")
            return
        
        for obj in response['Contents']:
            size_kb = obj['Size'] / 1024
            print(f"  {obj['Key']:<40} {size_kb:>8.1f} KB")
        
        print(f"\nTotal objects: {len(response['Contents'])}")
        
    except ClientError as e:
        print(f"Error listing bucket: {e}")


def main():
    """Main entry point."""
    print("=" * 60)
    print("S3 Upload Script")
    print("=" * 60)
    
    # Create S3 client
    s3_client = get_s3_client()
    
    # Check bucket exists
    print(f"\nChecking bucket: {CONFIG['bucket_name']}")
    if not check_bucket_exists(s3_client, CONFIG['bucket_name']):
        print("\nPlease create the bucket first and update CONFIG['bucket_name']")
        return
    
    # Upload files
    print("\n" + "-" * 60)
    print("Uploading files...")
    print("-" * 60)
    
    success_count = 0
    for file_info in CONFIG['files_to_upload']:
        print()
        if upload_file(
            s3_client,
            file_info['local_path'],
            CONFIG['bucket_name'],
            file_info['s3_key']
        ):
            success_count += 1
    
    # Summary
    print("\n" + "-" * 60)
    print(f"Upload complete: {success_count}/{len(CONFIG['files_to_upload'])} files")
    print("-" * 60)
    
    # List bucket contents
    list_bucket_contents(s3_client, CONFIG['bucket_name'])
    
    print("\n" + "=" * 60)
    print("Done!")
    print("=" * 60)


if __name__ == "__main__":
    main()