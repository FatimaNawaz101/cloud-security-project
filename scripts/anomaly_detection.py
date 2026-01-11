"""
Anomaly Detection using Isolation Forest
Detects security anomalies in CloudTrail events
Author: Fatima Nawaz
Date: January 2026
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import json
import os
import warnings

warnings.filterwarnings('ignore')

#Set up path for input and output
# Configuration
CONFIG = {
    "input_file": "../data/processed/features.csv",
    "output_predictions": "../data/results/anomaly_predictions.csv",
    "output_summary": "../data/results/detection_summary.json",
    "model_file": "../models/isolation_forest_model.pkl",
    "scaler_file": "../models/scaler.pkl",
    
    # Model parameters
    #Configuring model parameters
    #Contamination=0.10 tells the model to expect 10% anomalies which matches our generated data
    "contamination": 0.10,  # Expected percentage of anomalies (10%)
    "n_estimators": 100,    # Number of trees
    "random_state": 42      # For reproducibility
}

print("Anomaly Detection Pipeline initialized")
print(f"Input: {CONFIG['input_file']}")
print(f"Expected anomaly rate: {CONFIG['contamination']*100}%")

#This function reads the features CSV
def load_data(filepath):
    """Load the feature-engineered data."""
    print(f"\n{'='*60}")
    print("LOADING DATA")
    print('='*60)
    
    df = pd.read_csv(filepath)
    print(f"✓ Loaded {len(df)} rows and {len(df.columns)} columns")
    
    return df

#picks only numerical features the model can use
def select_features(df):
    """
    Select numerical features for the ML model.
    We exclude IDs, timestamps, and categorical strings.
    """
    print(f"\n{'='*60}")
    print("FEATURE SELECTION")
    print('='*60)
    
    # Features to use for anomaly detection
    feature_columns = [
        # Time-based features
        'hour',
        'day_of_week',
        'is_business_hours',
        'is_weekend',
        'is_late_night',
        'time_period_encoded',
        
        # User behavior features
        'user_total_events',
        'user_unique_ips',
        'user_unique_event_types',
        'user_error_rate',
        'is_new_user',
        'user_activity_diversity',
        
        # Event-based features
        'is_sensitive_action',
        'is_recon_action',
        'is_data_access',
        'has_error',
        'is_access_denied',
        'service_category_encoded',
        'event_type_frequency',
        'is_rare_event',
        
        # Network features
        'is_suspicious_ip',
        'is_internal_ip',
        'ip_event_count',
        'ip_unique_users',
        'is_shared_ip',
        'is_suspicious_user_agent',
        'is_console_access',
        
        # Temporal pattern features
        'time_since_prev_event',
        'is_rapid_event',
        'events_this_minute',
        'is_burst_activity',
        'user_events_this_hour',
        'is_unusual_user_activity',
        
        # Risk score (as additional feature)
        'risk_score_normalized'
    ]
    
    # Check which features exist in the dataframe
    available_features = [col for col in feature_columns if col in df.columns]
    missing_features = [col for col in feature_columns if col not in df.columns]
    
    if missing_features:
        print(f"⚠ Missing features (will skip): {missing_features}")
    
    print(f"✓ Selected {len(available_features)} features for model")
    
    # Extract feature matrix
    X = df[available_features].copy()
    
    # Handle any missing values
    X = X.fillna(0)
    
    # Handle infinite values
    X = X.replace([np.inf, -np.inf], 0)
    
    print(f"✓ Feature matrix shape: {X.shape}")
    
    return X, available_features

#gets the original anomaly labels for evaluation
def get_ground_truth(df):
    """
    Extract ground truth labels if available (from our generated data).
    """
    if 'is_anomaly_original' in df.columns:
        y_true = df['is_anomaly_original'].apply(lambda x: 1 if x == True else 0)
        print(f"✓ Ground truth labels found: {y_true.sum()} anomalies, {len(y_true) - y_true.sum()} normal")
        return y_true
    else:
        print("⚠ No ground truth labels found (unsupervised mode)")
        return None
    
#Normalizes data so all features have equal importance
def scale_features(X):
    """
    Standardize features to have zero mean and unit variance.
    This helps the model treat all features equally.
    """
    print(f"\n{'='*60}")
    print("SCALING FEATURES")
    print('='*60)
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"✓ Features scaled to zero mean, unit variance")
    print(f"  Mean range: [{X_scaled.mean(axis=0).min():.4f}, {X_scaled.mean(axis=0).max():.4f}]")
    print(f"  Std range: [{X_scaled.std(axis=0).min():.4f}, {X_scaled.std(axis=0).max():.4f}]")
    
    return X_scaled, scaler

#We create and train the model
def train_isolation_forest(X_scaled):
    """
    Train the Isolation Forest model.
    """
    print(f"\n{'='*60}")
    print("TRAINING ISOLATION FOREST")
    print('='*60)
    
    print(f"Parameters:")
    print(f"  n_estimators: {CONFIG['n_estimators']}")
    print(f"  contamination: {CONFIG['contamination']}")
    print(f"  random_state: {CONFIG['random_state']}")
    
    # Create and train the model
    model = IsolationForest(
        n_estimators=CONFIG['n_estimators'],
        contamination=CONFIG['contamination'],
        random_state=CONFIG['random_state'],
        n_jobs=-1  # Use all CPU cores
    )
    
    print("\nTraining model...")
    model.fit(X_scaled)
    
    print("✓ Model trained successfully!")
    
    return model

#Gets anomaly predictions and risk scores
def get_predictions(model, X_scaled):
    """
    Get anomaly predictions and scores from the trained model.
    """
    print(f"\n{'='*60}")
    print("GENERATING PREDICTIONS")
    print('='*60)
    
    # Predict: 1 = normal, -1 = anomaly (sklearn convention)
    predictions_raw = model.predict(X_scaled)
    
    # Convert to: 0 = normal, 1 = anomaly (more intuitive)
    predictions = np.where(predictions_raw == -1, 1, 0)
    
    # Get anomaly scores (lower = more anomalous)
    scores_raw = model.decision_function(X_scaled)
    
    # Convert to anomaly score where higher = more anomalous
    # Normalize to 0-100 scale
    scores_normalized = (1 - (scores_raw - scores_raw.min()) / (scores_raw.max() - scores_raw.min())) * 100
    
    print(f"✓ Predictions generated")
    print(f"  Total events: {len(predictions)}")
    print(f"  Predicted anomalies: {predictions.sum()}")
    print(f"  Predicted normal: {len(predictions) - predictions.sum()}")
    print(f"  Anomaly rate: {predictions.sum() / len(predictions) * 100:.1f}%")
    
    return predictions, scores_normalized

#Calculates accuracy,precision,recall and F1 score
def evaluate_model(y_true, y_pred, scores):
    """
    Evaluate model performance against ground truth.
    """
    print(f"\n{'='*60}")
    print("MODEL EVALUATION")
    print('='*60)
    
    if y_true is None:
        print("⚠ No ground truth available for evaluation")
        return {}
    
    # Confusion Matrix
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print("\nConfusion Matrix:")
    print(f"                 Predicted")
    print(f"                 Normal  Anomaly")
    print(f"  Actual Normal    {tn:4}    {fp:4}")
    print(f"  Actual Anomaly   {fn:4}    {tp:4}")
    
    # Calculate metrics
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # ROC AUC Score
    try:
        roc_auc = roc_auc_score(y_true, scores)
    except:
        roc_auc = 0
    
    print(f"\nPerformance Metrics:")
    print(f"  Accuracy:  {accuracy:.4f}  ({accuracy*100:.1f}%)")
    print(f"  Precision: {precision:.4f}  ({precision*100:.1f}%)")
    print(f"  Recall:    {recall:.4f}  ({recall*100:.1f}%)")
    print(f"  F1 Score:  {f1:.4f}  ({f1*100:.1f}%)")
    print(f"  ROC AUC:   {roc_auc:.4f}  ({roc_auc*100:.1f}%)")
    
    # Interpretation
    print(f"\nInterpretation:")
    print(f"  • Precision {precision*100:.1f}%: Of events flagged as anomalies, {precision*100:.1f}% were actual anomalies")
    print(f"  • Recall {recall*100:.1f}%: Of actual anomalies, we detected {recall*100:.1f}%")
    print(f"  • F1 {f1*100:.1f}%: Harmonic mean of precision and recall")
    
    metrics = {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "true_positives": int(tp),
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn)
    }
    
    return metrics

#shows which feature matters most for anomaly detection
def analyze_feature_importance(model, feature_names, X_scaled):
    """
    Analyze which features contribute most to anomaly detection.
    Note: Isolation Forest doesn't have direct feature importances,
    so we use a proxy method based on score variation.
    """
    print(f"\n{'='*60}")
    print("FEATURE IMPORTANCE ANALYSIS")
    print('='*60)
    
    # Calculate feature importance using permutation-like approach
    base_scores = model.decision_function(X_scaled)
    importances = []
    
    for i, feature in enumerate(feature_names):
        # Create a copy and shuffle this feature
        X_permuted = X_scaled.copy()
        np.random.shuffle(X_permuted[:, i])
        
        # Calculate new scores
        permuted_scores = model.decision_function(X_permuted)
        
        # Importance = how much scores changed
        importance = np.abs(base_scores - permuted_scores).mean()
        importances.append((feature, importance))
    
    # Sort by importance
    importances.sort(key=lambda x: x[1], reverse=True)
    
    print("\nTop 10 Most Important Features:")
    for i, (feature, importance) in enumerate(importances[:10], 1):
        bar = '█' * int(importance * 100)
        print(f"  {i:2}. {feature:<30} {importance:.4f} {bar}")
    
    return importances

#Add ML predictions to original data and saves CSV
def save_predictions(df, predictions, scores, output_path):
    """
    Save predictions back to the original dataframe.
    """
    print(f"\n{'='*60}")
    print("SAVING PREDICTIONS")
    print('='*60)
    
    # Add predictions to dataframe
    df_results = df.copy()
    df_results['ml_anomaly_prediction'] = predictions
    df_results['ml_anomaly_score'] = scores.round(2)
    
    # Add anomaly severity based on score
    def get_severity(score):
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 40:
            return 'medium'
        else:
            return 'low'
    
    df_results['ml_severity'] = df_results['ml_anomaly_score'].apply(get_severity)
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Save to CSV
    df_results.to_csv(output_path, index=False)
    
    print(f"✓ Saved predictions to {output_path}")
    print(f"  Total rows: {len(df_results)}")
    print(f"  Columns added: ml_anomaly_prediction, ml_anomaly_score, ml_severity")
    
    # Print severity distribution
    print(f"\nSeverity Distribution (predicted anomalies only):")
    anomalies = df_results[df_results['ml_anomaly_prediction'] == 1]
    severity_counts = anomalies['ml_severity'].value_counts()
    for severity in ['critical', 'high', 'medium', 'low']:
        count = severity_counts.get(severity, 0)
        print(f"  {severity.upper():8}: {count}")
    
    return df_results

#Saves trained model for reuse
def save_model(model, scaler, model_path, scaler_path):
    """
    Save the trained model and scaler for later use.
    """
    print(f"\n{'='*60}")
    print("SAVING MODEL")
    print('='*60)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    
    # Save model
    joblib.dump(model, model_path)
    print(f"✓ Model saved to {model_path}")
    
    # Save scaler
    joblib.dump(scaler, scaler_path)
    print(f"✓ Scaler saved to {scaler_path}")

#Saves metrics + feature importance as JSON
def save_summary(metrics, feature_importances, output_path):
    """
    Save detection summary as JSON.
    """
    summary = {
        "model": "Isolation Forest",
        "parameters": {
            "n_estimators": CONFIG['n_estimators'],
            "contamination": CONFIG['contamination'],
            "random_state": CONFIG['random_state']
        },
        "metrics": metrics,
        "top_features": [
            {"feature": f, "importance": round(i, 4)} 
            for f, i in feature_importances[:10]
        ]
    }
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"✓ Summary saved to {output_path}")


def run_anomaly_detection_pipeline():
    """
    Run the complete anomaly detection pipeline.
    """
    print("\n" + "=" * 60)
    print("ANOMALY DETECTION PIPELINE")
    print("=" * 60)
    
    # Step 1: Load data
    df = load_data(CONFIG['input_file'])
    
    # Step 2: Select features
    X, feature_names = select_features(df)
    
    # Step 3: Get ground truth (if available)
    y_true = get_ground_truth(df)
    
    # Step 4: Scale features
    X_scaled, scaler = scale_features(X)
    
    # Step 5: Train model
    model = train_isolation_forest(X_scaled)
    
    # Step 6: Get predictions
    predictions, scores = get_predictions(model, X_scaled)
    
    # Step 7: Evaluate model
    metrics = evaluate_model(y_true, predictions, scores)
    
    # Step 8: Analyze feature importance
    importances = analyze_feature_importance(model, feature_names, X_scaled)
    
    # Step 9: Save predictions
    df_results = save_predictions(df, predictions, scores, CONFIG['output_predictions'])
    
    # Step 10: Save model
    save_model(model, scaler, CONFIG['model_file'], CONFIG['scaler_file'])
    
    # Step 11: Save summary
    save_summary(metrics, importances, CONFIG['output_summary'])
    
    return df_results, model, metrics


def print_final_summary(df_results, metrics):
    """
    Print a final summary of the detection results.
    """
    print("\n" + "=" * 60)
    print("FINAL SUMMARY")
    print("=" * 60)
    
    total = len(df_results)
    anomalies = df_results['ml_anomaly_prediction'].sum()
    normal = total - anomalies
    
    print(f"\nDataset Summary:")
    print(f"  Total events:      {total}")
    print(f"  Predicted normal:  {normal} ({normal/total*100:.1f}%)")
    print(f"  Predicted anomaly: {anomalies} ({anomalies/total*100:.1f}%)")
    
    if metrics:
        print(f"\nModel Performance:")
        print(f"  Accuracy:  {metrics['accuracy']*100:.1f}%")
        print(f"  Precision: {metrics['precision']*100:.1f}%")
        print(f"  Recall:    {metrics['recall']*100:.1f}%")
        print(f"  F1 Score:  {metrics['f1_score']*100:.1f}%")
    
    print(f"\nTop 5 Highest Risk Events:")
    top_anomalies = df_results.nlargest(5, 'ml_anomaly_score')[
        ['user_name', 'event_name', 'source_ip', 'ml_anomaly_score', 'ml_severity']
    ]
    print(top_anomalies.to_string(index=False))
    
    print("\n" + "=" * 60)
    print("Pipeline complete!")
    print("=" * 60)
    print(f"\nOutput files:")
    print(f"  Predictions: {CONFIG['output_predictions']}")
    print(f"  Model:       {CONFIG['model_file']}")
    print(f"  Summary:     {CONFIG['output_summary']}")


def main():
    """Main entry point."""
    # Run pipeline
    df_results, model, metrics = run_anomaly_detection_pipeline()
    
    # Print final summary
    print_final_summary(df_results, metrics)


if __name__ == "__main__":
    main()