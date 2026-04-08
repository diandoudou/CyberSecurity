import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder
import joblib
import os

def load_data(file_path):
    """
    Load dataset and preprocess
    """
    # Load data
    print(f"Loading data file: {file_path}")
    data = pd.read_csv(file_path)
    print(f"Total samples: {len(data)}")
    print(f"Original data distribution:\n{data['Attribute'].value_counts()}")
    
    # Handle missing values
    numeric_columns = ['url_length', 'has_ip', 'dot_count', 'protocol_http', 
                      'protocol_https', 'subdomain_count', 'dns_valid', 
                      'site_accessible', 'has_iframe', 'has_obfuscated_script', 
                      'whois_available']
    
    print("\nFeature statistics:")
    for col in numeric_columns:
        missing = data[col].isnull().sum()
        print(f"{col}: Missing values = {missing}")
        data[col] = pd.to_numeric(data[col], errors='coerce')
        data[col] = data[col].fillna(0)
    
    # Handle domain_age separately
    missing_age = data['domain_age'].isnull().sum()
    print(f"domain_age: Missing values = {missing_age}")
    data['domain_age'] = data['domain_age'].fillna(-1)
    
    # Convert labels to numeric values
    le = LabelEncoder()
    data['label'] = le.fit_transform(data['Attribute'])
    
    # Select features
    features = ['url_length', 'has_ip', 'dot_count', 'protocol_http', 'protocol_https',
               'subdomain_count', 'domain_age', 'dns_valid', 'site_accessible',
               'has_iframe', 'has_obfuscated_script', 'whois_available']
    
    X = data[features].astype(float)
    y = data['label']
    
    return X, y

def prepare_data(X, y):
    """
    Prepare training and testing data
    """
    print("\nData split:")
    print(f"Number of features: {X.shape[1]}")
    print(f"Total samples: {len(X)}")
    
    # Split into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    print(f"Training samples: {len(X_train)}")
    print(f"Testing samples: {len(X_test)}")
    print(f"Training label distribution:\n{pd.Series(y_train).value_counts()}")
    print(f"Testing label distribution:\n{pd.Series(y_test).value_counts()}")
    
    return X_train, X_test, y_train, y_test

def train_random_forest(X_train, y_train):
    """
    Train Random Forest model
    """
    print("\nStarting Random Forest model training:")
    print(f"Training samples: {len(X_train)}")
    
    # Create Random Forest classifier
    rf_classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        random_state=42
    )
    
    print("Model parameters:")
    print(f"- Number of trees: {rf_classifier.n_estimators}")
    print(f"- Maximum depth: {'Unlimited' if rf_classifier.max_depth is None else rf_classifier.max_depth}")
    print(f"- Minimum samples to split: {rf_classifier.min_samples_split}")
    print(f"- Minimum samples per leaf: {rf_classifier.min_samples_leaf}")
    
    # Evaluate model using cross-validation
    print("\nStarting 5-fold cross-validation...")
    cv_scores = cross_val_score(rf_classifier, X_train, y_train, cv=5)
    print(f"Cross-validation scores: {cv_scores}")
    print(f"Average CV score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    
    # Train the final model on the complete training set
    print("\nTraining final model on complete training set...")
    rf_classifier.fit(X_train, y_train)
    
    return rf_classifier

def evaluate_model(model, X_test, y_test):
    """
    Evaluate model performance
    """
    # Make predictions on test set
    print("\nModel evaluation:")
    print(f"Test samples: {len(X_test)}")
    y_pred = model.predict(X_test)
    
    # Print classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Print confusion matrix
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Print feature importance
    feature_names = ['URL Length', 'IP Address', 'Dot Count', 'HTTP Protocol', 'HTTPS Protocol',
                    'Subdomain Count', 'Domain Age', 'DNS Validity', 'Site Accessibility',
                    'iFrame', 'Obfuscated Script', 'WHOIS Availability']
    importances = pd.DataFrame({
        'Feature': feature_names,
        'Importance': model.feature_importances_
    })
    print("\nFeature Importance:")
    print(importances.sort_values('Importance', ascending=False))

def save_model(model, model_path):
    """
    Save the trained model
    """
    joblib.dump(model, model_path)
    print(f"\nModel saved to: {model_path}")

def main():
    # Set paths
    data_path = "1.2w.csv"
    model_path = "phishing_detection_model.joblib"
    
    # Load data
    print("=== Data Loading and Preprocessing ===")
    X, y = load_data(data_path)
    
    # Prepare data
    print("\n=== Dataset Split ===")
    X_train, X_test, y_train, y_test = prepare_data(X, y)
    
    # Train model
    print("\n=== Model Training ===")
    model = train_random_forest(X_train, y_train)
    
    # Evaluate model
    print("\n=== Model Evaluation ===")
    evaluate_model(model, X_test, y_test)
    
    # Save model
    save_model(model, model_path)

if __name__ == "__main__":
    main() 