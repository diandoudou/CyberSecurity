import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from statsmodels.nonparametric.smoothers_lowess import lowess
import joblib
import seaborn as sns

def load_data(csv_file='1.2w.csv'):
    """Load and process the phishing dataset"""
    print(f"Loading data from {csv_file}...")
    data = pd.read_csv(csv_file)
    
    # Convert the label to numeric
    data['label'] = data['Attribute'].map({'legit': 0, 'phishing': 1})
    
    # Handle missing values
    numeric_cols = ['url_length', 'has_ip', 'dot_count', 'protocol_http', 
                    'protocol_https', 'subdomain_count', 'dns_valid', 
                    'site_accessible', 'has_iframe', 'has_obfuscated_script', 
                    'whois_available']
    
    for col in numeric_cols:
        data[col] = pd.to_numeric(data[col], errors='coerce')
        data[col] = data[col].fillna(0)
    
    data['domain_age'] = data['domain_age'].fillna(-1)
    
    return data

def plot_loess_for_feature(data, feature, alpha=0.3, it=3):
    """
    Plot LOESS smoothed curve for a specific feature against phishing probability
    
    Parameters:
    - data: DataFrame containing the dataset
    - feature: Feature name to analyze
    - alpha: Smoothing parameter (0 < alpha <= 1)
    - it: Number of iterations for robustness
    """
    plt.figure(figsize=(10, 6))
    
    # Create a plot with jittered points to show density
    sns.stripplot(x=feature, y='label', data=data, alpha=0.3, 
                 jitter=True, size=3, hue='Attribute', dodge=True)
    
    # Group data by feature value ranges and calculate proportion of phishing URLs
    # This is for visualization purposes
    x_values = data[feature].dropna().values
    y_values = data['label'].values[~np.isnan(x_values)]
    x_values = x_values[~np.isnan(x_values)]
    
    # Apply LOESS smoothing
    smoothed = lowess(y_values, x_values, frac=alpha, it=it, return_sorted=True)
    
    # Plot the LOESS curve
    plt.plot(smoothed[:, 0], smoothed[:, 1], 'r-', linewidth=2.5, label='LOESS Curve')
    
    # Add a horizontal reference line at y=0.5
    plt.axhline(y=0.5, color='black', linestyle='--', alpha=0.7, label='Decision Boundary')
    
    plt.title(f'LOESS Curve: {feature} vs Phishing Probability', fontsize=14)
    plt.xlabel(feature, fontsize=12)
    plt.ylabel('Phishing Probability', fontsize=12)
    plt.legend()
    plt.tight_layout()
    
    # Save the figure
    plt.savefig(f'loess_{feature}.png', dpi=300)
    plt.close()
    
    print(f"LOESS curve for {feature} saved as loess_{feature}.png")

def plot_multiple_features(data, features=None, alpha=0.3, it=3):
    """Plot LOESS curves for multiple features"""
    if features is None:
        features = ['url_length', 'dot_count', 'subdomain_count', 'domain_age', 'dns_valid']
    
    print(f"Generating LOESS visualizations for {len(features)} features...")
    for feature in features:
        try:
            plot_loess_for_feature(data, feature, alpha, it)
        except Exception as e:
            print(f"Error plotting {feature}: {str(e)}")

def feature_importance_plot(model_path='phishing_detection_model.joblib'):
    """Plot feature importance from the trained model"""
    try:
        # Load the model
        model = joblib.load(model_path)
        
        # Get feature importances
        importances = model.feature_importances_
        
        # Feature names (ensure these match the model's features)
        feature_names = ['URL Length', 'Contains IP', 'Dot Count', 'HTTP Protocol', 
                        'HTTPS Protocol', 'Subdomain Count', 'Domain Age', 
                        'DNS Valid', 'Site Accessible', 'Contains iFrame', 
                        'Has Obfuscated Script', 'WHOIS Available']
        
        # Create DataFrame
        importance_df = pd.DataFrame({
            'Feature': feature_names,
            'Importance': importances
        })
        
        # Sort by importance
        importance_df = importance_df.sort_values('Importance', ascending=False)
        
        # Plot
        plt.figure(figsize=(10, 8))
        sns.barplot(x='Importance', y='Feature', data=importance_df)
        plt.title('Feature Importance for Phishing Detection', fontsize=14)
        plt.xlabel('Importance', fontsize=12)
        plt.ylabel('Feature', fontsize=12)
        plt.tight_layout()
        plt.savefig('feature_importance.png', dpi=300)
        plt.close()
        
        print("Feature importance plot saved as feature_importance.png")
        
        return importance_df
    except Exception as e:
        print(f"Error creating feature importance plot: {str(e)}")
        return None

def create_correlation_heatmap(data):
    """Create a correlation heatmap of features"""
    # Select numeric columns
    numeric_cols = ['url_length', 'has_ip', 'dot_count', 'protocol_http', 
                   'protocol_https', 'subdomain_count', 'domain_age', 
                   'dns_valid', 'site_accessible', 'has_iframe', 
                   'has_obfuscated_script', 'whois_available', 'label']
    
    # Create correlation matrix
    corr_matrix = data[numeric_cols].corr()
    
    # Plot heatmap
    plt.figure(figsize=(12, 10))
    mask = np.triu(np.ones_like(corr_matrix, dtype=bool))
    sns.heatmap(corr_matrix, mask=mask, annot=True, cmap='coolwarm', fmt='.2f',
               linewidths=0.5, vmin=-1, vmax=1)
    plt.title('Feature Correlation Heatmap', fontsize=14)
    plt.tight_layout()
    plt.savefig('correlation_heatmap.png', dpi=300)
    plt.close()
    
    print("Correlation heatmap saved as correlation_heatmap.png")

def main():
    # Set style
    sns.set_style('whitegrid')
    
    # Load data
    data = load_data()
    
    # Generate LOESS visualizations
    important_features = ['url_length', 'dot_count', 'subdomain_count', 'domain_age', 'dns_valid']
    plot_multiple_features(data, important_features)
    
    # Plot feature importance
    feature_importance_plot()
    
    # Create correlation heatmap
    create_correlation_heatmap(data)
    
    print("All visualizations completed!")

if __name__ == "__main__":
    main() 