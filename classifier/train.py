# classifier/train.py
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import re
import os

def extract_features(url: str):
    return {
        'length': len(url),
        'num_dots': url.count('.'),
        'has_at': int('@' in url),
        'has_https': int(url.lower().startswith('https')),
        'num_hyphens': url.count('-'),
        'num_digits': sum(c.isdigit() for c in url),
    }
import os
print("Current working directory:", os.getcwd())
# Load data
df = pd.read_csv(r'C:\Users\Sohan\Desktop\cybersec_project\classifier\data\phishing_dataset.csv')

# Show columns to double-check
print(df.columns)

# Feature extraction from 'URL' column
X = df['URL'].apply(lambda u: pd.Series(extract_features(u)))
y = df['label']

print(df.head())
# Split & train
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# Evaluate
acc = clf.score(X_test, y_test)
print(f"Test accuracy: {acc:.4f}")

os.makedirs('classifier', exist_ok=True)
joblib.dump(clf, 'classifier/model.joblib')
print("Model saved to classifier/model.joblib")
