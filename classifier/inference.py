# classifier/inference.py
import joblib
from classifier.train import extract_features
import pandas as pd

model = joblib.load('classifier/model.joblib')

def classify_url(url: str) -> str:
    feat = pd.Series(extract_features(url))
    pred = model.predict([feat])[0]
    return "MALICIOUS" if pred == 1 else "SAFE"

if __name__ == "__main__":
    import sys
    url = sys.argv[1]
    print(f"{url} → {classify_url(url)}")
