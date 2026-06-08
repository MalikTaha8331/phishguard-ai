import pandas as pd
import requests
import os

print("Downloading PhishTank data...")

# PhishTank free dataset
url = "http://data.phishtank.com/data/online-valid.csv"

try:
    df = pd.read_csv(url)
    print(f"Downloaded {len(df)} phishing URLs!")
    print(df.columns.tolist())
    df.to_csv('C:/Users/Malik Taha/phishguard-ai/data/phishtank_data.csv', index=False)
    print("Saved to data/phishtank_data.csv")
except Exception as e:
    print(f"Error: {e}")
    print("Try downloading manually from https://phishtank.org/developer_info.php")