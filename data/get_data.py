from ucimlrepo import fetch_ucirepo
import pandas as pd
import os

os.makedirs('data', exist_ok=True)

print("Fetching dataset...")
dataset = fetch_ucirepo(id=327)

X = dataset.data.features
y = dataset.data.targets

df = pd.concat([X, y], axis=1)
df.to_csv('data/phishing_data.csv', index=False)

print(f"Dataset saved! Shape: {df.shape}")
print(df.head())