import urllib.request
import os

os.makedirs('data', exist_ok=True)

print("Downloading phishing dataset...")
urllib.request.urlretrieve(
    'https://archive.ics.uci.edu/ml/machine-learning-databases/00327/Training%20Dataset.arff',
    'data/phishing_dataset.arff'
)
print("Done!")