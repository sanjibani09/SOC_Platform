import os
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

# Synthetic baseline data: tune/retrain with representative organisation data before deployment.
rng = np.random.default_rng(42)
normal = np.column_stack([
    rng.poisson(0.3, 3000),                 # failed_logins
    rng.integers(7, 21, 3000),              # hour
    rng.poisson(3, 3000),                   # files_accessed
    rng.integers(1, 3, 3000),               # distinct_ips
    rng.lognormal(10, 1, 3000),             # bytes_transferred
])
model = IsolationForest(n_estimators=150, contamination=0.03, random_state=42)
model.fit(normal)
joblib.dump(model, os.getenv("MODEL_PATH", "model.joblib"))
print("Isolation Forest trained on synthetic normal-activity baseline")
