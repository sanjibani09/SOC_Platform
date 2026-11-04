import os
import joblib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel, Field

app = FastAPI(title="SOC Anomaly Scoring Service", version="1.0.0")
model = joblib.load(os.getenv("MODEL_PATH", "model.joblib"))
FEATURES = ["failed_logins", "hour", "files_accessed", "distinct_ips", "bytes_transferred"]
class ScoreRequest(BaseModel):
    features: dict[str, float] = Field(default_factory=dict)
@app.get("/health")
def health(): return {"status": "ok", "model": "IsolationForest"}
@app.post("/score")
def score(request: ScoreRequest):
    row = np.array([[float(request.features.get(k, 0)) for k in FEATURES]])
    # decision_function is higher for inliers; sigmoid maps the inverted value to [0,1].
    raw = float(-model.decision_function(row)[0])
    anomaly = float(1.0 / (1.0 + np.exp(-8.0 * raw)))
    return {"anomaly_score": round(anomaly, 4), "model": "IsolationForest", "features": FEATURES}
