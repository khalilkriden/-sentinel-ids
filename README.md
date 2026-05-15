# SENTINEL IDS — Flask App
## Step-by-Step: Model Integration & Deployment

---

## STEP 1 — Save your model from the notebook

Run this cell at the end of your notebook (Section 11):

```python
import joblib, os

os.makedirs('models', exist_ok=True)
os.makedirs('data/processed', exist_ok=True)

# Save best model (XGBoost optimized)
joblib.dump(best_res['model'], 'models/best_model.pkl')

# Save full preprocessing pipeline
joblib.dump({
    'scaler':             scaler,
    'label_encoders':     label_encoders,
    'le_target':          le_target,
    'feature_cols_final': feature_cols_final,
    'cap_limits':         cap_limits,
}, 'data/processed/preprocessing_pipeline.pkl')

print("Saved!")
```

---

## STEP 2 — Copy model files into this project

```
sentinel-flask/
├── models/
│   └── best_model.pkl                   ← copy here
└── data/
    └── processed/
        └── preprocessing_pipeline.pkl   ← copy here
```

```bash
cp /path/to/notebook/models/best_model.pkl              sentinel-flask/models/
cp /path/to/notebook/data/processed/preprocessing_pipeline.pkl  sentinel-flask/data/processed/
```

---

## STEP 3 — Install dependencies

```bash
cd sentinel-flask
pip install -r requirements.txt
```

---

## STEP 4 — Run locally

```bash
python app.py
```

Open: **http://localhost:5000**

The app starts in **DEMO mode** if model files are missing, and switches
to **LIVE mode** automatically when it finds them.

---

## STEP 5 — Test the API

```bash
# Health check
curl http://localhost:5000/api/health

# Single prediction
curl -X POST http://localhost:5000/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "proto":   "tcp",
    "service": "http",
    "state":   "FIN",
    "sbytes":  5000,
    "dbytes":  3000,
    "spkts":   10,
    "dpkts":   8,
    "rate":    100.0,
    "dur":     0.1,
    "sttl":    64,
    "dttl":    64,
    "sload":   1000.0,
    "dload":   800.0,
    "sloss":   0,
    "dloss":   0,
    "sjit":    0.01,
    "djit":    0.01
  }'
```

Expected response:
```json
{
  "prediction":    "Normal",
  "severity":      "none",
  "color":         "#10b981",
  "risk_score":    0,
  "confidence":    92.3,
  "probabilities": {"Normal": 92.3, "Generic": 4.1, "Exploits": 1.5},
  "inference_ms":  12.4,
  "scan_id":       1,
  "mode":          "live"
}
```

---

## DEPLOY — Option A: Render.com (Free, recommended)

1. Push to GitHub:
```bash
git init
git add .
git commit -m "initial"
git remote add origin https://github.com/yourname/sentinel-ids.git
git push -u origin main
```

2. Go to **render.com** → New → Web Service → Connect your repo

3. Settings:
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `gunicorn app:app --bind 0.0.0.0:$PORT --workers 2`

4. Add model files: in Render dashboard → Environment → upload files
   OR use Git LFS for large .pkl files:
```bash
git lfs install
git lfs track "*.pkl"
git add .gitattributes models/ data/
git commit -m "add model files"
git push
```

---

## DEPLOY — Option B: Docker (any server)

```bash
# Build
docker build -t sentinel-ids .

# Run
docker run -p 5000:5000 \
  -v $(pwd)/models:/app/models \
  -v $(pwd)/data:/app/data \
  sentinel-ids
```

---

## DEPLOY — Option C: Railway.app (Free tier)

```bash
npm install -g @railway/cli
railway login
railway init
railway up
```

Railway auto-detects the Procfile and deploys automatically.

---

## Project Structure

```
sentinel-flask/
├── app.py                    ← Flask app + ML inference + API routes
├── requirements.txt
├── Procfile                  ← for Render / Railway
├── Dockerfile                ← for Docker / any cloud
├── models/
│   └── best_model.pkl        ← your trained model
├── data/
│   └── processed/
│       └── preprocessing_pipeline.pkl
├── templates/
│   ├── index.html            ← Dashboard UI
│   └── history.html          ← Scan history UI
├── logs/
│   └── sentinel.log          ← auto-generated
└── instance/
    └── sentinel.db           ← SQLite database (auto-generated)
```

---

## API Reference

| Method | Route              | Description                     |
|--------|--------------------|---------------------------------|
| GET    | `/`                | Dashboard UI                    |
| GET    | `/history`         | Scan history page               |
| POST   | `/api/predict`     | Run inference on connection     |
| GET    | `/api/stats`       | Dashboard statistics            |
| GET    | `/api/history`     | JSON history (limit param)      |
| GET    | `/api/health`      | Model status + mode             |
| POST   | `/api/clear`       | Clear all scan history          |
