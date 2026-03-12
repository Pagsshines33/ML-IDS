# ML-IDS — Setup Instructions

Complete guide to run ML-IDS locally or deploy it to Vercel.

---

## Prerequisites

Make sure you have the following installed:

| Tool | Version | Check |
|------|---------|-------|
| Python | 3.8+ | `python --version` |
| pip | Latest | `pip --version` |
| Git | Any | `git --version` |

---

## 1. Clone the Repository

```bash
git clone https://github.com/your-username/ML-IDS.git
cd ML-IDS
```

---

## 2. Create a Virtual Environment (Recommended)

```bash
# Create
python -m venv venv

# Activate — macOS / Linux
source venv/bin/activate

# Activate — Windows
venv\Scripts\activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- Flask
- scikit-learn
- pandas
- numpy
- requests
- gunicorn

---

## 4. Train the Model

The trained model file `ids_model.pkl` is **not included** in the repository due to file size. You must generate it by running the training script.

```bash
python src/model/train_model.py
```

This will:
1. **Download** the NSL-KDD dataset automatically from GitHub
2. **Preprocess** features (label encoding + scaling)
3. **Train** a Random Forest Classifier (100 estimators)
4. **Evaluate** and print accuracy + classification report
5. **Save** `ids_model.pkl` inside the `src/model/` directory

> ⚠️ If the download fails (no internet), the script will fall back to synthetic data for pipeline testing only. For real predictions, internet access is required during training.

Expected output:
```
Model Accuracy: 0.9724 (97.24%)
Model saved to: src/model/ids_model.pkl
Training complete!
```

---

## 5. Run the Application

```bash
python src/app.py
```

The app will start at:
```
http://localhost:5000
```

Open your browser and navigate to that URL.

---

## 6. Verify the Model Loaded

Visit the health check endpoint to confirm everything is working:

```
http://localhost:5000/api/health
```

Expected response:
```json
{
  "status": "ok",
  "model_loaded": true,
  "model_accuracy": 97.24,
  "model_classes": ["DoS", "Normal", "Probe", "R2L", "U2R"],
  "feature_count": 41
}
```

If `model_loaded` is `false`, re-run Step 4.

---

## 7. Test with Sample Data

A sample CSV file is included at `docs/nsl_kdd_sample_test.csv`.

1. Go to [http://localhost:5000/predict](http://localhost:5000/predict)
2. Upload `nsl_kdd_sample_test.csv`
3. Click **Analyze Traffic**
4. Review predictions in the results table

---

## Project Structure After Setup

```
ML-IDS/
├── src/
│   ├── app.py
│   ├── model/
│   │   ├── train_model.py
│   │   └── ids_model.pkl       ← generated in Step 4
│   ├── templates/
│   └── static/
├── requirements.txt
└── ...
```

---

## Deploying to Vercel

### Step 1 — Install Vercel CLI
```bash
npm install -g vercel
```

### Step 2 — Add `vercel.json` to project root
```json
{
  "version": 2,
  "builds": [
    { "src": "src/app.py", "use": "@vercel/python" }
  ],
  "routes": [
    { "src": "/(.*)", "dest": "src/app.py" }
  ]
}
```

### Step 3 — Commit and push `ids_model.pkl`
The trained model must be pushed to the repository for Vercel to access it:
```bash
git add src/model/ids_model.pkl
git commit -m "Add trained model"
git push
```

> ⚠️ If `ids_model.pkl` exceeds GitHub's 100MB limit, use [Git LFS](https://git-lfs.github.com/).

### Step 4 — Deploy
```bash
vercel --prod
```

Or connect the GitHub repository to [vercel.com](https://vercel.com) and enable auto-deploy on push.

---

## Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| `Model not loaded` error | `ids_model.pkl` missing | Run `python src/model/train_model.py` |
| `ModuleNotFoundError` | Dependencies not installed | Run `pip install -r requirements.txt` |
| Download fails during training | No internet access | Connect to internet and retry |
| Port 5000 already in use | Another app using port | Run `python src/app.py --port 5001` or kill the process |
| CSV predictions all wrong | CSV has header row | Remove header row or check column order |
| Vercel cold start — model missing | `.pkl` not in repo | Commit and push `ids_model.pkl` |

---

## API Usage (Programmatic)

```python
import requests

response = requests.post("http://localhost:5000/api/predict", json={
    "duration": 0,
    "protocol_type": "tcp",
    "service": "http",
    "flag": "SF",
    "src_bytes": 181,
    "dst_bytes": 5450,
    "land": 0,
    "wrong_fragment": 0,
    "urgent": 0,
    "hot": 0,
    "num_failed_logins": 0,
    "logged_in": 1,
    "num_compromised": 0,
    "root_shell": 0,
    "su_attempted": 0,
    "num_root": 0,
    "num_file_creations": 0,
    "num_shells": 0,
    "num_access_files": 0,
    "num_outbound_cmds": 0,
    "is_host_login": 0,
    "is_guest_login": 0,
    "count": 8,
    "srv_count": 8,
    "serror_rate": 0.0,
    "srv_serror_rate": 0.0,
    "rerror_rate": 0.0,
    "srv_rerror_rate": 0.0,
    "same_srv_rate": 1.0,
    "diff_srv_rate": 0.0,
    "srv_diff_host_rate": 0.0,
    "dst_host_count": 9,
    "dst_host_srv_count": 9,
    "dst_host_same_srv_rate": 1.0,
    "dst_host_diff_srv_rate": 0.0,
    "dst_host_same_src_port_rate": 0.11,
    "dst_host_srv_diff_host_rate": 0.0,
    "dst_host_serror_rate": 0.0,
    "dst_host_srv_serror_rate": 0.0,
    "dst_host_rerror_rate": 0.0,
    "dst_host_srv_rerror_rate": 0.0
})

print(response.json())
```

---

*ML-IDS — ASAC Capstone Project 2026*
