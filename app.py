import os
import pickle
import numpy as np
import pandas as pd
from flask import Flask, render_template, request, jsonify, redirect, url_for
from datetime import datetime
import json

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

MODEL = None
DETECTION_HISTORY = []

FEATURE_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate"
]

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
NUMERICAL_COLS = [c for c in FEATURE_COLUMNS if c not in CATEGORICAL_COLS]


def load_model():
    global MODEL
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "ids_model.pkl")
    if os.path.exists(model_path):
        with open(model_path, "rb") as f:
            MODEL = pickle.load(f)
        print("Model loaded successfully!")
        print(f"   Classes: {MODEL['classes']}")
        print(f"   Accuracy: {MODEL['accuracy']:.4f}")
    else:
        print("No trained model found. Please run: python model/train_model.py")
        MODEL = None


def preprocess_input(data_dict):
    if MODEL is None:
        return None

    feature_cols = MODEL["feature_cols"]
    encoders = MODEL["encoders"]
    scaler = MODEL["scaler"]

    # Make sure data_dict is actually a dictionary
    if not isinstance(data_dict, dict):
        return None

    features = []
    for col in feature_cols:
        val = data_dict.get(col, 0)

        # Handle NaN values
        if pd.isna(val) if not isinstance(val, str) else False:
            val = 0

        if col in CATEGORICAL_COLS and col in encoders:
            try:
                val = encoders[col].transform([str(val).strip()])[0]
            except (ValueError, KeyError):
                val = 0
        else:
            try:
                val = float(val)
            except (ValueError, TypeError):
                val = 0.0
        features.append(val)

    features = np.array(features).reshape(1, -1)
    features = scaler.transform(features)
    return features


def predict_single(data_dict):
    if MODEL is None:
        return {"error": "Model not loaded"}

    # Make sure it's a dictionary
    if not isinstance(data_dict, dict):
        return {"error": "Invalid input format"}

    features = preprocess_input(data_dict)
    if features is None:
        return {"error": "Preprocessing failed"}

    prediction = MODEL["model"].predict(features)[0]
    probabilities = MODEL["model"].predict_proba(features)[0]

    label = MODEL["label_encoder"].inverse_transform([prediction])[0]
    confidence = float(np.max(probabilities)) * 100

    prob_dict = {}
    for cls, prob in zip(MODEL["classes"], probabilities):
        prob_dict[cls] = round(float(prob) * 100, 2)

    result = {
        "prediction": label,
        "confidence": round(confidence, 2),
        "probabilities": prob_dict,
        "is_attack": label != "Normal",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    DETECTION_HISTORY.append(result)
    return result


def predict_batch(df):
    """Make predictions for a batch of connections (DataFrame)."""
    if MODEL is None:
        return [{"error": "Model not loaded"}]

    results = []
    for idx, row in df.iterrows():
        try:
            # Convert row to dictionary properly
            data_dict = {}
            feature_cols = MODEL["feature_cols"]

            for i, col in enumerate(feature_cols):
                if col in df.columns:
                    data_dict[col] = row[col]
                elif i < len(row):
                    data_dict[col] = row.iloc[i]
                else:
                    data_dict[col] = 0

            result = predict_single(data_dict)
            results.append(result)
        except Exception as e:
            results.append({
                "prediction": "Error",
                "confidence": 0,
                "probabilities": {},
                "is_attack": False,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "error": str(e)
            })

    return results


@app.route("/")
def index():
    accuracy = MODEL["accuracy"] * 100 if MODEL else 0
    return render_template("index.html", accuracy=round(accuracy, 1))


@app.route("/predict", methods=["GET", "POST"])
def predict():
    if request.method == "GET":
        return render_template("predict.html", result=None)

    if "manual_submit" in request.form:
        data = {}
        for col in FEATURE_COLUMNS:
            val = request.form.get(col, "0")
            data[col] = val
        result = predict_single(data)
        return render_template("predict.html", result=result, input_data=data)

    if "file" in request.files:
        file = request.files["file"]
        if file.filename == "":
            return render_template("predict.html", result=None, error="No file selected")

        if not file.filename.endswith(".csv"):
            return render_template("predict.html", result=None, error="Please upload a CSV file")

        try:
            df = pd.read_csv(file, header=None)

            # Assign column names based on number of columns
            feature_cols = MODEL["feature_cols"] if MODEL else FEATURE_COLUMNS
            num_features = len(feature_cols)

            if len(df.columns) == num_features:
                df.columns = feature_cols
            elif len(df.columns) == num_features + 1:
                df.columns = feature_cols + ["label"]
            elif len(df.columns) == num_features + 2:
                df.columns = feature_cols + ["label", "difficulty"]
            elif len(df.columns) == 41:
                df.columns = FEATURE_COLUMNS
            elif len(df.columns) == 42:
                df.columns = FEATURE_COLUMNS + ["label"]
            elif len(df.columns) == 43:
                df.columns = FEATURE_COLUMNS + ["label", "difficulty"]
            else:
                # Try to use first N columns as features
                if len(df.columns) >= len(FEATURE_COLUMNS):
                    col_names = FEATURE_COLUMNS + [f"extra_{i}" for i in range(len(df.columns) - len(FEATURE_COLUMNS))]
                    df.columns = col_names[:len(df.columns)]
                else:
                    return render_template("predict.html", result=None,
                                           error=f"CSV has {len(df.columns)} columns, expected at least {len(FEATURE_COLUMNS)}")

            results = predict_batch(df)

            # Filter out error results for summary
            valid_results = [r for r in results if "error" not in r or r.get("prediction") != "Error"]

            summary = {
                "total": len(results),
                "normal": sum(1 for r in valid_results if not r.get("is_attack", True)),
                "attacks": sum(1 for r in valid_results if r.get("is_attack", False)),
                "attack_types": {},
            }
            for r in valid_results:
                pred = r.get("prediction", "Unknown")
                summary["attack_types"][pred] = summary["attack_types"].get(pred, 0) + 1

            return render_template("predict.html", batch_results=results, summary=summary)
        except Exception as e:
            return render_template("predict.html", result=None, error=f"Error processing file: {str(e)}")

    return render_template("predict.html", result=None)


@app.route("/dashboard")
def dashboard():
    stats = get_stats_data()
    return render_template("dashboard.html", stats=stats)


@app.route("/about")
def about():
    model_info = {}
    if MODEL:
        model_info = {
            "accuracy": round(MODEL["accuracy"] * 100, 2),
            "classes": MODEL["classes"],
            "report": MODEL.get("classification_report", {}),
            "feature_importances": MODEL.get("feature_importances", {}),
            "confusion_matrix": MODEL.get("confusion_matrix", []),
        }
    return render_template("about.html", model_info=model_info)


@app.route("/api/predict", methods=["POST"])
def api_predict():
    if MODEL is None:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    result = predict_single(data)
    return jsonify(result)


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats_data())


def get_stats_data():
    total = len(DETECTION_HISTORY)
    if total == 0:
        return {
            "total": 0, "normal": 0, "attacks": 0,
            "detection_rate": 0, "attack_types": {},
            "recent": [],
        }

    normal = sum(1 for r in DETECTION_HISTORY if not r.get("is_attack", True))
    attacks = total - normal
    attack_types = {}
    for r in DETECTION_HISTORY:
        pred = r.get("prediction", "Unknown")
        attack_types[pred] = attack_types.get(pred, 0) + 1

    return {
        "total": total,
        "normal": normal,
        "attacks": attacks,
        "detection_rate": round((attacks / total) * 100, 2) if total > 0 else 0,
        "attack_types": attack_types,
        "recent": DETECTION_HISTORY[-20:][::-1],
    }


if __name__ == "__main__":
    load_model()
    app.run(debug=True, host="0.0.0.0", port=5000)