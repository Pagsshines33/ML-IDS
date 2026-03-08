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


def load_model():
    global MODEL
    model_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "model", "ids_model.pkl")
    if os.path.exists(model_path):
        with open(model_path, "rb") as f:
            MODEL = pickle.load(f)
        print("Model loaded successfully!")
        print(f"   Classes: {MODEL['classes']}")
        print(f"   Accuracy: {MODEL['accuracy']:.4f}")
        print(f"   Feature columns: {len(MODEL['feature_cols'])}")
    else:
        print("No trained model found. Please run: python model/train_model.py")
        MODEL = None


def preprocess_single(values_list):
    """Preprocess a list of values (in feature column order) into model-ready features."""
    if MODEL is None:
        return None

    feature_cols = MODEL["feature_cols"]
    encoders = MODEL["encoders"]
    scaler = MODEL["scaler"]

    features = []
    for i, col in enumerate(feature_cols):
        # Get value by index from the list
        if i < len(values_list):
            val = values_list[i]
        else:
            val = 0

        # Handle NaN
        try:
            if pd.isna(val):
                val = 0
        except (TypeError, ValueError):
            pass

        # Encode categorical or convert to float
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


def predict_from_values(values_list):
    """Make a prediction from a list of feature values."""
    if MODEL is None:
        return {"error": "Model not loaded"}

    features = preprocess_single(values_list)
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


def predict_from_dict(data_dict):
    """Make a prediction from a dictionary of feature names to values."""
    if MODEL is None:
        return {"error": "Model not loaded"}

    feature_cols = MODEL["feature_cols"]
    values_list = []
    for col in feature_cols:
        val = data_dict.get(col, 0)
        values_list.append(val)

    return predict_from_values(values_list)


@app.route("/")
def index():
    accuracy = MODEL["accuracy"] * 100 if MODEL else 0
    return render_template("index.html", accuracy=round(accuracy, 1))


@app.route("/predict", methods=["GET", "POST"])
def predict():
    if request.method == "GET":
        return render_template("predict.html", result=None)

    # Handle manual input
    if "manual_submit" in request.form:
        data = {}
        for col in FEATURE_COLUMNS:
            val = request.form.get(col, "0")
            data[col] = val
        result = predict_from_dict(data)
        return render_template("predict.html", result=result, input_data=data)

    # Handle file upload
    if "file" in request.files:
        file = request.files["file"]
        if file.filename == "":
            return render_template("predict.html", result=None, error="No file selected")

        if not file.filename.endswith(".csv"):
            return render_template("predict.html", result=None, error="Please upload a CSV file")

        try:
            # Read CSV without headers
            df = pd.read_csv(file, header=None)

            print(f"CSV loaded: {df.shape[0]} rows x {df.shape[1]} columns")

            # Determine how many feature columns the model expects
            num_model_features = len(MODEL["feature_cols"]) if MODEL else len(FEATURE_COLUMNS)

            print(f"Model expects: {num_model_features} features")
            print(f"CSV has: {df.shape[1]} columns")

            results = []
            for idx in range(len(df)):
                try:
                    # Get the row as a list of values
                    row_values = df.iloc[idx].tolist()

                    # Only take the first N values (number of features the model needs)
                    feature_values = row_values[:num_model_features]

                    result = predict_from_values(feature_values)
                    results.append(result)
                except Exception as e:
                    print(f"Error on row {idx}: {e}")
                    results.append({
                        "prediction": "Error",
                        "confidence": 0,
                        "probabilities": {},
                        "is_attack": False,
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    })

            print(f"Processed {len(results)} predictions")

            # Calculate summary
            valid_results = [r for r in results if r.get("prediction") != "Error"]
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
            print(f"Error processing CSV: {e}")
            import traceback
            traceback.print_exc()
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

    result = predict_from_dict(data)
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