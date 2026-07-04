import os, sys, random
import numpy as np
import pandas as pd
from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

sys.path.insert(0, os.path.dirname(__file__))
from ml.data_generator import generate_dataset, generate_packet, packets_to_matrix
from ml.models import AnomalyDetector

app = Flask(__name__)
CORS(app)

EXCEL_PATH      = os.path.join(os.path.dirname(__file__), "network_analysis.xlsx")
THRESHOLD       = 0.42
_packet_counter = [300]

# ── Train on startup ──────────────────────────────────────────
print("=" * 50)
print("Training models...")
detector = AnomalyDetector()
detector.train(n_normal=2000)

# ── Generate and score 300 packets ───────────────────────────
print("Generating and scoring 300 packets...")
packets = generate_dataset(300)
scored  = detector.score_packets(packets)

# ── Build DataFrame ───────────────────────────────────────────
rows = []
for i, p in enumerate(scored):
    avg = (p["iforest_score"] + p["ae_score"]) / 2
    rows.append({
        "ID"             : i + 1,
        "Protocol"       : p["protocol"],
        "Port"           : p["port"],
        "Packet Size (B)": round(p["packetSize"], 1),
        "Bytes In (KB)"  : round(p["bytesIn"] / 1000, 2),
        "Bytes Out (KB)" : round(p["bytesOut"] / 1000, 2),
        "Duration (s)"   : round(p["duration"], 4),
        "Packets In"     : p["packetsIn"],
        "Packets Out"    : p["packetsOut"],
        "Flag Count"     : p["flagCount"],
        "TTL"            : p["ttl"],
        "IF Score"       : p["iforest_score"],
        "PCA Score"      : p["ae_score"],
        "Avg Score"      : round(avg, 4),
        "True Label"     : p["label"],
        "Detected As"    : "Anomaly" if avg > THRESHOLD else "Normal",
    })

df_all     = pd.DataFrame(rows)
df_normal  = df_all[df_all["Detected As"] == "Normal"].reset_index(drop=True)
df_anomaly = df_all[df_all["Detected As"] == "Anomaly"].reset_index(drop=True)

print(f"  Total: {len(df_all)}  Normal: {len(df_normal)}  Anomaly: {len(df_anomaly)}")

# ── Save Excel ────────────────────────────────────────────────
with pd.ExcelWriter(EXCEL_PATH, engine="openpyxl") as writer:
    df_all.to_excel(    writer, sheet_name="All Packets",     index=False)
    df_normal.to_excel( writer, sheet_name="Normal Packets",  index=False)
    df_anomaly.to_excel(writer, sheet_name="Anomaly Packets", index=False)
print(f"Excel saved → {EXCEL_PATH}")

# ── Compute centroids ─────────────────────────────────────────
normal_centroid  = np.array([df_normal["IF Score"].mean(),  df_normal["PCA Score"].mean()])
anomaly_centroid = np.array([df_anomaly["IF Score"].mean(), df_anomaly["PCA Score"].mean()])
print(f"Normal  centroid: IF={normal_centroid[0]:.4f}  PCA={normal_centroid[1]:.4f}")
print(f"Anomaly centroid: IF={anomaly_centroid[0]:.4f}  PCA={anomaly_centroid[1]:.4f}")
print("\nFlask ready!")


# ── Endpoints ─────────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"status": "ok"})

@app.route("/api/data")
def get_data():
    return jsonify([{**p, "id": i} for i, p in enumerate(scored)])

@app.route("/api/packet")
def get_packet():
    _packet_counter[0] += 1
    pkt    = generate_packet()
    result = detector.score_packets([pkt])[0]
    result["id"] = _packet_counter[0]
    return jsonify(result)

@app.route("/api/classify", methods=["POST"])
def classify():
    data   = request.json
    packet = {
        "packetSize"  : float(data.get("packetSize",  500)),
        "bytesIn"     : float(data.get("bytesIn",    1500)),
        "bytesOut"    : float(data.get("bytesOut",    800)),
        "duration"    : float(data.get("duration",    0.5)),
        "packetsIn"   : int(  data.get("packetsIn",    10)),
        "packetsOut"  : int(  data.get("packetsOut",    8)),
        "flagCount"   : int(  data.get("flagCount",     1)),
        "ttl"         : int(  data.get("ttl",          64)),
        "protocol"    : "TCP",
        "port"        : 80,
        "isAnomaly"   : False,
        "label"       : "Unknown",
    }
    p     = detector.score_packets([packet])[0]
    point = np.array([p["iforest_score"], p["ae_score"]])

    dist_normal  = float(np.linalg.norm(point - normal_centroid))
    dist_anomaly = float(np.linalg.norm(point - anomaly_centroid))

    classification = "SAFE"      if dist_normal < dist_anomaly else "SUSPICIOUS"
    color          = "#00f5d4"   if dist_normal < dist_anomaly else "#ff4d6d"
    total          = dist_normal + dist_anomaly + 1e-9
    confidence     = round(abs(dist_anomaly - dist_normal) / total * 100, 1)

    return jsonify({
        "iforest_score"  : p["iforest_score"],
        "ae_score"       : p["ae_score"],
        "avg_score"      : round((p["iforest_score"] + p["ae_score"]) / 2, 4),
        "dist_normal"    : round(dist_normal,  4),
        "dist_anomaly"   : round(dist_anomaly, 4),
        "classification" : classification,
        "color"          : color,
        "confidence"     : confidence,
    })

@app.route("/api/roc")
def get_roc():
    from sklearn.metrics import roc_curve, auc
    y_true = [1 if p["isAnomaly"] else 0 for p in scored]
    y_if   = [p["iforest_score"]         for p in scored]
    y_pca  = [p["ae_score"]              for p in scored]

    fpr_if,  tpr_if,  _ = roc_curve(y_true, y_if)
    fpr_pca, tpr_pca, _ = roc_curve(y_true, y_pca)

    return jsonify({
        "iforest": {
            "fpr": [round(v,4) for v in fpr_if.tolist()],
            "tpr": [round(v,4) for v in tpr_if.tolist()],
            "auc": round(float(auc(fpr_if, tpr_if)), 4),
        },
        "autoencoder": {
            "fpr": [round(v,4) for v in fpr_pca.tolist()],
            "tpr": [round(v,4) for v in tpr_pca.tolist()],
            "auc": round(float(auc(fpr_pca, tpr_pca)), 4),
        }
    })

@app.route("/api/download")
def download():
    return send_file(EXCEL_PATH, as_attachment=True,
                     download_name="network_analysis.xlsx")

if __name__ == "__main__":
    app.run(debug=False, port=5000)
