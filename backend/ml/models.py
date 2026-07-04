import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

from ml.data_generator import FEATURES, packets_to_matrix


class IForestModel:

    def __init__(self):
        self.scaler = StandardScaler()
        self.model  = IsolationForest(
            n_estimators  = 100,
            contamination = 0.08,
            random_state  = 42
        )

    def train(self, X_normal):
        X = self.scaler.fit_transform(X_normal)
        self.model.fit(X)
        print(f"[IForest] Trained on {len(X_normal)} normal packets")

    def score(self, X):
        X_scaled = self.scaler.transform(X)
        raw      = self.model.decision_function(X_scaled)
        scores   = 1.0 / (1.0 + np.exp(raw * 10))
        return np.clip(scores, 0.0, 1.0)


class AutoencoderModel:

    def __init__(self, input_dim=8):
        self.input_dim = input_dim
        self.scaler    = StandardScaler()
        self.model     = self._build(input_dim)
        self.max_error = 1.0

    def _build(self, dim):
        inputs  = keras.Input(shape=(dim,))
        x       = layers.Dense(6, activation="relu")(inputs)
        encoded = layers.Dense(3, activation="relu")(x)
        x       = layers.Dense(6, activation="relu")(encoded)
        decoded = layers.Dense(dim, activation="linear")(x)
        model   = keras.Model(inputs, decoded, name="autoencoder")
        model.compile(optimizer="adam", loss="mse")
        return model

    def train(self, X_normal, epochs=60, batch_size=32):
        X = self.scaler.fit_transform(X_normal)
        self.model.fit(X, X,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.1,
            verbose=0,
            shuffle=True
        )
        preds          = self.model.predict(X, verbose=0)
        errors         = np.mean((X - preds) ** 2, axis=1)
        self.max_error = float(errors.max()) * 2
        print(f"[Autoencoder] Trained. Max error: {self.max_error:.4f}")

    def score(self, X):
        X_scaled = self.scaler.transform(X)
        preds    = self.model.predict(X_scaled, verbose=0)
        errors   = np.mean((X_scaled - preds) ** 2, axis=1)
        return np.clip(errors / self.max_error, 0.0, 1.0)


class AnomalyDetector:

    def __init__(self):
        self.iforest     = IForestModel()
        self.autoencoder = AutoencoderModel(input_dim=len(FEATURES))

    def train(self, n_normal=2000):
        from ml.data_generator import generate_packet
        print(f"Generating {n_normal} normal training packets...")
        normal_packets = [generate_packet(force_anomaly=False) for _ in range(n_normal)]
        X_normal = np.array(packets_to_matrix(normal_packets), dtype=float)
        self.iforest.train(X_normal)
        self.autoencoder.train(X_normal, epochs=60)
        print("Both models ready.\n")

    def score_packets(self, packets):
        if not packets:
            return []
        X          = np.array(packets_to_matrix(packets), dtype=float)
        if_scores  = self.iforest.score(X)
        ae_scores  = self.autoencoder.score(X)
        result = []
        for i, pkt in enumerate(packets):
            p = dict(pkt)
            p["id"]            = i
            p["iforest_score"] = round(float(if_scores[i]), 4)
            p["ae_score"]      = round(float(ae_scores[i]), 4)
            result.append(p)
        return result
