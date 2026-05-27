from __future__ import annotations

import pickle
import sys
from pathlib import Path
from typing import Any

try:
    import joblib
except Exception:
    joblib = None

try:
    import numpy as np
except Exception:
    np = None

try:
    import pandas as pd
except Exception:
    pd = None

from app.config import BASE_DIR


MODEL_DIR = BASE_DIR / "models" / "cicids"

MODEL_FILE = MODEL_DIR / "tier1_lgbm_temp_scaled.pkl"
FEATURE_COLS_FILE = MODEL_DIR / "feature_cols.pkl"
SELECTED_FEATURES_FILE = MODEL_DIR / "selected_features.pkl"
SCALER_FILE = MODEL_DIR / "scaler.pkl"
FEATURE_SELECTOR_FILE = MODEL_DIR / "feature_selector.pkl"
LABEL_ENCODER_FILE = MODEL_DIR / "label_encoder.pkl"
THRESHOLDS_FILE = MODEL_DIR / "pipeline_thresholds.pkl"
ISOLATION_FOREST_FILE = MODEL_DIR / "stage1_isolation_forest.pkl"


_REQUIRED_FILES = [
    MODEL_FILE,
    FEATURE_COLS_FILE,
    SELECTED_FEATURES_FILE,
    SCALER_FILE,
    FEATURE_SELECTOR_FILE,
    LABEL_ENCODER_FILE,
]


class TemperatureScaledClassifier:
    """
    Compatibility wrapper needed to load the Hugging Face CICIDS model.

    The pickle was saved with a custom class named TemperatureScaledClassifier.
    Without this class, joblib/pickle cannot load tier1_lgbm_temp_scaled.pkl.

    This class is intentionally flexible because different exported versions may
    store the wrapped estimator under different attribute names.
    """

    def __init__(self, base_model=None, temperature: float = 1.0, **kwargs):
        self.base_model = base_model
        self.model = base_model
        self.estimator = base_model
        self.classifier = base_model
        self.temperature = temperature

        for key, value in kwargs.items():
            setattr(self, key, value)

    def _get_base_model(self):
        for name in [
            "base_model",
            "model",
            "estimator",
            "classifier",
            "clf",
            "lgbm",
            "wrapped_model",
        ]:
            value = getattr(self, name, None)
            if value is not None and value is not self:
                return value
        return None

    def predict_proba(self, X):
        base = self._get_base_model()

        if base is None:
            raise RuntimeError("TemperatureScaledClassifier has no wrapped base model")

        if hasattr(base, "predict_proba"):
            probs = base.predict_proba(X)
        else:
            raw = base.predict(X)

            if np is None:
                return raw

            raw = np.asarray(raw)

            if raw.ndim == 1:
                return raw

            exp = np.exp(raw - np.max(raw, axis=1, keepdims=True))
            probs = exp / np.sum(exp, axis=1, keepdims=True)

        if np is None:
            return probs

        probs = np.asarray(probs, dtype=float)

        temperature = float(getattr(self, "temperature", 1.0) or 1.0)

        if temperature <= 0:
            return probs

        # Apply temperature scaling safely on probabilities.
        eps = 1e-12
        logits = np.log(np.clip(probs, eps, 1.0))
        logits = logits / temperature
        exp = np.exp(logits - np.max(logits, axis=1, keepdims=True))
        scaled = exp / np.sum(exp, axis=1, keepdims=True)

        return scaled

    def predict(self, X):
        base = self._get_base_model()

        if base is not None and hasattr(base, "predict"):
            try:
                return base.predict(X)
            except Exception:
                pass

        probs = self.predict_proba(X)

        if np is None:
            return probs

        return np.argmax(probs, axis=1)


# Critical fix:
# The Hugging Face pickle expects TemperatureScaledClassifier to exist in __main__.
setattr(sys.modules.get("__main__"), "TemperatureScaledClassifier", TemperatureScaledClassifier)


_model_cache: dict[str, Any] = {}
_last_error = ""


def _load_pickle(path: Path) -> Any:
    """
    Load Hugging Face CICIDS pipeline files with joblib.

    Do not silently fall back to raw pickle because these files are joblib/pickle
    objects and fallback can create misleading errors such as:
    invalid load key, '\x04'.
    """
    if joblib is None:
        raise RuntimeError("joblib is not installed. Run: python -m pip install joblib")

    try:
        return joblib.load(path)
    except Exception as exc:
        raise RuntimeError(f"Could not load {path.name} with joblib: {exc}") from exc


def cicids_ai_status() -> dict[str, Any]:
    missing = [str(p) for p in _REQUIRED_FILES if not p.exists()]

    return {
        "available": len(missing) == 0,
        "model_dir": str(MODEL_DIR),
        "model_file": str(MODEL_FILE),
        "missing_files": missing,
        "has_model": MODEL_FILE.exists(),
        "has_feature_cols": FEATURE_COLS_FILE.exists(),
        "has_selected_features": SELECTED_FEATURES_FILE.exists(),
        "has_scaler": SCALER_FILE.exists(),
        "has_feature_selector": FEATURE_SELECTOR_FILE.exists(),
        "has_label_encoder": LABEL_ENCODER_FILE.exists(),
        "last_error": _last_error,
        "note": (
            "This model requires CICIDS-style flow features. "
            "Live connection metadata such as PID, process name, local address, "
            "remote address, and port are not enough for prediction."
        ),
    }


def _load_pipeline() -> dict[str, Any] | None:
    global _model_cache, _last_error

    if _model_cache:
        return _model_cache

    status = cicids_ai_status()

    if not status["available"]:
        _last_error = "Missing CICIDS model files"
        return None

    try:
        _model_cache = {
            "model": _load_pickle(MODEL_FILE),
            "feature_cols": _load_pickle(FEATURE_COLS_FILE),
            "selected_features": _load_pickle(SELECTED_FEATURES_FILE),
            "scaler": _load_pickle(SCALER_FILE),
            "feature_selector": _load_pickle(FEATURE_SELECTOR_FILE),
            "label_encoder": _load_pickle(LABEL_ENCODER_FILE),
        }

        if THRESHOLDS_FILE.exists():
            _model_cache["thresholds"] = _load_pickle(THRESHOLDS_FILE)

        if ISOLATION_FOREST_FILE.exists():
            _model_cache["isolation_forest"] = _load_pickle(ISOLATION_FOREST_FILE)

        _last_error = ""
        return _model_cache

    except Exception as exc:
        _last_error = str(exc)
        _model_cache = {}
        return None


def _get_flow_rows(audit_result: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Return CICIDS-style flow rows if a future flow extractor adds them.

    Current Network Audit only has:
    PID, process name, local address, remote address, port, status.

    CICIDS needs:
    packet counts, byte counts, duration, packet length statistics,
    flow rates, TCP flag counts, etc.
    """
    for key in ["flow_features", "flows", "cicids_flows"]:
        rows = audit_result.get(key)
        if isinstance(rows, list) and rows:
            return rows

    return []


def _canonical_name(name: str) -> str:
    return "".join(ch.lower() for ch in str(name) if ch.isalnum())


def _prepare_dataframe(rows: list[dict[str, Any]], feature_cols: list[str]):
    if pd is None:
        raise RuntimeError("pandas is not installed. Run: python -m pip install pandas")

    clean_rows = []

    for row in rows:
        canonical_index = {
            _canonical_name(key): value
            for key, value in row.items()
        }

        clean_row = {}

        for col in feature_cols:
            value = row.get(col, None)

            if value is None:
                value = canonical_index.get(_canonical_name(col), 0)

            try:
                value = float(value)
            except Exception:
                value = 0.0

            if np is not None:
                try:
                    if not np.isfinite(value):
                        value = 0.0
                except Exception:
                    pass

            clean_row[col] = value

        clean_rows.append(clean_row)

    return pd.DataFrame(clean_rows, columns=feature_cols)



def run_optional_cicids_ai(audit_result: dict[str, Any]) -> dict[str, Any]:
    """
    Optional CICIDS2017 AI.

    It loads the Hugging Face model if available, but refuses to run unless
    CICIDS-style flow features are present.
    """

    status = cicids_ai_status()

    if not status["available"]:
        return {
            "ran": False,
            "status": "not_configured",
            "summary": (
                "Network AI model files are incomplete. Add all Hugging Face "
                "pipeline files inside models/cicids."
            ),
            "details": status,
            "predictions": [],
        }

    pipeline = _load_pipeline()

    if pipeline is None:
        return {
            "ran": False,
            "status": "load_error",
            "summary": f"CICIDS model files were found, but loading failed: {_last_error}",
            "details": cicids_ai_status(),
            "predictions": [],
        }

    flow_rows = _get_flow_rows(audit_result)

    if not flow_rows:
        return {
            "ran": False,
            "status": "flow_features_required",
            "summary": (
                "CICIDS2017 AI is installed and the model files load correctly, "
                "but it was not run because the current Network Audit tab only has "
                "live connection metadata: PID, process name, local address, remote "
                "address, remote port, and status. To enable this AI model, add a "
                "flow extractor such as CICFlowMeter, Zeek, Suricata eve.json, or "
                "PyShark/Scapy flow aggregation."
            ),
            "required_input": (
                "CICIDS-style flow rows with packet counts, byte counts, duration, "
                "packet length statistics, flow rates, and TCP flag counts."
            ),
            "predictions": [],
            "details": status,
        }

    try:
        feature_cols = list(pipeline["feature_cols"])
        selected_features = list(pipeline["selected_features"])

        df = _prepare_dataframe(flow_rows, feature_cols)

        scaler = pipeline["scaler"]
        selector = pipeline["feature_selector"]
        model = pipeline["model"]
        label_encoder = pipeline["label_encoder"]

        X_scaled = scaler.transform(df)

        try:
            X_selected = selector.transform(X_scaled)
        except Exception:
            selected_indexes = [
                feature_cols.index(col)
                for col in selected_features
                if col in feature_cols
            ]
            X_selected = X_scaled[:, selected_indexes]

        predictions = model.predict(X_selected)

        probabilities = None

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X_selected)

        labels = label_encoder.inverse_transform(predictions)

        output = []

        for i, label in enumerate(labels):
            confidence = 0.0
            class_scores = {}

            if probabilities is not None:
                probs = probabilities[i]

                try:
                    class_names = list(label_encoder.classes_)
                except Exception:
                    class_names = [str(j) for j in range(len(probs))]

                class_scores = {
                    str(cls): round(float(prob), 4)
                    for cls, prob in zip(class_names, probs)
                }

                confidence = max(class_scores.values()) if class_scores else 0.0

            output.append(
                {
                    "flow_index": i,
                    "prediction": str(label),
                    "confidence": round(float(confidence), 4),
                    "class_scores": class_scores,
                }
            )

        risky = [
            p
            for p in output
            if str(p.get("prediction", "")).lower() not in {"benign", "normal"}
        ]

        return {
            "ran": True,
            "status": "ok",
            "summary": (
                f"CICIDS2017 AI analyzed {len(output)} network flow(s). "
                f"{len(risky)} flow(s) were classified as non-benign."
            ),
            "predictions": output,
            "details": status,
        }

    except Exception as exc:
        return {
            "ran": False,
            "status": "prediction_error",
            "summary": f"CICIDS prediction failed: {exc}",
            "predictions": [],
            "details": status,
        }

# ---------------------------------------------------------------------
# Final override for Hugging Face CICIDS TemperatureScaledClassifier
# ---------------------------------------------------------------------
class TemperatureScaledClassifier:
    """
    Compatibility class for mehddii/cicids2017-soc-classifier-v2.

    The model file tier1_lgbm_temp_scaled.pkl contains:
        base_estimator: LightGBM classifier
        T_: temperature value

    This class must exist in __main__ before joblib.load() can restore the model.
    """

    def __init__(self, base_estimator=None, T_=1.0, **kwargs):
        self.base_estimator = base_estimator
        self.T_ = T_

        for key, value in kwargs.items():
            setattr(self, key, value)

    def __setstate__(self, state):
        if isinstance(state, dict):
            self.__dict__.update(state)

    def _get_base_model(self):
        for name in [
            "base_estimator",
            "base_model",
            "model",
            "estimator",
            "classifier",
            "clf",
            "lgbm",
            "wrapped_model",
        ]:
            value = getattr(self, name, None)

            if value is not None and value is not self:
                return value

        return None

    def _temperature(self):
        for name in ["T_", "temperature", "T"]:
            value = getattr(self, name, None)

            if value is not None:
                try:
                    value = float(value)
                    if value > 0:
                        return value
                except Exception:
                    pass

        return 1.0

    def _scale_probabilities(self, probs):
        import numpy as np

        probs = np.asarray(probs, dtype=float)

        if probs.ndim == 1:
            probs = np.vstack([1.0 - probs, probs]).T

        temperature = self._temperature()

        eps = 1e-12
        logits = np.log(np.clip(probs, eps, 1.0))
        logits = logits / temperature

        exp = np.exp(logits - np.max(logits, axis=1, keepdims=True))
        scaled = exp / np.sum(exp, axis=1, keepdims=True)

        return scaled

    def predict_proba(self, X):
        base = self._get_base_model()

        if base is None:
            attrs = list(getattr(self, "__dict__", {}).keys())
            raise RuntimeError(
                "TemperatureScaledClassifier has no wrapped base model. "
                f"Available attributes: {attrs}"
            )

        if not hasattr(base, "predict_proba"):
            raise RuntimeError("Wrapped base_estimator has no predict_proba method")

        probs = base.predict_proba(X)
        return self._scale_probabilities(probs)

    def predict(self, X):
        import numpy as np

        probs = self.predict_proba(X)
        return np.argmax(probs, axis=1)


import sys
if sys.modules.get("__main__") is not None:
    setattr(sys.modules["__main__"], "TemperatureScaledClassifier", TemperatureScaledClassifier)

