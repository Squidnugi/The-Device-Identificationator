"""Random Forest classifier for per-MAC network device identification."""
import os
import pickle
import time
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

try:
    from ..datapipeline.pcap import load_datasets
    from ..config import DEFAULT_CONFIDENCE_THRESHOLD, DEFAULT_MARGIN_THRESHOLD
except ImportError:
    if __package__ in (None, ""):
        project_root = Path(__file__).resolve().parents[2]
        if str(project_root) not in sys.path:
            sys.path.insert(0, str(project_root))
        from src.datapipeline.pcap import load_datasets
        from src.config import DEFAULT_CONFIDENCE_THRESHOLD, DEFAULT_MARGIN_THRESHOLD
    else:
        raise


# ---------------------------------------------------------------------------
# Model hyperparameters and classification thresholds
# ---------------------------------------------------------------------------
RF_N_ESTIMATORS = 150
RF_RANDOM_STATE = 42
RF_TEST_SIZE = 0.3
RF_MAX_DEPTH = 8
RF_MIN_SAMPLES_SPLIT = 100
RF_MIN_SAMPLES_LEAF = 50
MAX_TRAINING_ROWS = 21_000_000
TRAIN_ACCURACY_SAMPLE_SIZE = 2_000_000
DEFAULT_MODEL_PATH = "models/random_forest_model"


def _train_classifier(features, labels):
    """Train a calibrated Random Forest on labelled features and return the model.

    Parameters
    ----------
    features : pd.DataFrame
        Numeric feature matrix (rows = packets, columns = extracted features).
    labels : pd.Series
        Integer-encoded device-type label for each row.

    Returns
    -------
    CalibratedClassifierCV
        A fitted, probability-calibrated classifier.
    """
    features_train, features_test, labels_train, labels_test = train_test_split(
        features, labels,
        test_size=RF_TEST_SIZE,
        random_state=RF_RANDOM_STATE,
        stratify=labels,
    )

    clf = RandomForestClassifier(
        n_estimators=RF_N_ESTIMATORS,
        random_state=RF_RANDOM_STATE,
        class_weight="balanced",
        max_depth=RF_MAX_DEPTH,
        min_samples_split=RF_MIN_SAMPLES_SPLIT,
        min_samples_leaf=RF_MIN_SAMPLES_LEAF,
        max_features="sqrt",
        n_jobs=-1,
    )
    clf.fit(features_train, labels_train)

    # Calibrate so confidence values better reflect true correctness.
    calibrated_model = CalibratedClassifierCV(clf, method="sigmoid", cv=3)
    calibrated_model.fit(features_train, labels_train)

    labels_pred = calibrated_model.predict(features_test)

    print(classification_report(labels_test, labels_pred))
    print("\nFeature Importances (Top 10):")
    feature_importance = pd.DataFrame({
        "feature": features.columns,
        "importance": clf.feature_importances_,
    }).sort_values("importance", ascending=False)
    print(feature_importance.head(10))

    test_acc = accuracy_score(labels_test, labels_pred)

    # Sample training set to avoid out-of-memory on large datasets.
    train_eval_size = min(TRAIN_ACCURACY_SAMPLE_SIZE, len(features_train))
    rng = np.random.default_rng(RF_RANDOM_STATE)
    train_idx = rng.choice(len(features_train), size=train_eval_size, replace=False)
    train_acc = accuracy_score(
        labels_train.iloc[train_idx],
        calibrated_model.predict(features_train.iloc[train_idx]),
    )
    print(f"\nTraining Accuracy: {train_acc:.4f}")
    print(f"Test Accuracy:     {test_acc:.4f}")

    return calibrated_model


def _predict_devices(
    features,
    model,
    label_encoders,
    mac_addresses=None,
    confidence_threshold=DEFAULT_CONFIDENCE_THRESHOLD,
    margin_threshold=DEFAULT_MARGIN_THRESHOLD,
):
    """Run inference and return per-MAC device predictions.

    Parameters
    ----------
    features : pd.DataFrame
        Numeric feature matrix (one row per packet).
    model : CalibratedClassifierCV
        Fitted classifier returned by ``_train_classifier``.
    label_encoders : dict
        Mapping of column name to fitted ``LabelEncoder`` instances.
    mac_addresses : pd.Series or None
        Source MAC address for each packet row; when supplied, predictions are
        aggregated per MAC by averaging class probabilities.
    confidence_threshold : float
        Minimum probability required to accept a prediction.
    margin_threshold : float
        Minimum top-1 minus top-2 probability gap required to accept a prediction.

    Returns
    -------
    pd.DataFrame
        One row per MAC address (or per packet when *mac_addresses* is None)
        with columns: MAC_Address, Predicted_Device, Confidence, Packet_Count,
        Vote_Count, Margin.
    """
    probabilities = model.predict_proba(features)
    class_values = np.asarray(model.classes_)
    predicted_idx = probabilities.argmax(axis=1)
    predicted_encoded = class_values[predicted_idx]
    confidences = probabilities.max(axis=1)

    if probabilities.shape[1] > 1:
        top2 = np.partition(probabilities, -2, axis=1)[:, -2:]
        margins = top2[:, 1] - top2[:, 0]
    else:
        margins = np.ones(len(probabilities), dtype=np.float32)

    device_encoder = label_encoders.get("Device_Type")
    if device_encoder is not None:
        predicted_devices = device_encoder.inverse_transform(predicted_encoded)
    else:
        predicted_devices = predicted_encoded

    per_packet_results = pd.DataFrame({
        "MAC_Address": mac_addresses if mac_addresses is not None else range(len(predicted_devices)),
        "Predicted_Device": predicted_devices,
        "Confidence": confidences,
        "Margin": margins,
    })

    if mac_addresses is not None:
        class_labels = class_values
        if device_encoder is not None:
            class_labels = device_encoder.inverse_transform(class_values.astype(int))

        prob_columns = [str(label) for label in class_labels]
        prob_df = pd.DataFrame(probabilities, columns=prob_columns)
        prob_df.insert(0, "MAC_Address", per_packet_results["MAC_Address"].values)

        mean_probs = prob_df.groupby("MAC_Address", as_index=False).mean()
        mean_prob_values = mean_probs[prob_columns].to_numpy()

        winner_idx = mean_prob_values.argmax(axis=1)
        winning_conf = mean_prob_values[np.arange(len(mean_probs)), winner_idx]

        if mean_prob_values.shape[1] > 1:
            mac_top2 = np.partition(mean_prob_values, -2, axis=1)[:, -2:]
            mac_margins = mac_top2[:, 1] - mac_top2[:, 0]
        else:
            mac_margins = np.ones(len(mean_probs), dtype=np.float32)

        predicted_mac_device = np.asarray(prob_columns, dtype=object)[winner_idx]

        packet_counts = per_packet_results.groupby("MAC_Address").size().rename("Packet_Count")

        results = pd.DataFrame({
            "MAC_Address": mean_probs["MAC_Address"].values,
            "Predicted_Device": predicted_mac_device,
            "Confidence": winning_conf,
            "Margin": mac_margins,
        })
        results = results.merge(packet_counts.reset_index(), on="MAC_Address", how="left")

        vote_counts = (
            per_packet_results
            .groupby(["MAC_Address", "Predicted_Device"])
            .size()
            .rename("Vote_Count")
            .reset_index()
        )
        results = results.merge(vote_counts, on=["MAC_Address", "Predicted_Device"], how="left")
        results["Vote_Count"] = results["Vote_Count"].fillna(0).astype(int)

        low_conf_mask = (
            (results["Confidence"] < confidence_threshold) |
            (results["Margin"] < margin_threshold)
        )
        results.loc[low_conf_mask, "Predicted_Device"] = "Unknown"
        results = results[["MAC_Address", "Predicted_Device", "Confidence", "Packet_Count", "Vote_Count", "Margin"]]
    else:
        low_conf_mask = (
            (per_packet_results["Confidence"] < confidence_threshold) |
            (per_packet_results["Margin"] < margin_threshold)
        )
        per_packet_results.loc[low_conf_mask, "Predicted_Device"] = "Unknown"
        results = per_packet_results

    return results


def save_model(model, path, encoder):
    """Save model and encoder to disk as pickle files.

    Parameters
    ----------
    model : estimator
        Fitted classifier to persist.
    path : str
        Filesystem path prefix; two files are written with .pkl suffixes.
    encoder : dict
        LabelEncoder mapping returned by ``encode_data``.

    Returns
    -------
    tuple[estimator, dict]
        The model and encoder passed in (unchanged).
    """
    try:
        with open(path + ".pkl", "wb") as file_handle:
            pickle.dump(model, file_handle)
        with open(path + "_encoder.pkl", "wb") as file_handle:
            pickle.dump(encoder, file_handle)
    except OSError as exc:
        raise OSError(f"Failed to save model artifacts to '{path}': {exc}") from exc
    return model, encoder


def load_model(path):
    """Load model and encoder from disk.

    Parameters
    ----------
    path : str
        Filesystem path prefix used when the model was saved.

    Returns
    -------
    tuple[estimator, dict]
        Fitted model and label-encoder mapping.
    """
    try:
        with open(path + ".pkl", "rb") as file_handle:
            model = pickle.load(file_handle)
        with open(path + "_encoder.pkl", "rb") as file_handle:
            encoder = pickle.load(file_handle)
    except OSError as exc:
        raise OSError(f"Failed to load model artifacts from '{path}': {exc}") from exc

    return model, encoder


def encode_data(data, label_encoders=None):
    """Encode categorical columns to numeric using LabelEncoder.

    In training mode (no existing encoders supplied) a new encoder is fitted
    for each categorical column. In inference mode the existing encoders are
    applied; unseen categories receive a deterministic numeric bucket so the
    model can still process them without crashing.

    Parameters
    ----------
    data : pd.DataFrame
        Raw dataset that may contain string-typed columns.
    label_encoders : dict or None
        Existing encoders to reuse. Pass None to fit new encoders (training).

    Returns
    -------
    tuple[pd.DataFrame, dict]
        Encoded copy of the data and the updated encoder mapping.
    """
    is_training = label_encoders is None
    if is_training:
        label_encoders = {}

    data = data.copy()
    categorical_columns = data.select_dtypes(include=["object"]).columns

    for col in categorical_columns:
        try:
            if is_training:
                print(f"Encoding column '{col}' in training mode.")
                label_encoder = LabelEncoder()
                data[col] = label_encoder.fit_transform(data[col].astype(str))
                label_encoders[col] = label_encoder
            else:
                print(f"Encoding column '{col}' in inference mode.")
                if col in label_encoders:
                    label_encoder = label_encoders[col]
                    num_known_classes = len(label_encoder.classes_)
                    class_to_idx = {cls: idx for idx, cls in enumerate(label_encoder.classes_)}

                    col_str = data[col].astype(str)
                    mapped = col_str.map(class_to_idx)

                    # Deterministic unknown-category bucket: avoids per-row lambdas.
                    unknown_codes = (
                        pd.util.hash_pandas_object(col_str, index=False)
                        .astype(np.uint64)
                        .mod(1_000_000)
                        .add(num_known_classes)
                        .astype(np.int64)
                    )
                    data[col] = mapped.where(mapped.notna(), unknown_codes).astype(np.int64)
                else:
                    print(f"No existing encoder for column '{col}', fitting new encoder.")
                    label_encoder = LabelEncoder()
                    data[col] = label_encoder.fit_transform(data[col].astype(str))
        except (ValueError, TypeError) as exc:
            print(f"Warning: Failed to encode column '{col}': {exc}")
            continue

    return data, label_encoders


def dataset_split(
    data,
    target_column=None,
    drop_cols=None,
    expect_target=True,
):
    """Split dataset into feature matrix and optional label vector.

    Parameters
    ----------
    data : pd.DataFrame
        Encoded dataset.
    target_column : str or None
        Name of the label column; defaults to ``'Device_Type'``.
    drop_cols : list or None
        Columns to remove before returning features; defaults to MAC/IP cols.
    expect_target : bool
        When True, raise ``KeyError`` if *target_column* is absent.

    Returns
    -------
    tuple[pd.DataFrame, pd.Series or None]
        Feature matrix and label vector (or None).
    """
    if drop_cols is None:
        drop_cols = ["eth.src", "eth.dst", "IP.src", "IP.dst"]
    if target_column is None:
        target_column = "Device_Type"

    has_target = target_column in data.columns
    if expect_target and not has_target:
        raise KeyError(f"Target column '{target_column}' was not found in dataset.")

    if has_target:
        features = data.drop(columns=target_column)
        labels = data[target_column]
    else:
        features = data.copy()
        labels = None

    features = features.drop(columns=drop_cols, errors="ignore")
    features = features.astype(np.float32)

    return features, labels


def train_model(
    dataset_path="data/processed/merged_training_extracted.csv",
    model_path=DEFAULT_MODEL_PATH,
    max_rows=MAX_TRAINING_ROWS,
):
    """Train the Random Forest model from a processed CSV and save artifacts.

    Parameters
    ----------
    dataset_path : str
        Path to the labelled training CSV produced by the PCAP pipeline.
    model_path : str
        Output path prefix for the three saved ``.pkl`` artifact files.
    max_rows : int or None
        Cap on training rows; stratified sampling is used when the dataset
        exceeds this limit to preserve class distribution.
    """
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    print(f"Loading dataset: {dataset_path}")
    data = load_datasets(dataset_path)

    if max_rows is not None and len(data) > max_rows:
        print(f"Dataset has {len(data):,} rows. Sampling down to {max_rows:,} for memory-safe training...")
        if "Device_Type" in data.columns:
            data = data.groupby("Device_Type", group_keys=False).apply(
                lambda group: group.sample(
                    n=min(len(group), max(1, int(max_rows * (len(group) / len(data))))),
                    random_state=RF_RANDOM_STATE,
                )
            )
            if len(data) > max_rows:
                data = data.sample(n=max_rows, random_state=RF_RANDOM_STATE)
        else:
            data = data.sample(n=max_rows, random_state=RF_RANDOM_STATE)
        data = data.reset_index(drop=True)
        print(f"Sampled training rows: {len(data):,}")

    print("Encoding data...")
    data, label_encoders = encode_data(data)
    print("Splitting dataset...")
    features, labels = dataset_split(data, target_column="Device_Type")
    print("Training model...")
    model = _train_classifier(features, labels)
    print("Saving model...")
    save_model(model, model_path, label_encoders)
    print("Model training complete.")
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))


def use_model(
    file_path=None,
    dataset=None,
    confidence_threshold=DEFAULT_CONFIDENCE_THRESHOLD,
    margin_threshold=DEFAULT_MARGIN_THRESHOLD,
):
    """Load the trained model and return per-MAC device predictions.

    Parameters
    ----------
    file_path : str
        Path to a processed CSV when no *dataset* is supplied.
    dataset : pd.DataFrame or None
        Pre-loaded DataFrame to use instead of reading from disk.
    confidence_threshold : float
        Minimum prediction confidence to accept a classification.
    margin_threshold : float
        Minimum top-1 vs top-2 probability gap to accept a classification.

    Returns
    -------
    pd.DataFrame
        Prediction results with columns: MAC_Address, Predicted_Device,
        Confidence, Packet_Count, Vote_Count, Margin.
    """
    if not os.path.exists(DEFAULT_MODEL_PATH + ".pkl"):
        raise FileNotFoundError("Model file not found. Please train the model first.")

    if dataset is not None:
        print("Using provided dataset.")
        data = dataset
    else:
        if not os.path.exists(file_path):
            raise FileNotFoundError(
                f"Dataset file '{file_path}' not found. Please ensure the file exists."
            )
        print("Loading dataset.")
        data = load_datasets(file_path)

    print("Loading model.")
    model, label_encoders = load_model(DEFAULT_MODEL_PATH)
    model.n_jobs = 1  # avoid loky multiprocessing issues inside async/TUI contexts on Linux
    print("Encoding data.")
    encoded_data, _ = encode_data(data, label_encoders=label_encoders)
    print("Preparing features.")
    features, _ = dataset_split(encoded_data, "Device_Type", expect_target=False)
    print("Running predictions.")
    results = _predict_devices(
        features,
        model=model,
        label_encoders=label_encoders,
        mac_addresses=data.get("eth.src"),
        confidence_threshold=confidence_threshold,
        margin_threshold=margin_threshold,
    )

    if "IP.src" in data.columns and "eth.src" in data.columns:
        valid_ips = data[data["IP.src"] != "N/A"]
        ip_map = valid_ips.groupby("eth.src")["IP.src"].last()
        results["IP_Address"] = results["MAC_Address"].map(ip_map)

    return results


if __name__ == "__main__":
    train_model(dataset_path="data/processed/16-09-23_extracted.csv", model_path="models/random_forest_model_test")
