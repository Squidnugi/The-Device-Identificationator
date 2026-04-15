import os

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
from sklearn.preprocessing import LabelEncoder
import pickle
import time
import numpy as np


def random_forest_model(
    X,
    mode,
    Y=None,
    model=None,
    label_encoders=None,
    mac_addresses=None,
    confidence_threshold=0.70,
    margin_threshold=0.12,
):
    """Device identification using Random Forest Classifier.
    split into training and usage modes."""
    if mode == 'train':
        X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.3, random_state=42, stratify=Y)

        # model
        clf = RandomForestClassifier(
            n_estimators=150,
            random_state=42,
            class_weight='balanced',
            max_depth=8, 
            min_samples_split=100,
            min_samples_leaf=50,
            max_features='sqrt',
            # Use all cores for faster training.
            n_jobs=-1
        )
        clf.fit(X_train, y_train)

        # Calibrate probabilities so confidence values better match true correctness.
        calibrated_model = CalibratedClassifierCV(clf, method='sigmoid', cv=3)
        calibrated_model.fit(X_train, y_train)

        y_pred = calibrated_model.predict(X_test)

        # report
        print(classification_report(y_test, y_pred))
        print(f"\nFeature Importances (Top 10):")
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': clf.feature_importances_
        }).sort_values('importance', ascending=False)
        print(feature_importance.head(10))

        # Avoid a second full pass over the massive training set just for scoring.
        test_acc = accuracy_score(y_test, y_pred)

        # Estimate train accuracy from a bounded sample to prevent OOM.
        train_eval_size = min(200000, len(X_train))
        train_idx = np.random.default_rng(42).choice(len(X_train), size=train_eval_size, replace=False)
        train_acc = accuracy_score(y_train.iloc[train_idx], calibrated_model.predict(X_train.iloc[train_idx]))
        print(f"\nTraining Accuracy: {train_acc:.4f}")
        print(f"Test Accuracy: {test_acc:.4f}")
        
        return calibrated_model
    elif mode == 'use':
        # model
        probabilities = model.predict_proba(X)
        class_values = np.asarray(model.classes_)
        predicted_idx = probabilities.argmax(axis=1)
        predicted_encoded = class_values[predicted_idx]
        confidences = probabilities.max(axis=1)

        # Top-2 margin is a useful ambiguity signal (small margin => uncertain).
        if probabilities.shape[1] > 1:
            top2 = np.partition(probabilities, -2, axis=1)[:, -2:]
            margins = top2[:, 1] - top2[:, 0]
        else:
            margins = np.ones(len(probabilities), dtype=np.float32)
        
        # decode predictions
        device_encoder = label_encoders.get('Device_Type')
        if device_encoder is not None:
            predicted_devices = device_encoder.inverse_transform(predicted_encoded)
        else:
            predicted_devices = predicted_encoded
        
        # per-packet results
        per_packet_results = pd.DataFrame({
            'MAC_Address': mac_addresses if mac_addresses is not None else range(len(predicted_devices)),
            'Predicted_Device': predicted_devices,
            'Confidence': confidences,
            'Margin': margins,
        })
        
        if mac_addresses is not None:
            # Better MAC-level confidence: average calibrated probabilities per MAC.
            class_labels = class_values
            if device_encoder is not None:
                class_labels = device_encoder.inverse_transform(class_values.astype(int))

            prob_columns = [str(label) for label in class_labels]
            prob_df = pd.DataFrame(probabilities, columns=prob_columns)
            prob_df.insert(0, 'MAC_Address', per_packet_results['MAC_Address'].values)

            mean_probs = prob_df.groupby('MAC_Address', as_index=False).mean()
            mean_prob_values = mean_probs[prob_columns].to_numpy()

            winner_idx = mean_prob_values.argmax(axis=1)
            winning_conf = mean_prob_values[np.arange(len(mean_probs)), winner_idx]

            if mean_prob_values.shape[1] > 1:
                mac_top2 = np.partition(mean_prob_values, -2, axis=1)[:, -2:]
                mac_margins = mac_top2[:, 1] - mac_top2[:, 0]
            else:
                mac_margins = np.ones(len(mean_probs), dtype=np.float32)

            predicted_mac_device = np.asarray(prob_columns, dtype=object)[winner_idx]

            packet_counts = per_packet_results.groupby('MAC_Address').size().rename('Packet_Count')

            results = pd.DataFrame({
                'MAC_Address': mean_probs['MAC_Address'].values,
                'Predicted_Device': predicted_mac_device,
                'Confidence': winning_conf,
                'Margin': mac_margins,
            })
            results = results.merge(packet_counts.reset_index(), on='MAC_Address', how='left')

            # Keep Vote_Count for compatibility with existing outputs.
            vote_counts = (
                per_packet_results
                .groupby(['MAC_Address', 'Predicted_Device'])
                .size()
                .rename('Vote_Count')
                .reset_index()
            )
            results = results.merge(
                vote_counts,
                on=['MAC_Address', 'Predicted_Device'],
                how='left',
            )
            results['Vote_Count'] = results['Vote_Count'].fillna(0).astype(int)

            low_conf_mask = (results['Confidence'] < confidence_threshold) | (results['Margin'] < margin_threshold)
            results.loc[low_conf_mask, 'Predicted_Device'] = 'Unknown'
            results = results[['MAC_Address', 'Predicted_Device', 'Confidence', 'Packet_Count', 'Vote_Count', 'Margin']]
        else:
            low_conf_mask = (per_packet_results['Confidence'] < confidence_threshold) | (per_packet_results['Margin'] < margin_threshold)
            per_packet_results.loc[low_conf_mask, 'Predicted_Device'] = 'Unknown'
            results = per_packet_results
        
        return results

def save_model(model, path, encoder, scaler):
    """Save model, encoder, and scaler."""
    with open(path + '.pkl', 'wb') as f:
        pickle.dump(model, f)
    with open(path + '_encoder.pkl', 'wb') as f:
        pickle.dump(encoder, f)
    with open(path + '_scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    return model, encoder

def load_model(path):
    """Load model, encoder, and scaler."""
    with open(path + '.pkl', 'rb') as f:
        model = pickle.load(f)
    with open(path + '_encoder.pkl', 'rb') as f:
        encoder = pickle.load(f)
    scaler_path = path + '_scaler.pkl'
    if os.path.exists(scaler_path):
        with open(scaler_path, 'rb') as f:
            scaler = pickle.load(f)
    else:
        scaler = None
    return model, encoder, scaler



def load_datasets(path):
    """Load dataset"""
    if path.endswith('.csv'):
        data = pd.read_csv(path)
    else:
        raise ValueError(f"Unsupported file format: {path}")
    return data


def encode_data(data, label_encoders=None):
    """Encode str columns to numeric using LabelEncoder for model compatibility."""
    if label_encoders is None:
        label_encoders = {}
        mode = True
    else:
        mode = False
    
    data = data.copy()
    
    categorical_columns = data.select_dtypes(include=['object']).columns

    for col in categorical_columns:
        try:
            if mode:
                # Create encoder
                print(f"Encoding column '{col}' in training mode.")
                le = LabelEncoder()
                data[col] = le.fit_transform(data[col].astype(str))
                label_encoders[col] = le
            else:
                # Use existing encoder
                print(f"Encoding column '{col}' in testing mode.")
                # Check if encoder exists
                if col in label_encoders:
                    print(f"Using existing encoder for column '{col}'.")
                    le = label_encoders[col]
                    num_known_classes = len(le.classes_)
                    
                    # Encoder mapping
                    class_to_idx = {cls: idx for idx, cls in enumerate(le.classes_)}
                    
                    col_str = data[col].astype(str)
                    mapped = col_str.map(class_to_idx)

                    # Deterministic unknown bucket assignment avoids per-row Python lambdas.
                    unknown_codes = (
                        pd.util.hash_pandas_object(col_str, index=False)
                        .astype(np.uint64)
                        .mod(1000000)
                        .add(num_known_classes)
                        .astype(np.int64)
                    )
                    data[col] = mapped.where(mapped.notna(), unknown_codes).astype(np.int64)
                else:
                    print(f"No existing encoder for column '{col}', fitting new encoder.")
                    le = LabelEncoder()
                    data[col] = le.fit_transform(data[col].astype(str))
        except Exception as e:
            print(f"Warning: Failed to encode column '{col}': {e}")
            continue

    return data, label_encoders

def dataset_split(
    data,
    target_column=None,
    scaler=None,
    drop_cols=None,
    expect_target=True,
):
    """Split dataset when training and prepare numeric feature matrix."""
    if drop_cols is None:
        drop_cols = ['eth.src', 'eth.dst', 'IP.src', 'IP.dst']
    if target_column is None:
        target_column = 'Device_Type'

    has_target = target_column in data.columns
    if expect_target and not has_target:
        raise KeyError(f"Target column '{target_column}' was not found in dataset.")

    if has_target:
        X = data.drop(columns=target_column)
        Y = data[target_column]
    else:
        X = data.copy()
        Y = None

    X = X.drop(columns=drop_cols, errors='ignore')

    # Random forest does not require feature scaling; keep backwards compatibility
    # if an older scaler artifact is present.
    if scaler is not None:
        X_prepared = scaler.transform(X)
        X_prepared = pd.DataFrame(X_prepared, columns=X.columns)
    else:
        X_prepared = X

    X_prepared = X_prepared.astype(np.float32)
    
    return X_prepared, Y, scaler


def train_model(
    dataset_path='data/processed/16-09-23_extracted.csv',
    model_path='models/random_forest_model',
    max_rows=2000000,
):
    """Train the random forest model from a processed CSV dataset."""
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    print(f"Loading dataset: {dataset_path}")
    data = load_datasets(dataset_path)

    if max_rows is not None and len(data) > max_rows:
        print(f"Dataset has {len(data):,} rows. Sampling down to {max_rows:,} rows for memory-safe training...")
        if 'Device_Type' in data.columns:
            data = data.groupby('Device_Type', group_keys=False).apply(
                lambda group: group.sample(
                    n=min(len(group), max(1, int(max_rows * (len(group) / len(data))))),
                    random_state=42,
                )
            )
            if len(data) > max_rows:
                data = data.sample(n=max_rows, random_state=42)
        else:
            data = data.sample(n=max_rows, random_state=42)
        data = data.reset_index(drop=True)
        print(f"Sampled training rows: {len(data):,}")

    print("Encoding data...")
    data, label_encoders = encode_data(data)
    print("Splitting dataset...")
    X, Y, scaler = dataset_split(data, 'Device_Type')
    print("Training model...")
    model = random_forest_model(X, 'train', Y)
    print("Saving model...")
    save_model(model, model_path, label_encoders, scaler)
    print("Model training complete.")
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

def use_model(
    file_path='data/processed/16-10-12_extracted.csv',
    dataset=None,
    confidence_threshold=0.70,
    margin_threshold=0.12,
):
    """use the random forest model"""
    if not os.path.exists('models/random_forest_model.pkl'):
        raise FileNotFoundError("Model file not found. Please train the model first.")
    if dataset is not None:
        print("Using provided dataset.")
        data = dataset
    else:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dataset file '{file_path}' not found. Please ensure the file exists.")
        print("loading dataset")
        data = load_datasets(file_path)
    print("loading model")
    model, label_encoders, scaler = load_model('models/random_forest_model')
    print("encoding data")
    endata, _ = encode_data(data, label_encoders=label_encoders)
    print("prepare data")
    X, _, _ = dataset_split(endata, 'Device_Type', scaler=scaler, expect_target=False)
    print("predicting")
    results = random_forest_model(
        X,
        'use',
        model=model,
        label_encoders=label_encoders,
        mac_addresses=data.get('eth.src'),
        confidence_threshold=confidence_threshold,
        margin_threshold=margin_threshold,
    )
    return results


if __name__ == "__main__":
    #train_model(dataset_path='data/processed/merged_training_extracted.csv', model_path='models/random_forest_model', max_rows=20000000)
    results = use_model()
    print(results)