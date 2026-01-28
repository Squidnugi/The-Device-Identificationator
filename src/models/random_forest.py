import pandas as pd
from ucimlrepo import fetch_ucirepo 
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pickle
import time


def random_forest_model(X, mode, Y=None, model=None, label_encoders=None, mac_addresses=None):
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
            n_jobs=-1
        )
        clf.fit(X_train, y_train)

        y_pred = clf.predict(X_test)

        # report
        print(classification_report(y_test, y_pred))
        print(f"\nFeature Importances (Top 10):")
        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': clf.feature_importances_
        }).sort_values('importance', ascending=False)
        print(feature_importance.head(10))
        
        train_acc = clf.score(X_train, y_train)
        test_acc = clf.score(X_test, y_test)
        print(f"\nTraining Accuracy: {train_acc:.4f}")
        print(f"Test Accuracy: {test_acc:.4f}")
        
        return clf
    elif mode == 'use':
        # model
        probabilities = model.predict_proba(X)
        predicted_encoded = probabilities.argmax(axis=1)
        confidences = probabilities.max(axis=1)
        
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
            'Confidence': confidences
        })
        
        if mac_addresses is not None:
            aggregated_results = []
            for mac in per_packet_results['MAC_Address'].unique():
                mac_data = per_packet_results[per_packet_results['MAC_Address'] == mac]
                
                # Majority voting
                device_votes = mac_data['Predicted_Device'].value_counts()
                most_common_device = device_votes.index[0]
                num_votes = device_votes.iloc[0]
                
                # Average confidence
                winning_predictions = mac_data[mac_data['Predicted_Device'] == most_common_device]
                avg_confidence = winning_predictions['Confidence'].mean()
                
                # Confidence threshold
                confidence_threshold = 0.6
                if avg_confidence < confidence_threshold:
                    most_common_device = 'Unknown'
                
                # Aggregated results
                aggregated_results.append({
                    'MAC_Address': mac,
                    'Predicted_Device': most_common_device,
                    'Confidence': avg_confidence,
                    'Packet_Count': len(mac_data),
                    'Vote_Count': num_votes
                })
            
            results = pd.DataFrame(aggregated_results)
        else:
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
    with open(path + '_scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
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
                    
                    # Vectorized mapping
                    # Handle unknowns while keeping the known
                    col_str = data[col].astype(str)
                    data[col] = col_str.map(
                        lambda x: class_to_idx.get(x, abs(hash(x)) % 1000000 + num_known_classes)
                    )
                else:
                    print(f"No existing encoder for column '{col}', fitting new encoder.")
                    le = LabelEncoder()
                    data[col] = le.fit_transform(data[col].astype(str))
        except Exception as e:
            print(f"Warning: Failed to encode column '{col}': {e}")
            continue

    return data, label_encoders

def dataset_split(data, target_column=None, scaler=None, drop_cols=['eth.src', 'eth.dst', 'IP.src', 'IP.dst']):
    """Split dataset when training and scale features."""
    if target_column is None:
        target_column = 'Device_Type'
    X = data.drop(columns=target_column)
    X = X.drop(columns=drop_cols, errors='ignore')
    Y = data[target_column]
    
    if scaler is None:
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
    else:
        X_scaled = scaler.transform(X)
    
    X_scaled = pd.DataFrame(X_scaled, columns=X.columns)
    
    return X_scaled, Y, scaler


def train_model():
    """train the random forest model"""
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    print("Loading datasets...")
    data = load_datasets('data/processed/16-09-23_extracted.csv')
    print("Encoding data...")
    data, label_encoders = encode_data(data)
    print("Splitting dataset...")
    X, Y, scaler = dataset_split(data, 'Device_Type')
    print("Training model...")
    model = random_forest_model(X, 'train', Y)
    print("Saving model...")
    save_model(model, 'models/random_forest_model', label_encoders, scaler)
    print("Model training complete.")
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))

def use_model():
    """use the random forest model"""
    print("loading dataset")
    data = load_datasets('data/processed/16-09-24_extracted.csv')
    print("loading model")
    model, label_encoders, scaler = load_model('models/random_forest_model')
    print("encoding data")
    endata, _ = encode_data(data, label_encoders=label_encoders)
    print("prepare data")
    X, _, _ = dataset_split(endata, 'Device_Type', scaler=scaler)
    print("predicting")
    results = random_forest_model(X, 'use', model=model, label_encoders=label_encoders, mac_addresses=data.get('eth.src'))
    print(results.to_string())


if __name__ == "__main__":
    #train_model()
    use_model()