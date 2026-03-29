import pandas as pd

def import_data(file):
    """Import data"""
    try:
        try:
            file_path = 'data/raw/' + file
            df = pd.read_csv(file_path)
            return df
        except FileNotFoundError:
            file_path = 'data/processed/' + file
            df = pd.read_csv(file_path)
            return df
    except Exception as e:
        print(f"Error importing data: {e}")
        return None
    
def clean_data(df):
    """Clean data by removing duplicates and handling missing values."""
    #df = df.drop_duplicates()
    df = df.fillna(method='ffill').fillna(method='bfill')
    return df

def save_data(df, file):
    """Save DataFrame to a CSV file."""
    try:
        file_path = 'data/processed/' + file
        df.to_csv(file_path, index=False)
        print(f"Data saved to {file_path}")
    except Exception as e:
        print(f"Error saving data: {e}")
        

def source_column_names(df):
    """Get Source column name"""
    lower_to_original = {col.lower(): col for col in df.columns}
    names = ['source', 'src', 'src_ip']
    
    for name in names:
        if name in lower_to_original:
            original_col = lower_to_original[name]
            df = df.rename(columns={original_col: 'src'})
            break
    return df

def standardise_data(df):
    """Standardise column names for source and destination ports."""
    standard_names = {
        'Src': 'id.orig_p',
        'Dst': 'id.resp_p',
    }
    df = df.rename(columns=standard_names)
    return df

def calculate_packet_rate(df):
    """Calculate packet rate (packets per time window) for each source."""
    df = df.copy()
    
    # Method: Count packets per source in a rolling window
    # Group by source and calculate packet count with rolling average
    df['Packet_Rate'] = df.groupby('eth.src').cumcount() + 1
    
    # Calculate rolling average of packet counts (10-packet window)
    df['Packet_Rate'] = df.groupby('eth.src')['Packet_Rate'].transform(
        lambda x: x.rolling(window=10, min_periods=1).mean()
    )
    
    return df

def data_encoder(df, label_encoders=None):
    """Encode categorical columns using Label Encoding."""
    from sklearn.preprocessing import LabelEncoder
    
    if label_encoders is None:
        label_encoders = {}
    df_encoded = df.copy()
    for column in df.select_dtypes(include=['object']).columns:
        le = LabelEncoder()
        df_encoded[column] = le.fit_transform(df[column])
        label_encoders[column] = le
    return df_encoded, label_encoders

def pipeline_run(data_path):
    imported_data = import_data(data_path)
    cleaned_data = clean_data(imported_data)
    cleaned_data = calculate_packet_rate(cleaned_data)
    save_data(cleaned_data, 'cleaned_data.csv')
    cleaned_data = source_column_names(cleaned_data)
    cleaned_data = standardise_data(cleaned_data)
    print("Cleaned DataFrame head:\n", cleaned_data.head())
    return cleaned_data


if __name__ == "__main__":
    file = '.csv'
    data = pipeline_run(file)
