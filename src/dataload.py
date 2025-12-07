import pandas as pd

def import_data(file):
    """Import data"""
    try:
        file_path = 'data/raw/' + file
        df = pd.read_csv(file_path)
        return df
    except Exception as e:
        print(f"Error importing data: {e}")
        return None
    
def clean_data(df):
    """Clean data by removing duplicates and handling missing values."""
    df = df.drop_duplicates()
    df = df.fillna(method='ffill').fillna(method='bfill')
    return df

def save_data(df, file):
    """Save DataFrame to a CSV file."""
    try:
        file_path = 'data/cleaned/' + file
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

def pipeline_run(data_path):
    imported_data = import_data(data_path)
    cleaned_data = clean_data(imported_data)
    save_data(cleaned_data, 'cleaned_data.csv')
    cleaned_data = source_column_names(cleaned_data)
    print("Cleaned DataFrame head:\n", cleaned_data.head())
    return cleaned_data


if __name__ == "__main__":
    file = 'Midterm_53_group.csv'
    data = pipeline_run(file)
