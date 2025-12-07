import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt

def import_data(file_path):
    """Import data from a CSV file."""
    return pd.read_csv(file_path)

def clean_data(df):
    """Clean the data by handling missing values and duplicates."""
    df = df.drop_duplicates()
    df = df.fillna(method='ffill').fillna(method='bfill')
    return df


def sort_by_length(df):
    return df.sort_values(by='Length', ascending=False)

def plot_data(df, column):
    """Plot a specified column from the DataFrame."""
    plt.figure(figsize=(10, 6))
    plt.plot(df[column])
    plt.title(f'Plot of {column}')
    plt.xlabel('Index')
    plt.ylabel(column)
    plt.savefig('outputs/plot.png')
    plt.close()

def calculate_frequency(df):
    """Calculate frequency by subtracting the last packet time from the current packet time for the same source."""
    df['Frequency'] = df.groupby('Source')['Time'].transform(lambda x: x - x.shift(1))
    return df

def scatter_plot(df, x_column, y_column, filename='outputs/scatter_plot.png'):
    """Create a scatter plot of two specified columns from the DataFrame."""
    plt.figure(figsize=(10, 6))
    plt.scatter(df[x_column], df[y_column], alpha=0.5)
    plt.title(f'Scatter Plot of {y_column} vs {x_column}')
    plt.xlabel(x_column)
    plt.ylabel(y_column)
    plt.savefig(filename)
    plt.close()
    
if __name__ == "__main__":
    # Example usage
    data = import_data('data/Midterm_53_group.csv')
    cleaned_data = clean_data(data)
    print(cleaned_data.head())
    sorted_data = sort_by_length(cleaned_data)
    print(sorted_data.head())
    frequency_data = calculate_frequency(cleaned_data)
    scatter_plot(frequency_data, 'Time', 'Frequency', filename='outputs/frequency_scatter_plot.png')