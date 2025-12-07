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

def scatter_plot(df, x_column, y_column, filename='outputs/scatter_plot.png', colour=None):
    """Create a scatter plot of two specified columns from the DataFrame."""
    plt.figure(figsize=(10, 6))
    
    if colour is not None:
        # Color by the specified column and create legend
        unique_values = df[colour].unique()
        for value in unique_values:
            mask = df[colour] == value
            plt.scatter(df[mask][x_column], df[mask][y_column], alpha=0.5, label=str(value))
        plt.legend()
    else:
        # Simple scatter plot without legend
        plt.scatter(df[x_column], df[y_column], alpha=0.5)
    
    plt.title(f'Scatter Plot of {y_column} vs {x_column}')
    plt.xlabel(x_column)
    plt.ylabel(y_column)
    plt.savefig(filename)
    plt.close()

def ignore_source(df, source_to_ignore):
    """Ignore data from a specific source."""
    return df[df['Source'] != source_to_ignore]

def remove_vms(df):
    """Remove data from specified VMs."""
    df = df.copy()  # Create a copy to avoid modifying the original
    for i in df.index:
        if df.at[i, 'Source'].startswith('VMware'):
            df = df.drop(i)
    return df

def average_plot(df, x_column, y_column, filename='outputs/average_plot.png'):
    """Create an average plot of y_column against x_column."""
    avg_df = df.groupby(x_column)[y_column].mean().reset_index()
    
    plt.figure(figsize=(10, 6))
    plt.plot(avg_df[x_column], avg_df[y_column], marker='o')
    plt.title(f'Average Plot of {y_column} vs {x_column}')
    plt.xlabel(x_column)
    plt.ylabel(f'Average {y_column}')
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
    #scatter_plot(frequency_data, 'Length', 'Frequency', filename='outputs/frequency_scatter_plot.png', colour='Source')
    ignored_data = ignore_source(cleaned_data, '192.167.7.162')
    print(ignored_data.head())
    #scatter_plot(ignored_data, 'Length', 'Time', filename='outputs/ignored_source_scatter_plot.png', colour='Source')
    vm_removed_data = remove_vms(cleaned_data)
    print(vm_removed_data.head())
    #scatter_plot(vm_removed_data, 'Length', 'Time', filename='outputs/vm_removed_scatter_plot.png', colour='Source')
    vm_removed_sorted_data = sort_by_length(vm_removed_data)
    print(vm_removed_sorted_data.head())
    vm_removed_ignored_data = ignore_source(vm_removed_data, '192.167.7.162')
    print(vm_removed_ignored_data.head())
    #scatter_plot(vm_removed_ignored_data, 'Length', 'Time', filename='outputs/vm_removed_ignored_scatter_plot.png', colour='Source')
    average_plot(vm_removed_ignored_data, 'Length', 'Time', filename='outputs/vm_removed_ignored_average_plot.png')