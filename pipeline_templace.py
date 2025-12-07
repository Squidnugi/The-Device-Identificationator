from pathlib import Path
import pandas as pd
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

def extract(csv_path: Path) -> pd.DataFrame:
    logging.info("Reading %s", csv_path)
    return pd.read_csv(csv_path)

def transform(df: pd.DataFrame) -> pd.DataFrame:
    logging.info("Cleaning data")
    df = df.drop_duplicates()
    df = df.fillna(method="ffill").fillna(method="bfill")
    # Example feature: frequency per Source
    df["Frequency"] = df.groupby("Source")["Time"].diff()
    return df

def load(df: pd.DataFrame, out_path: Path) -> None:
    logging.info("Writing to %s", out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out_path, index=False)

def run_pipeline(input_csv: str, output_csv: str) -> None:
    df = extract(Path(input_csv))
    df = transform(df)
    #load(df, Path(output_csv))
    logging.info("Transformed DataFrame head:\n%s", df.head())

if __name__ == "__main__":
    run_pipeline("data/Midterm_53_group.csv", "outputs/cleaned.csv")