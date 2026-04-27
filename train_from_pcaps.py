"""Batch-process all PCAP files in a directory, merge into one dataset, and train the model."""
import gc

import src

RAW_DIR = "data/raw/train_files"
MERGED_OUTPUT = "data/processed/merged_training_extracted.csv"
MODEL_PATH = "models/random_forest_model"
SAVE_INDIVIDUAL_CSV = True
MAX_TRAINING_ROWS = 21_000_000


def main():
    merged_path = src.process_and_merge_pcaps(
        raw_dir=RAW_DIR,
        merged_output_path=MERGED_OUTPUT,
        save_individual_csv=SAVE_INDIVIDUAL_CSV,
    )

    gc.collect()

    src.train_model(
        dataset_path=merged_path,
        model_path=MODEL_PATH,
        max_rows=MAX_TRAINING_ROWS,
    )
    print("\nAutomation complete.")
    print(f"Merged training dataset: {merged_path}")
    print(f"Model artifacts prefix: {MODEL_PATH}")


if __name__ == "__main__":
    main()
