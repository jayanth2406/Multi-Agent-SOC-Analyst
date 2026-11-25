"""Download the raw public datasets as CSV files into data/raw/, unchanged.

    pip install datasets
    python scripts/fetch_raw_datasets.py

This only downloads and saves. It never edits values and never writes to the
telemetry database. Afterwards, run scripts/build_poc_alerts.py.

The Hugging Face copies are community re-uploads, not the official releases.
They are fine for the Semester 7 proof of concept; the final evaluation should
use the official files (see docs/poc-alert-set.md). Each download's source and
the columns it contains are recorded in data/raw/SOURCES.txt so this can be
checked.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw"

# (folder the generator reads, Hugging Face dataset id, columns the generator needs)
SOURCES = [
    ("unsw_nb15", "Mouwiya/UNSW-NB15", {"attack_cat", "label"}),
    ("beth", "peytonjoyce/beth-dataset", {"sus", "evil"}),
]


def main():
    try:
        from datasets import load_dataset
    except ImportError:
        sys.exit("The 'datasets' package is missing. Run:  pip install datasets")

    RAW.mkdir(parents=True, exist_ok=True)
    log = []
    for folder, repo, needed in SOURCES:
        out = RAW / folder
        out.mkdir(exist_ok=True)
        print(f"Downloading {repo} ...")
        try:
            ds = load_dataset(repo)
        except Exception as e:  # report and carry on with the next dataset
            print(f"  FAILED: {e}")
            log.append(f"{folder}: {repo} FAILED ({e})")
            continue
        for split, part in ds.items():
            path = out / f"{folder}_{split}.csv"
            part.to_csv(str(path), index=False)
            cols = set(part.column_names)
            lower = {c.strip().lower() for c in cols}
            missing = {c for c in needed if c not in lower}
            status = "OK" if not missing else f"MISSING COLUMNS {sorted(missing)}"
            print(f"  {split}: {part.num_rows} rows -> {path.relative_to(ROOT)}  [{status}]")
            log.append(f"{folder}: {repo} split={split} rows={part.num_rows} {status}\n"
                       f"    columns: {sorted(cols)}")

    (RAW / "SOURCES.txt").write_text("\n".join(log) + "\n")
    print(f"\nWrote {(RAW / 'SOURCES.txt').relative_to(ROOT)}.")
    print("CICIDS2017 is not on this list: download its MachineLearningCSV zip from the CIC site and "
          "unzip the CSVs into data/raw/cicids2017/.")


if __name__ == "__main__":
    main()