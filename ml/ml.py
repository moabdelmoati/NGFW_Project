# save as create_sample_parquet.py
import os, csv, random
from glob import glob
import pandas as pd

INPUT_DIR = "./IDS2018"          # غيّر هنا لو مجلدك غير كده
OUTPUT_CSV = "sampled_600k.csv"
OUTPUT_PARQUET = "sampled_600k.parquet"
SAMPLE_SIZE = 600_000
RANDOM_SEED = 42

random.seed(RANDOM_SEED)
files = sorted(glob(os.path.join(INPUT_DIR, "*.csv")))
print(f"Found {len(files)} CSV files in {INPUT_DIR}")

reservoir = []
total_seen = 0
header = None

for f in files:
    print("Processing:", f)
    with open(f, newline='', encoding='utf-8', errors='replace') as fh:
        reader = csv.reader(fh)
        try:
            file_header = next(reader)
        except StopIteration:
            continue
        if header is None:
            header = file_header
        else:
            if file_header != header:
                # If headers differ, we align by using header from first file.
                # Rows from files with different header will be padded/truncated later when converting to DataFrame.
                pass
        for row in reader:
            total_seen += 1
            if len(reservoir) < SAMPLE_SIZE:
                reservoir.append(row)
            else:
                j = random.randrange(total_seen)
                if j < SAMPLE_SIZE:
                    reservoir[j] = row

print("Total rows scanned:", total_seen)
if header is None:
    raise SystemExit("No CSVs with header found.")

# save sampled CSV
with open(OUTPUT_CSV, "w", newline='', encoding='utf-8') as outfh:
    writer = csv.writer(outfh)
    writer.writerow(header)
    writer.writerows(reservoir)

print("Wrote sample CSV:", OUTPUT_CSV)
# convert to parquet (pandas will infer columns)
df = pd.read_csv(OUTPUT_CSV, low_memory=False)
# optional: drop rows with wrong length or create consistent columns if some files differ
df.to_parquet(OUTPUT_PARQUET, index=False)
print("Wrote parquet:", OUTPUT_PARQUET)
