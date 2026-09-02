import json, os, glob, shutil, zipfile, hashlib
from install_monitor import InstallMonitor

DATADOG_REPO = "/home/ubuntu/data"
ECOSYSTEM = "malicious_zips"
OUT_DIR = "/home/ubuntu/malicious-software-packages-dataset/data/malicious"
MAX_SAMPLES = 150  # keep it small per your trimmed Phase 2 scope

os.makedirs(OUT_DIR, exist_ok=True)

def file_hash(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def extract_zip(zip_path, out_dir):
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(out_dir, pwd=b"infected")
    return out_dir

def find_installable(extracted_dir):
    candidates = glob.glob(f"{extracted_dir}/**/*.tar.gz", recursive=True) + \
                 glob.glob(f"{extracted_dir}/**/*.whl", recursive=True) + \
                 glob.glob(f"{extracted_dir}/**/setup.py", recursive=True)
    return candidates[0] if candidates else None

def capture_sample(sample_path, name):
    events = []
    mon = InstallMonitor()
    mon.on_event = lambda e: events.append(e)
    target_dir = "/tmp/mal_sandbox"
    shutil.rmtree(target_dir, ignore_errors=True)
    os.makedirs(target_dir, exist_ok=True)

    if sample_path.endswith("setup.py"):
        install_dir = os.path.dirname(sample_path)
        cmd = ["pip", "install", f"--target={target_dir}", install_dir]
    else:
        cmd = ["pip", "install", f"--target={target_dir}", sample_path]

    try:
        mon.run_and_capture(cmd, duration_sec=20)
    except Exception as ex:
        print(f"  FAILED {name}: {ex}")
        return False

    if not events:
        print(f"  WARNING: 0 events for {name}")
        return False

    with open(f"{OUT_DIR}/{name}.jsonl", "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")

    print(f"  {name}: captured {len(events)} events")
    return True


zip_files = glob.glob(f"{DATADOG_REPO}/{ECOSYSTEM}/*.zip")

print(f"Found {len(zip_files)} candidate samples, using up to {MAX_SAMPLES}")

seen_hashes = set()
captured = 0

for zip_path in zip_files:
    if captured >= MAX_SAMPLES:
        break

    h = file_hash(zip_path)

    if h in seen_hashes:
        continue

    seen_hashes.add(h)

    name = os.path.basename(zip_path).replace(".zip", "")

    print(f"Processing {name}...")

    try:
        extracted = extract_zip(
            zip_path,
            "/tmp/dd_extract"
        )

    except Exception as ex:
        print(f"  EXTRACT FAILED: {ex}")
        continue

    sample_file = find_installable(extracted)

    if not sample_file:
        print(f"  No installable file found, skipping")
        continue

    if capture_sample(
        sample_file,
        f"datadog__{name}"
    ):
        captured += 1

print(f"\nDone. Captured {captured} malicious samples into {OUT_DIR}/")