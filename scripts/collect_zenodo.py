#!/usr/bin/env python3

import argparse
import json
import re
import shutil
import subprocess
import time
import zipfile

from pathlib import Path
from typing import Optional


# ============================================================
# CONFIGURATION
# ============================================================

ZENODO_DIR = Path("/home/ubuntu/data/zenodo_13746167")

MALWARE_ZIP = ZENODO_DIR / "rq1_pypi_malware.zip"
BENIGN_ZIP = ZENODO_DIR / "rq1_pypi_benign.zip"

EXTRACT_DIR_NAME = "extracted"
TRACE_DIR_NAME = "traces"
DATA_DIR_NAME = "data"

MALWARE_OUTPUT_NAME = "malware.jsonl"
BENIGN_OUTPUT_NAME = "benign.jsonl"

MONITOR_NAME = "monitor.sh"

TEMP_VENV = Path("/tmp/scbf_zenodo")

PYTHON312 = Path(
    "/home/ubuntu/.pyenv/versions/3.12.10/bin/python"
)

PIP_TIMEOUT = 600

POST_INSTALL_WAIT = 2

MAX_ARTIFACTS_DEFAULT = 1500

BOOTSTRAP_PACKAGES = [
    "pip",
    "setuptools",
    "wheel",
    "requests",
]


# ============================================================
# OUTPUT HELPERS
# ============================================================

def info(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warning(message: str) -> None:
    print(f"[WARNING] {message}", flush=True)


def error(message: str) -> None:
    print(f"[ERROR] {message}", flush=True)


def section(title: str) -> None:
    print()
    print("=" * 80)
    print(title)
    print("=" * 80)
    print()


# ============================================================
# PATHS
# ============================================================

class DatasetPaths:

    def __init__(self, root: Path):

        self.root = root

        # ----------------------------------------------------
        # Separate dataset roots
        # ----------------------------------------------------

        self.malware_dir = root / "malware"
        self.benign_dir = root / "benign"

        # ----------------------------------------------------
        # Malware
        # ----------------------------------------------------

        self.malware_extract = (
            self.malware_dir /
            EXTRACT_DIR_NAME
        )

        self.malware_trace_dir = (
            self.malware_dir /
            TRACE_DIR_NAME
        )

        self.malware_data_dir = (
            self.malware_dir /
            DATA_DIR_NAME
        )

        self.malware_output = (
            self.malware_data_dir /
            MALWARE_OUTPUT_NAME
        )

        # ----------------------------------------------------
        # Benign
        # ----------------------------------------------------

        self.benign_extract = (
            self.benign_dir /
            EXTRACT_DIR_NAME
        )

        self.benign_trace_dir = (
            self.benign_dir /
            TRACE_DIR_NAME
        )

        self.benign_data_dir = (
            self.benign_dir /
            DATA_DIR_NAME
        )

        self.benign_output = (
            self.benign_data_dir /
            BENIGN_OUTPUT_NAME
        )

        # ----------------------------------------------------
        # Monitor
        # ----------------------------------------------------

        self.monitor = (
            root /
            MONITOR_NAME
        )

    def create_directories(self) -> None:

        self.malware_extract.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.malware_trace_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.malware_data_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.benign_extract.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.benign_trace_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.benign_data_dir.mkdir(
            parents=True,
            exist_ok=True,
        )


# ============================================================
# NORMALIZATION
# ============================================================

def normalize_package_name(name: str) -> str:

    name = name.strip()

    name = re.sub(
        r"\.(tar\.gz|tar|tgz|zip|whl)$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"[-_.]+",
        "-",
        name,
    )

    return name.lower()


def artifact_package_name(
    artifact: Path,
) -> str:

    name = artifact.name

    name = re.sub(
        r"\.tar\.gz$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"\.tgz$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"\.tar$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"\.zip$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"\.whl$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    match = re.match(
        r"^(.+?)-\d+(?:\.\d+)*(?:[a-zA-Z0-9.-]*)?$",
        name,
    )

    if match:
        name = match.group(1)

    return normalize_package_name(name)


def artifact_version(
    artifact: Path,
) -> Optional[str]:

    name = artifact.name

    name = re.sub(
        r"\.tar\.gz$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"\.tgz$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"\.tar$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"\.zip$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    name = re.sub(
        r"\.whl$",
        "",
        name,
        flags=re.IGNORECASE,
    )

    match = re.search(
        r"-(\d+(?:\.\d+)+(?:[a-zA-Z0-9.-]*)?)$",
        name,
    )

    if match:
        return match.group(1)

    return None


# ============================================================
# ZIP SAFETY
# ============================================================

def safe_extract_zip(
    archive: Path,
    destination: Path,
) -> bool:

    # --------------------------------------------------------
    # Only skip extraction if directory contains content.
    # --------------------------------------------------------

    if destination.exists():

        try:
            has_content = any(
                destination.iterdir()
            )
        except Exception:
            has_content = False

        if has_content:

            info(
                f"Already extracted: {destination}"
            )

            return True

        info(
            f"Extraction directory is empty: "
            f"{destination}"
        )

    destination.mkdir(
        parents=True,
        exist_ok=True,
    )

    info(
        f"Extracting: {archive}"
    )

    try:

        with zipfile.ZipFile(
            archive,
            "r",
        ) as z:

            destination_resolved = (
                destination.resolve()
            )

            for member in z.infolist():

                member_path = (
                    destination /
                    member.filename
                ).resolve()

                if not str(member_path).startswith(
                    str(destination_resolved)
                ):

                    error(
                        f"Unsafe ZIP path: "
                        f"{member.filename}"
                    )

                    return False

            z.extractall(
                destination
            )

        info(
            f"Extracted to: {destination}"
        )

        return True

    except Exception as exc:

        error(
            f"Extraction failed: {exc}"
        )

        return False


# ============================================================
# ARCHIVE INSPECTION
# ============================================================

def inspect_archive(
    archive: Path,
) -> None:

    section(
        f"INSPECT: {archive.name}"
    )

    try:

        with zipfile.ZipFile(
            archive,
            "r",
        ) as z:

            entries = z.namelist()

            print(
                f"[+] Archive entries: {len(entries)}"
            )

            for entry in entries[:100]:

                print(
                    f"  {entry}"
                )

            if len(entries) > 100:

                print()
                print(
                    "... showing first 100 entries ..."
                )

    except Exception as exc:

        error(
            f"Unable to inspect archive: {exc}"
        )


# ============================================================
# DATASET VERIFICATION
# ============================================================

def verify_dataset() -> bool:

    section(
        "VERIFY ZENODO DATASET"
    )

    print(
        f"[+] Dataset directory: {ZENODO_DIR}"
    )

    print()

    print(
        f"[+] Malware archive: {MALWARE_ZIP}"
    )

    if MALWARE_ZIP.exists():

        print(
            f"[+] Malware size: "
            f"{MALWARE_ZIP.stat().st_size / (1024 * 1024):.2f} MB"
        )

    else:

        error(
            f"Missing malware archive: {MALWARE_ZIP}"
        )

    print()

    print(
        f"[+] Benign archive: {BENIGN_ZIP}"
    )

    if BENIGN_ZIP.exists():

        print(
            f"[+] Benign size: "
            f"{BENIGN_ZIP.stat().st_size / (1024 * 1024):.2f} MB"
        )

    else:

        error(
            f"Missing benign archive: {BENIGN_ZIP}"
        )

    print()

    if (
        MALWARE_ZIP.exists()
        and
        BENIGN_ZIP.exists()
    ):

        print(
            "[OK] Both archives found."
        )

        return True

    return False


# ============================================================
# EXTRACTION
# ============================================================

def extract_datasets(
    paths: DatasetPaths,
    clean_extraction: bool = False,
    malware_only: bool = False,
    benign_only: bool = False,
) -> bool:

    # --------------------------------------------------------
    # Clean only selected extraction directories.
    # --------------------------------------------------------

    if clean_extraction:

        if not benign_only:

            info(
                "Cleaning malware extraction directory."
            )

            shutil.rmtree(
                paths.malware_extract,
                ignore_errors=True,
            )

        if not malware_only:

            info(
                "Cleaning benign extraction directory."
            )

            shutil.rmtree(
                paths.benign_extract,
                ignore_errors=True,
            )

    # --------------------------------------------------------
    # Create selected extraction directories.
    # --------------------------------------------------------

    if not benign_only:

        paths.malware_extract.mkdir(
            parents=True,
            exist_ok=True,
        )

    if not malware_only:

        paths.benign_extract.mkdir(
            parents=True,
            exist_ok=True,
        )

    # --------------------------------------------------------
    # Extract selected dataset.
    # --------------------------------------------------------

    if not benign_only:

        malware_ok = safe_extract_zip(
            MALWARE_ZIP,
            paths.malware_extract,
        )

        if not malware_ok:
            return False

    if not malware_only:

        benign_ok = safe_extract_zip(
            BENIGN_ZIP,
            paths.benign_extract,
        )

        if not benign_ok:
            return False

    return True


# ============================================================
# ARTIFACT DISCOVERY
# ============================================================

def discover_artifacts(
    extraction_dir: Path,
) -> list[Path]:

    artifacts = []

    if not extraction_dir.exists():
        return artifacts

    for path in extraction_dir.rglob("*"):

        if not path.is_file():
            continue

        name = path.name.lower()

        if (
            name.endswith(".tar.gz")
            or
            name.endswith(".tgz")
            or
            name.endswith(".tar")
            or
            name.endswith(".zip")
            or
            name.endswith(".whl")
        ):

            artifacts.append(path)

    artifacts.sort(
        key=lambda p: str(p).lower()
    )

    return artifacts


# ============================================================
# TEMPORARY VENV
# ============================================================

def remove_temp_venv() -> None:

    if TEMP_VENV.exists():

        info(
            f"Removing temporary venv: {TEMP_VENV}"
        )

        shutil.rmtree(
            TEMP_VENV,
            ignore_errors=True,
        )


def create_temp_venv() -> Optional[Path]:

    # --------------------------------------------------------
    # Always start from a clean disposable environment.
    # --------------------------------------------------------

    remove_temp_venv()

    TEMP_VENV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    info(
        f"Creating temporary venv: {TEMP_VENV}"
    )

    if not PYTHON312.exists():

        error(
            f"Python 3.12 not found: {PYTHON312}"
        )

        return None

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # --without-pip prevents Python's ensurepip from running.
    #
    # Your previous collector was failing here:
    #
    # ensurepip --upgrade --default-pip
    #
    # We avoid that completely.
    # --------------------------------------------------------

    result = subprocess.run(
        [
            str(PYTHON312),
            "-m",
            "venv",
            "--without-pip",
            str(TEMP_VENV),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    if result.returncode != 0:

        error(
            "Failed to create temporary venv."
        )

        print(
            result.stdout
        )

        remove_temp_venv()

        return None

    python_path = (
        TEMP_VENV /
        "bin" /
        "python"
    )

    if not python_path.exists():

        error(
            f"Venv Python not found: {python_path}"
        )

        remove_temp_venv()

        return None

    # --------------------------------------------------------
    # Bootstrap pip into the new venv.
    #
    # We use the known-working Python 3.12 installation.
    # --------------------------------------------------------

    info(
        "Bootstrapping pip into temporary venv..."
    )

    bootstrap = subprocess.run(
        [
            str(PYTHON312),
            "-m",
            "pip",
            "--python",
            str(python_path),
            "install",
            "--upgrade",
            *BOOTSTRAP_PACKAGES,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=PIP_TIMEOUT,
    )

    if bootstrap.returncode != 0:

        error(
            "Failed to bootstrap temporary venv."
        )

        print(
            bootstrap.stdout
        )

        remove_temp_venv()

        return None

    # --------------------------------------------------------
    # Verify build environment.
    # --------------------------------------------------------

    verify = subprocess.run(
        [
            str(python_path),
            "-c",
            (
                "import sys; "
                "import pip; "
                "import setuptools; "
                "import requests; "
                "import setuptools.build_meta; "
                "print(sys.version); "
                "print('pip:', pip.__version__); "
                "print('setuptools:', setuptools.__version__); "
                "print('requests:', requests.__version__); "
                "print('BUILD ENV OK')"
            ),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    if verify.returncode != 0:

        error(
            "Build environment verification failed."
        )

        print(
            verify.stdout
        )

        remove_temp_venv()

        return None

    info(
        "Temporary venv build environment ready."
    )

    print(
        verify.stdout
    )

    return python_path


# ============================================================
# MONITOR PROCESS
# ============================================================

def count_events(
    jsonl_path: Path,
) -> int:

    if not jsonl_path.exists():
        return 0

    count = 0

    try:

        with jsonl_path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                try:

                    json.loads(line)

                    count += 1

                except json.JSONDecodeError:

                    continue

    except Exception as exc:

        warning(
            f"Unable to count events: {exc}"
        )

    return count


def run_monitor_install(
    monitor: Path,
    package: str,
    python_path: Path,
    artifact: Path,
    output_path: Path,
) -> tuple[int, int]:

    if not monitor.exists():

        error(
            f"Monitor not found: {monitor}"
        )

        return 1, 0

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    if output_path.exists():

        output_path.unlink()

    info(
        f"Starting SCBF monitor for: {package}"
    )

    command = [
        "sudo",
        str(monitor),
        package,
        str(python_path),
        str(artifact),
        str(output_path),
    ]

    info(
        "Executing monitored installation."
    )

    info(
        "Network remains isolated/controlled; "
        "malicious external connections are not enabled."
    )

    try:

        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=PIP_TIMEOUT,
        )

    except subprocess.TimeoutExpired as exc:

        error(
            f"Installation timed out after "
            f"{PIP_TIMEOUT} seconds."
        )

        if exc.stdout:
            print(exc.stdout)

        return (
            124,
            count_events(output_path),
        )

    except Exception as exc:

        error(
            f"Monitor execution failed: {exc}"
        )

        return (
            1,
            count_events(output_path),
        )

    print(
        result.stdout
    )

    event_count = count_events(
        output_path
    )

    info(
        f"Monitor return code: {result.returncode}"
    )

    info(
        f"Captured events: {event_count}"
    )

    return (
        result.returncode,
        event_count,
    )


# ============================================================
# TRACE METADATA
# ============================================================

def load_events(
    path: Path,
) -> list[dict]:

    events = []

    if not path.exists():
        return events

    try:

        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                try:

                    event = json.loads(
                        line
                    )

                    if isinstance(
                        event,
                        dict,
                    ):

                        events.append(event)

                except json.JSONDecodeError:
                    continue

    except Exception as exc:

        warning(
            f"Unable to read trace: {exc}"
        )

    return events


def enrich_events(
    events: list[dict],
    package: str,
    version: Optional[str],
    artifact: Path,
    label: str,
) -> list[dict]:

    enriched = []

    for event in events:

        item = dict(event)

        item.setdefault(
            "package",
            package,
        )

        if version is not None:

            item.setdefault(
                "version",
                version,
            )

        item.setdefault(
            "artifact",
            str(artifact),
        )

        item.setdefault(
            "label",
            label,
        )

        enriched.append(item)

    return enriched


# ============================================================
# JSONL WRITING
# ============================================================

def append_jsonl(
    output_path: Path,
    records: list[dict],
) -> None:

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "a",
        encoding="utf-8",
    ) as f:

        for record in records:

            f.write(
                json.dumps(
                    record,
                    separators=(
                        ",",
                        ":",
                    ),
                    ensure_ascii=False,
                )
            )

            f.write("\n")


# ============================================================
# CLEAN DATASET OUTPUT
# ============================================================

def clear_dataset_output(
    paths: DatasetPaths,
    label: str,
) -> None:

    if label.upper() == "MALICIOUS":

        output_path = paths.malware_output
        trace_dir = paths.malware_trace_dir

    else:

        output_path = paths.benign_output
        trace_dir = paths.benign_trace_dir

    # --------------------------------------------------------
    # Remove combined JSONL.
    # --------------------------------------------------------

    if output_path.exists():

        info(
            f"Removing previous output: {output_path}"
        )

        output_path.unlink()

    # --------------------------------------------------------
    # Remove previous final traces.
    # --------------------------------------------------------

    if trace_dir.exists():

        info(
            f"Cleaning previous traces: {trace_dir}"
        )

        for trace in trace_dir.glob("*.jsonl"):

            try:
                trace.unlink()

            except Exception as exc:

                warning(
                    f"Could not remove trace "
                    f"{trace}: {exc}"
                )

    # --------------------------------------------------------
    # Remove temporary traces.
    # --------------------------------------------------------

    temp_trace_dir = paths.root / ".tmp_traces"

    if temp_trace_dir.exists():

        info(
            f"Cleaning temporary traces: "
            f"{temp_trace_dir}"
        )

        for trace in temp_trace_dir.glob("*.jsonl"):

            try:
                trace.unlink()

            except Exception as exc:

                warning(
                    f"Could not remove temporary trace "
                    f"{trace}: {exc}"
                )


# ============================================================
# SINGLE ARTIFACT COLLECTION
# ============================================================

def collect_artifact(
    paths: DatasetPaths,
    artifact: Path,
    label: str,
) -> Optional[bool]:

    package = artifact_package_name(artifact)
    version = artifact_version(artifact)

    print()
    print("=" * 80)
    print(f"[{label}]")
    print(f"Package : {package}")

    if version:
        print(f"Version : {version}")

    print(f"Artifact: {artifact}")
    print("=" * 80)

    # --------------------------------------------------------
    # Create disposable environment.
    # --------------------------------------------------------

    python_path = create_temp_venv()

    if python_path is None:

        warning(
            "Unable to create disposable environment."
        )

        return None

    # --------------------------------------------------------
    # Select class-specific directories.
    # --------------------------------------------------------

    if label.upper() == "MALICIOUS":

        trace_dir = paths.malware_trace_dir
        output_path = paths.malware_output

    else:

        trace_dir = paths.benign_trace_dir
        output_path = paths.benign_output

    trace_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # --------------------------------------------------------
    # Final trace filename.
    #
    # IMPORTANT:
    # The final trace does NOT exist until the package
    # successfully completes.
    # --------------------------------------------------------

    trace_name = artifact.name + ".jsonl"

    final_trace_path = (
        trace_dir /
        trace_name
    )

    # --------------------------------------------------------
    # Temporary trace directory.
    #
    # Monitor writes here first.
    # --------------------------------------------------------

    temp_trace_dir = (
        paths.root /
        ".tmp_traces"
    )

    temp_trace_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    temp_trace_path = (
        temp_trace_dir /
        trace_name
    )

    # --------------------------------------------------------
    # Remove stale files.
    # --------------------------------------------------------

    if temp_trace_path.exists():

        try:
            temp_trace_path.unlink()

        except Exception as exc:

            warning(
                f"Could not remove stale temporary trace "
                f"{temp_trace_path}: {exc}"
            )

    if final_trace_path.exists():

        try:
            final_trace_path.unlink()

        except Exception as exc:

            warning(
                f"Could not remove stale final trace "
                f"{final_trace_path}: {exc}"
            )

    try:

        # ====================================================
        # RUN MONITOR
        # ====================================================

        monitor_rc, event_count = (
            run_monitor_install(
                paths.monitor,
                package,
                python_path,
                artifact,
                temp_trace_path,
            )
        )

        time.sleep(
            POST_INSTALL_WAIT
        )

        # Re-count after monitor exits and flushes events.
        event_count = count_events(
            temp_trace_path
        )

        print()

        print(
            f"[+] pip/monitor return code: "
            f"{monitor_rc}"
        )

        print(
            f"[+] Events captured: "
            f"{event_count}"
        )

        # ====================================================
        # STRICT SUCCESS RULE
        #
        # ACCEPT ONLY:
        #
        #   returncode == 0
        #   AND
        #   events > 0
        #
        # Failed packages:
        #
        #   - no final trace
        #   - no JSONL events
        #
        # ====================================================

        if monitor_rc != 0:

            print(
                "[SKIP] Package installation failed."
            )

            print(
                "[+] Temporary trace will be deleted."
            )

            return False

        if event_count <= 0:

            print(
                "[SKIP] Installation succeeded "
                "but no behavioral events were captured."
            )

            print(
                "[+] Temporary trace will be deleted."
            )

            return False

        # ====================================================
        # LOAD TRACE
        # ====================================================

        events = load_events(
            temp_trace_path
        )

        if not events:

            print(
                "[SKIP] Trace contains "
                "no valid JSON events."
            )

            return False

        # ====================================================
        # ADD PACKAGE METADATA
        # ====================================================

        events = enrich_events(
            events,
            package,
            version,
            artifact,
            label,
        )

        if not events:

            print(
                "[SKIP] No events remained "
                "after enrichment."
            )

            return False

        # ====================================================
        # SAVE SUCCESSFUL OBSERVATION
        # ====================================================
        #
        # Only successful packages reach this point.
        # ====================================================

        append_jsonl(
            output_path,
            events,
        )

        # ====================================================
        # COMMIT TRACE
        # ====================================================
        #
        # Only now does the trace enter traces/.
        # ====================================================

        shutil.move(
            str(temp_trace_path),
            str(final_trace_path),
        )

        print()
        print(
            "[SUCCESS] Behavioral trace accepted."
        )

        print(
            f"[+] JSONL events: {len(events)}"
        )

        print(
            f"[+] Output: {output_path}"
        )

        print(
            f"[+] Trace: {final_trace_path}"
        )

        return True

    except Exception as exc:

        warning(
            f"Collector error for "
            f"{package} {version or ''}: {exc}"
        )

        return None

    finally:

        # ----------------------------------------------------
        # Failed packages leave no temporary trace.
        #
        # If shutil.move() succeeded, this path no longer
        # exists.
        # ----------------------------------------------------

        if temp_trace_path.exists():

            try:

                temp_trace_path.unlink()

            except Exception as exc:

                warning(
                    f"Could not remove temporary trace "
                    f"{temp_trace_path}: {exc}"
                )

        # ----------------------------------------------------
        # Always destroy disposable environment.
        # ----------------------------------------------------

        remove_temp_venv()


# ============================================================
# COLLECTION LOOP
# ============================================================

def collect_dataset(
    paths: DatasetPaths,
    artifacts: list[Path],
    label: str,
    limit: int,
) -> tuple[int, int, int]:

    total = min(
        len(artifacts),
        limit,
    )

    processed = 0
    successful = 0
    skipped = 0

    if total == 0:

        warning(
            f"No artifacts discovered for {label}."
        )

        return (
            0,
            0,
            0,
        )

    for index, artifact in enumerate(
        artifacts[:total],
        start=1,
    ):

        processed += 1

        print()
        print(
            "=" * 80
        )

        print(
            f"[{index}/{total}] {label}"
        )

        print(
            f"Package : "
            f"{artifact_package_name(artifact)}"
        )

        print(
            f"Artifact: {artifact}"
        )

        print(
            "=" * 80
        )

        result = collect_artifact(
            paths,
            artifact,
            label,
        )

        # ----------------------------------------------------
        # Successful package.
        # ----------------------------------------------------

        if result is True:

            successful += 1

        # ----------------------------------------------------
        # Actual package installation failure.
        # ----------------------------------------------------

        elif result is False:

            skipped += 1

        # ----------------------------------------------------
        # Collector/environment failure.
        #
        # STOP instead of falsely counting hundreds of
        # packages as skipped.
        # ----------------------------------------------------

        elif result is None:

            warning(
                "Collector environment failure detected."
            )

            warning(
                "Stopping collection to prevent "
                "incorrect dataset statistics."
            )

            break

        print()
        print(
            "-" * 90
        )

        print(
            f"{label} PROGRESS"
        )

        print(
            f"Processed : {processed}/{total}"
        )

        print(
            f"Successful: {successful}"
        )

        print(
            f"Skipped   : {skipped}"
        )

        print(
            "-" * 90
        )

    print()
    print(
        "=" * 80
    )

    print(
        f"{label} COMPLETE"
    )

    print(
        "=" * 80
    )

    print(
        f"Processed : {processed}"
    )

    print(
        f"Successful: {successful}"
    )

    print(
        f"Skipped   : {skipped}"
    )

    return (
        processed,
        successful,
        skipped,
    )


# ============================================================
# OUTPUT STATISTICS
# ============================================================

def jsonl_stats(
    path: Path,
) -> tuple[int, int]:

    records = 0
    events = 0

    if not path.exists():

        return (
            0,
            0,
        )

    try:

        with path.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as f:

            for line in f:

                if not line.strip():
                    continue

                try:

                    record = json.loads(
                        line
                    )

                    records += 1

                    if isinstance(
                        record,
                        dict,
                    ):

                        events += 1

                except json.JSONDecodeError:

                    continue

    except Exception:

        pass

    return (
        records,
        events,
    )


# ============================================================
# TRACE STATISTICS
# ============================================================

def trace_stats(
    trace_dir: Path,
) -> tuple[int, int]:

    trace_files = 0
    total_events = 0

    if not trace_dir.exists():

        return (
            0,
            0,
        )

    for trace in trace_dir.glob("*.jsonl"):

        trace_files += 1

        total_events += count_events(
            trace
        )

    return (
        trace_files,
        total_events,
    )


# ============================================================
# ARGUMENTS
# ============================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "Collect behavioral traces from the "
            "Zenodo PyPI malware/benign datasets."
        )
    )

    parser.add_argument(
        "--root",
        type=Path,
        default=Path("/home/ubuntu/SCBF"),
        help="SCBF repository root.",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=MAX_ARTIFACTS_DEFAULT,
        help=(
            "Maximum number of artifacts "
            "to process for each selected class."
        ),
    )

    parser.add_argument(
        "--malicious-only",
        action="store_true",
        help="Collect only malicious packages.",
    )

    parser.add_argument(
        "--benign-only",
        action="store_true",
        help="Collect only benign packages.",
    )

    parser.add_argument(
        "--clean-extraction",
        action="store_true",
        help=(
            "Remove existing extraction directory "
            "for the selected dataset before extraction."
        ),
    )

    return parser.parse_args()


# ============================================================
# MAIN
# ============================================================

def main() -> int:

    args = parse_args()

    # --------------------------------------------------------
    # Validate arguments.
    # --------------------------------------------------------

    if args.limit <= 0:

        error(
            "--limit must be greater than zero."
        )

        return 2

    if (
        args.malicious_only
        and
        args.benign_only
    ):

        error(
            "--malicious-only and "
            "--benign-only cannot be used together."
        )

        return 2

    # --------------------------------------------------------
    # Dataset paths.
    # --------------------------------------------------------

    paths = DatasetPaths(
        args.root
    )

    paths.create_directories()

    # --------------------------------------------------------
    # Verify monitor.
    # --------------------------------------------------------

    if not paths.monitor.exists():

        error(
            f"SCBF monitor not found: {paths.monitor}"
        )

        error(
            "Expected monitor at:"
        )

        error(
            str(paths.monitor)
        )

        return 1

    # --------------------------------------------------------
    # Verify Python 3.12.
    # --------------------------------------------------------

    if not PYTHON312.exists():

        error(
            f"Python 3.12 executable not found: "
            f"{PYTHON312}"
        )

        return 1

    # --------------------------------------------------------
    # Verify Zenodo archives.
    # --------------------------------------------------------

    if not verify_dataset():

        return 1

    # --------------------------------------------------------
    # Inspect selected archives.
    # --------------------------------------------------------

    if not args.benign_only:

        inspect_archive(
            MALWARE_ZIP
        )

    if not args.malicious_only:

        inspect_archive(
            BENIGN_ZIP
        )

    # --------------------------------------------------------
    # Extract selected dataset.
    # --------------------------------------------------------

    if not extract_datasets(
        paths,
        args.clean_extraction,
        malware_only=args.malicious_only,
        benign_only=args.benign_only,
    ):

        return 1

    # --------------------------------------------------------
    # Discover artifacts.
    # --------------------------------------------------------

    malware_artifacts = []

    benign_artifacts = []

    if not args.benign_only:

        malware_artifacts = discover_artifacts(
            paths.malware_extract
        )

    if not args.malicious_only:

        benign_artifacts = discover_artifacts(
            paths.benign_extract
        )

    # --------------------------------------------------------
    # Collection: MALWARE
    # --------------------------------------------------------

    if not args.benign_only:

        section(
            "DISCOVERING MALICIOUS PACKAGES"
        )

        print(
            f"[+] Discovered package artifacts: "
            f"{len(malware_artifacts)}"
        )

        print(
            f"[+] Test limit: {args.limit}"
        )

        # ----------------------------------------------------
        # Clean old malware output only when requested.
        # ----------------------------------------------------

        if args.clean_extraction:

            clear_dataset_output(
                paths,
                "MALICIOUS",
            )

        collect_dataset(
            paths,
            malware_artifacts,
            "MALICIOUS",
            args.limit,
        )

    # --------------------------------------------------------
    # Collection: BENIGN
    # --------------------------------------------------------

    if not args.malicious_only:

        section(
            "DISCOVERING BENIGN PACKAGES"
        )

        print(
            f"[+] Discovered package artifacts: "
            f"{len(benign_artifacts)}"
        )

        print(
            f"[+] Test limit: {args.limit}"
        )

        # ----------------------------------------------------
        # Clean old benign output only when requested.
        # ----------------------------------------------------

        if args.clean_extraction:

            clear_dataset_output(
                paths,
                "BENIGN",
            )

        collect_dataset(
            paths,
            benign_artifacts,
            "BENIGN",
            args.limit,
        )

    # --------------------------------------------------------
    # Final statistics.
    # --------------------------------------------------------

    section(
        "ZENODO COLLECTION FINISHED"
    )

    print(
        f"[+] Malware output: "
        f"{paths.malware_output}"
    )

    print(
        f"[+] Benign output: "
        f"{paths.benign_output}"
    )

    # --------------------------------------------------------
    # Combined JSONL stats.
    # --------------------------------------------------------

    malware_records, malware_events = (
        jsonl_stats(
            paths.malware_output
        )
    )

    benign_records, benign_events = (
        jsonl_stats(
            paths.benign_output
        )
    )

    # --------------------------------------------------------
    # Individual trace stats.
    # --------------------------------------------------------

    malware_trace_files, malware_trace_events = (
        trace_stats(
            paths.malware_trace_dir
        )
    )

    benign_trace_files, benign_trace_events = (
        trace_stats(
            paths.benign_trace_dir
        )
    )

    print()

    print(
        f"[+] Malware JSONL records: "
        f"{malware_records}"
    )

    print(
        f"[+] Malware JSONL events: "
        f"{malware_events}"
    )

    print(
        f"[+] Malware individual trace files: "
        f"{malware_trace_files}"
    )

    print(
        f"[+] Malware trace events: "
        f"{malware_trace_events}"
    )

    print()

    print(
        f"[+] Benign JSONL records: "
        f"{benign_records}"
    )

    print(
        f"[+] Benign JSONL events: "
        f"{benign_events}"
    )

    print(
        f"[+] Benign individual trace files: "
        f"{benign_trace_files}"
    )

    print(
        f"[+] Benign trace events: "
        f"{benign_trace_events}"
    )

    print()

    print(
        "[+] Collection structure:"
    )

    print(
        f"    Malware traces: "
        f"{paths.malware_trace_dir}"
    )

    print(
        f"    Malware dataset: "
        f"{paths.malware_output}"
    )

    print(
        f"    Benign traces: "
        f"{paths.benign_trace_dir}"
    )

    print(
        f"    Benign dataset: "
        f"{paths.benign_output}"
    )

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        raise SystemExit(
            main()
        )

    except KeyboardInterrupt:

        print()

        warning(
            "Collection interrupted by user."
        )

        raise SystemExit(130)

    except Exception as exc:

        print()

        error(
            f"Fatal error: {exc}"
        )

        raise SystemExit(1)
