"""
Validate SCBF dataset integrity and format.

This script checks:
1. Directory structure exists
2. JSONL format is valid
3. Required event fields are present
4. Event types are correct (exec, open, connect only)
5. Data consistency (timestamps, PIDs, package metadata)
6. Reports statistics

Usage:
    python scripts/validate_dataset.py
"""

import json
from pathlib import Path
from collections import defaultdict, Counter


class DatasetValidator:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.stats = defaultdict(int)
        self.event_types = Counter()
        self.packages = set()
        
    def add_error(self, msg):
        """Add validation error."""
        self.errors.append(msg)
        print(f"  ❌ ERROR: {msg}")
    
    def add_warning(self, msg):
        """Add validation warning."""
        self.warnings.append(msg)
        print(f"  ⚠️  WARNING: {msg}")
    
    def validate_structure(self):
        """Validate directory structure exists."""
        print("\n📁 Validating directory structure...")
        
        required_dirs = [
            "data/zenodo_13746167",
            "data/zenodo_13746167/benign/data",
            "data/zenodo_13746167/benign/traces",
            "data/zenodo_13746167/malware/data",
            "data/zenodo_13746167/malware/traces",
        ]
        
        for dir_path in required_dirs:
            path = Path(dir_path)
            if not path.exists():
                self.add_error(f"Missing directory: {dir_path}")
            else:
                print(f"  ✓ {dir_path}")
        
        return len(self.errors) == 0
    
    def validate_jsonl_file(self, filepath, label):
        """Validate a single JSONL file."""
        print(f"\n📄 Validating {filepath}...")
        
        if not filepath.exists():
            self.add_error(f"File does not exist: {filepath}")
            return False
        
        line_num = 0
        prev_pkg_ts = {}  # Track last timestamp per package
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line_num += 1
                    line = line.strip()
                    
                    if not line:
                        continue
                    
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError as e:
                        self.add_error(f"Line {line_num}: Invalid JSON - {e}")
                        continue
                    
                    # Validate event
                    self.validate_event(event, filepath.name, line_num, label, prev_pkg_ts)
                    
                    # Update stats
                    self.stats[f"{label}_events"] += 1
                    self.event_types[event.get("type", "unknown")] += 1
                    
                    pkg_key = f"{event.get('package', 'unknown')}-{event.get('version', 'unknown')}"
                    self.packages.add((pkg_key, label))
        
        except Exception as e:
            self.add_error(f"Failed to read {filepath}: {e}")
            return False
        
        print(f"  ✓ Validated {line_num} lines")
        return True
    
    def validate_event(self, event, filename, line_num, label, prev_pkg_ts):
        """Validate single event."""
        # Check required fields
        required_fields = ["type", "pid", "ts"]
        for field in required_fields:
            if field not in event:
                self.add_error(f"{filename}:{line_num} - Missing required field '{field}'")
        
        # Check event type
        event_type = event.get("type")
        valid_types = ["exec", "open", "connect"]
        if event_type not in valid_types:
            self.add_error(f"{filename}:{line_num} - Invalid event type '{event_type}' (must be one of {valid_types})")
        
        # Check PID
        pid = event.get("pid")
        if pid is not None:
            if not isinstance(pid, int) or pid <= 0:
                self.add_error(f"{filename}:{line_num} - Invalid PID: {pid} (must be positive integer)")
        
        # Check timestamp
        ts = event.get("ts")
        if ts is not None:
            if not isinstance(ts, (int, float)) or ts <= 0:
                self.add_error(f"{filename}:{line_num} - Invalid timestamp: {ts} (must be positive number)")
            
            # Check monotonic timestamps within package
            pkg_key = f"{event.get('package', 'unknown')}-{event.get('version', 'unknown')}"
            if pkg_key in prev_pkg_ts:
                if ts < prev_pkg_ts[pkg_key]:
                    self.add_warning(f"{filename}:{line_num} - Non-monotonic timestamp for {pkg_key}")
            prev_pkg_ts[pkg_key] = ts
        
        # Check exec-specific fields
        if event_type == "exec":
            if "ppid" not in event:
                self.add_warning(f"{filename}:{line_num} - Exec event missing 'ppid'")
            if "comm" not in event:
                self.add_warning(f"{filename}:{line_num} - Exec event missing 'comm'")
        
        # Check open/connect-specific fields
        if event_type in ["open", "connect"]:
            if "fname" not in event:
                self.add_warning(f"{filename}:{line_num} - {event_type} event missing 'fname'")
        
        # Check package metadata
        if "package" not in event:
            self.add_warning(f"{filename}:{line_num} - Missing package metadata")
        
        # Check label
        if "label" not in event:
            self.add_warning(f"{filename}:{line_num} - Missing label")
        else:
            event_label = event["label"]
            # Accept both string and numeric labels (case-insensitive)
            # 0/"benign"/"BENIGN" for benign, 1/"malicious"/"MALICIOUS" for malicious
            if label == "benign":
                valid = event_label in [0, "0", "benign", "BENIGN"]
            else:  # malicious
                valid = event_label in [1, "1", "malicious", "MALICIOUS"]
            
            if not valid:
                self.add_error(f"{filename}:{line_num} - Invalid label: got '{event_label}', expected label compatible with '{label}'")
        
        # Check for unexpected fields (network destination info)
        unexpected_fields = ["dst_ip", "dst_port", "hostname", "dns", "url"]
        for field in unexpected_fields:
            if field in event:
                self.add_error(f"{filename}:{line_num} - Unexpected field '{field}' (not part of SCBF schema)")
    
    def validate_traces(self, traces_dir, label):
        """Validate individual trace files."""
        print(f"\n📂 Validating {label} traces...")
        
        traces_path = Path(traces_dir)
        if not traces_path.exists():
            self.add_error(f"Traces directory does not exist: {traces_dir}")
            return False
        
        trace_files = list(traces_path.glob("*.jsonl"))
        print(f"  Found {len(trace_files)} trace files")
        
        self.stats[f"{label}_trace_files"] = len(trace_files)
        
        # Check for empty traces
        empty_traces = []
        for trace_file in trace_files:
            if trace_file.stat().st_size == 0:
                empty_traces.append(trace_file.name)
        
        if empty_traces:
            self.add_warning(f"Found {len(empty_traces)} empty trace files")
            for name in empty_traces[:5]:
                print(f"    - {name}")
            if len(empty_traces) > 5:
                print(f"    ... and {len(empty_traces) - 5} more")
        
        return True
    
    def print_summary(self):
        """Print validation summary."""
        print("\n" + "="*80)
        print("VALIDATION SUMMARY")
        print("="*80)
        
        # Dataset statistics
        print("\n📊 Dataset Statistics")
        print(f"  Benign packages: {sum(1 for _, lbl in self.packages if lbl == 'benign')}")
        print(f"  Malware packages: {sum(1 for _, lbl in self.packages if lbl == 'malicious')}")
        print(f"  Total unique packages: {len(self.packages)}")
        
        print(f"\n  Benign events: {self.stats.get('benign_events', 0):,}")
        print(f"  Malware events: {self.stats.get('malicious_events', 0):,}")
        print(f"  Total events: {sum(self.event_types.values()):,}")
        
        benign_files = self.stats.get('benign_trace_files', 0)
        malware_files = self.stats.get('malicious_trace_files', 0)
        print(f"\n  Benign trace files: {benign_files}")
        print(f"  Malware trace files: {malware_files}")
        print(f"  Total trace files: {benign_files + malware_files}")
        
        # Event type distribution
        print("\n📈 Event Type Distribution")
        total_events = sum(self.event_types.values())
        for event_type, count in self.event_types.most_common():
            pct = 100.0 * count / total_events if total_events > 0 else 0
            print(f"  {event_type}: {count:,} ({pct:.1f}%)")
        
        # Average events per package
        if self.packages:
            benign_pkgs = sum(1 for _, lbl in self.packages if lbl == 'benign')
            malware_pkgs = sum(1 for _, lbl in self.packages if lbl == 'malicious')
            
            if benign_pkgs > 0:
                avg_benign = self.stats.get('benign_events', 0) / benign_pkgs
                print(f"\n  Avg events/benign package: {avg_benign:.1f}")
            
            if malware_pkgs > 0:
                avg_malware = self.stats.get('malicious_events', 0) / malware_pkgs
                print(f"  Avg events/malware package: {avg_malware:.1f}")
        
        # Validation results
        print("\n🔍 Validation Results")
        print(f"  Errors: {len(self.errors)}")
        print(f"  Warnings: {len(self.warnings)}")
        
        if self.errors:
            print(f"\n❌ Errors ({len(self.errors)}):")
            for error in self.errors[:10]:
                print(f"  - {error}")
            if len(self.errors) > 10:
                print(f"  ... and {len(self.errors) - 10} more")
        
        if self.warnings:
            print(f"\n⚠️  Warnings ({len(self.warnings)}):")
            for warning in self.warnings[:10]:
                print(f"  - {warning}")
            if len(self.warnings) > 10:
                print(f"  ... and {len(self.warnings) - 10} more")
        
        # Final verdict
        print("\n" + "="*80)
        if len(self.errors) == 0:
            print("✅ DATASET VALIDATION PASSED")
            print("\nNext steps:")
            print("  sudo make train-split")
        else:
            print("❌ DATASET VALIDATION FAILED")
            print(f"\nFound {len(self.errors)} errors. Fix them before training.")
        print("="*80)
        
        return len(self.errors) == 0


def main():
    """Main validation workflow."""
    print("="*80)
    print("SCBF Dataset Validation")
    print("="*80)
    
    validator = DatasetValidator()
    
    # Validate structure
    if not validator.validate_structure():
        print("\n❌ Structure validation failed. Run aggregation first:")
        print("  python scripts/aggregate_jsonl.py")
        return
    
    # Validate benign dataset
    validator.validate_jsonl_file(
        Path("data/zenodo_13746167/benign/data/benign.jsonl"),
        "benign"
    )
    validator.validate_traces(
        "data/zenodo_13746167/benign/traces",
        "benign"
    )
    
    # Validate malware dataset
    validator.validate_jsonl_file(
        Path("data/zenodo_13746167/malware/data/malware.jsonl"),
        "malicious"
    )
    validator.validate_traces(
        "data/zenodo_13746167/malware/traces",
        "malicious"
    )
    
    # Print summary
    success = validator.print_summary()
    
    # Exit with appropriate code
    exit(0 if success else 1)


if __name__ == "__main__":
    main()
