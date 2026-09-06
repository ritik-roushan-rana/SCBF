"""
Verify if malicious traces represent SUCCESSFUL or FAILED installations.

Checks for signs of successful install completion:
- Package files written to site-packages
- setup.py/pyproject.toml execution completed
- .dist-info or .egg-info directory created
- Final "Successfully installed" indicators
- pip cleanup files

vs signs of FAILED installation:
- Truncated trace
- No site-packages writes
- Killed before setup.py runs
- No dist-info directory
"""

import json
import glob
import os
from collections import Counter


def load_events(path):
    with open(path, 'r') as f:
        return [json.loads(line) for line in f]


def check_install_completion(events, package_name):
    """Check if this trace shows a completed installation."""
    n_events = len(events)
    
    # Look for install completion indicators
    completion_signals = {
        'has_site_packages_write': False,
        'has_dist_info': False,
        'has_egg_info': False,
        'has_setup_py_run': False,
        'has_pip_cleanup': False,
        'ran_package_code': False,
        'has_metadata_write': False,
        'has_wheel_install': False,
    }
    
    paths = [e.get('fname', '') for e in events if e.get('fname')]
    comms = [e.get('comm', '') for e in events]
    
    # Check for signs of completion
    for path in paths:
        if 'site-packages' in path and not '.pyenv' in path:
            completion_signals['has_site_packages_write'] = True
        if '.dist-info' in path:
            completion_signals['has_dist_info'] = True
        if '.egg-info' in path:
            completion_signals['has_egg_info'] = True
        if 'setup.py' in path:
            completion_signals['has_setup_py_run'] = True
        if 'pip-tmp' in path or 'pip-cache' in path:
            completion_signals['has_pip_cleanup'] = True
        if 'METADATA' in path or 'PKG-INFO' in path:
            completion_signals['has_metadata_write'] = True
        if '.whl' in path or 'wheel' in path.lower():
            completion_signals['has_wheel_install'] = True
    
    # Check if package code ran
    package_short = package_name.split('-')[0].replace('_', '').lower()
    for path in paths[-100:]:  # Last 100 events
        if package_short in path.lower() and 'site-packages' in path:
            completion_signals['ran_package_code'] = True
            break
    
    return completion_signals, n_events


def analyze_dataset(traces_dir, label):
    """Analyze all traces in a directory."""
    print(f"\n{'=' * 80}")
    print(f"ANALYZING {label.upper()} TRACES")
    print(f"{'=' * 80}")
    
    files = glob.glob(f"{traces_dir}/*.jsonl")
    print(f"Total traces: {len(files)}")
    
    stats = {
        'total': 0,
        'has_site_packages': 0,
        'has_dist_info': 0,
        'has_setup_py': 0,
        'has_metadata': 0,
        'has_wheel': 0,
        'ran_package_code': 0,
        'appears_successful': 0,
        'appears_failed': 0,
    }
    
    event_counts = []
    
    for i, path in enumerate(files):
        if (i + 1) % 100 == 0:
            print(f"  Analyzed {i + 1}/{len(files)}...")
        
        try:
            events = load_events(path)
            package_name = os.path.basename(path).replace('.tar.gz.jsonl', '')
            
            signals, n = check_install_completion(events, package_name)
            event_counts.append(n)
            
            stats['total'] += 1
            if signals['has_site_packages_write']:
                stats['has_site_packages'] += 1
            if signals['has_dist_info']:
                stats['has_dist_info'] += 1
            if signals['has_setup_py_run']:
                stats['has_setup_py'] += 1
            if signals['has_metadata_write']:
                stats['has_metadata'] += 1
            if signals['has_wheel_install']:
                stats['has_wheel'] += 1
            if signals['ran_package_code']:
                stats['ran_package_code'] += 1
            
            # Determine if successful
            success_count = sum([
                signals['has_site_packages_write'],
                signals['has_dist_info'] or signals['has_egg_info'],
                signals['has_metadata_write'],
            ])
            
            if success_count >= 2:
                stats['appears_successful'] += 1
            else:
                stats['appears_failed'] += 1
        
        except Exception as e:
            continue
    
    print(f"\n📊 STATISTICS FOR {label.upper()}:")
    print(f"  Total analyzed: {stats['total']}")
    print(f"  Event count: mean={sum(event_counts)/len(event_counts):.0f}, "
          f"min={min(event_counts)}, max={max(event_counts)}")
    
    print(f"\n  Install completion signals:")
    print(f"    Has site-packages writes:   {stats['has_site_packages']}/{stats['total']} ({stats['has_site_packages']/stats['total']:.1%})")
    print(f"    Has .dist-info directory:   {stats['has_dist_info']}/{stats['total']} ({stats['has_dist_info']/stats['total']:.1%})")
    print(f"    Has setup.py execution:     {stats['has_setup_py']}/{stats['total']} ({stats['has_setup_py']/stats['total']:.1%})")
    print(f"    Has METADATA/PKG-INFO:      {stats['has_metadata']}/{stats['total']} ({stats['has_metadata']/stats['total']:.1%})")
    print(f"    Has wheel install:          {stats['has_wheel']}/{stats['total']} ({stats['has_wheel']/stats['total']:.1%})")
    print(f"    Ran package code:           {stats['ran_package_code']}/{stats['total']} ({stats['ran_package_code']/stats['total']:.1%})")
    
    print(f"\n  Installation outcome:")
    print(f"    ✅ Appears SUCCESSFUL:  {stats['appears_successful']}/{stats['total']} ({stats['appears_successful']/stats['total']:.1%})")
    print(f"    ❌ Appears FAILED:      {stats['appears_failed']}/{stats['total']} ({stats['appears_failed']/stats['total']:.1%})")
    
    return stats


def main():
    print("=" * 80)
    print("INSTALLATION SUCCESS/FAILURE VERIFICATION")
    print("=" * 80)
    print("\nChecking if traces represent SUCCESSFUL or FAILED installations...")
    
    clean_stats = analyze_dataset(
        "data/zenodo_13746167/benign/traces", 
        "CLEAN"
    )
    
    mal_stats = analyze_dataset(
        "data/zenodo_13746167/malware/traces",
        "MALICIOUS"
    )
    
    # Compare
    print("\n" + "=" * 80)
    print("COMPARISON")
    print("=" * 80)
    
    clean_success = clean_stats['appears_successful'] / clean_stats['total']
    mal_success = mal_stats['appears_successful'] / mal_stats['total']
    
    print(f"\n{'Metric':<35} {'Clean':<15} {'Malicious':<15}")
    print("-" * 65)
    print(f"{'Installation appears successful':<35} {clean_success:.1%}          {mal_success:.1%}")
    
    for key in ['has_site_packages', 'has_dist_info', 'has_setup_py', 'has_metadata', 'ran_package_code']:
        c = clean_stats[key] / clean_stats['total']
        m = mal_stats[key] / mal_stats['total']
        print(f"{key.replace('_', ' ').title():<35} {c:.1%}          {m:.1%}")
    
    # Final verdict
    print("\n" + "=" * 80)
    print("VERDICT")
    print("=" * 80)
    
    if mal_success > 0.5:
        print(f"""
✅ SUCCESSFUL MALWARE INSTALLS: {mal_success:.1%}

Malicious packages ARE installing successfully in this dataset!
The traces contain post-install activity, so behavioral detection is possible.
""")
    elif mal_success > 0.2:
        print(f"""
⚠️  MIXED: {mal_success:.1%} malicious installs appear successful

Some malicious packages install successfully, others fail.
Dataset has partial post-install behavior.
""")
    else:
        print(f"""
❌ MOSTLY FAILED MALWARE: Only {mal_success:.1%} appear successful

Most malicious traces represent FAILED installations.
The behavioral signal is dominated by install failures, not real malware behavior.
""")


if __name__ == "__main__":
    main()
