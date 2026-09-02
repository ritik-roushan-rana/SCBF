# cli.py
import argparse, shutil, os, torch, numpy as np
from tgn_encoder import TGNEncoder
from itbg_constructor import ITBGConstructor
from install_monitor import InstallMonitor

def load_model(num_nodes=50000, weights="tgn_v1.pt"):
    model = TGNEncoder(num_nodes=num_nodes)
    if os.path.exists(weights):
        model.load_state_dict(torch.load(weights))
    model.eval()
    return model

def score_against_envelope(dna_vector, envelope_path="envelope_pure_python.npy"):
    centroid = np.load(envelope_path)
    dna_np = dna_vector.detach().numpy()
    dist = float(np.linalg.norm(dna_np - centroid))
    # crude threshold logic for now — replace with the doc's
    # threat_score formula once you have real malicious distances to calibrate against
    if dist > 1.2:
        verdict = "BLOCK"
    elif dist > 0.7:
        verdict = "WARN"
    else:
        verdict = "ALLOW"
    return verdict, dist

def scan_package(pkg_name, target_dir="/tmp/scbf_sandbox"):
    shutil.rmtree(target_dir, ignore_errors=True)
    os.makedirs(target_dir, exist_ok=True)

    model = load_model()
    constructor = ITBGConstructor(model)
    events = []

    mon = InstallMonitor()
    mon.on_event = lambda e: events.append(e)
    mon.run_and_capture(
        ["pip", "install", f"--target={target_dir}", "--force-reinstall", pkg_name],
        duration_sec=25
    )

    if not events:
        print(f"WARNING: no events captured for {pkg_name} — check monitor/permissions")
        return

    final_dna = constructor.replay_session(events)
    verdict, dist = score_against_envelope(final_dna)

    print(f"\n=== SCBF Scan Report: {pkg_name} ===")
    print(f"Events captured : {len(events)}")
    print(f"Envelope distance: {dist:.4f}")
    print(f"Verdict         : {verdict}")
    return verdict

def main():
    parser = argparse.ArgumentParser(description="Supply Chain Behavioral Fingerprinting scanner")
    parser.add_argument("--package", required=True, help="Package name to scan")
    args = parser.parse_args()
    scan_package(args.package)

if __name__ == "__main__":
    main()
