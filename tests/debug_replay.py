# debug_replay.py
import json
from itbg_constructor import ITBGConstructor
from tgn_encoder import TGNEncoder

model = TGNEncoder(num_nodes=50000)
constructor = ITBGConstructor(model)

events = [json.loads(l) for l in open("data/data/clean/requests.jsonl")]
print(f"Total raw events: {len(events)}")

kept = 0
skipped_noise = 0
skipped_type = 0

for e in sorted(events, key=lambda x: x["ts"]):
    if constructor._is_noise(e):
        skipped_noise += 1
        continue
    if e["type"] not in ("exec", "open"):
        skipped_type += 1
        continue
    kept += 1

print(f"Kept: {kept}")
print(f"Skipped as noise: {skipped_noise}")
print(f"Skipped (unknown type): {skipped_type}")

dna = constructor.replay_session(events)
print(f"Final DNA: {'None' if dna is None else dna.shape}")
