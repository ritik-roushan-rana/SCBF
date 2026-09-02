# test_pipeline.py — run captured data through the real pipeline
import json
from tgn_encoder import TGNEncoder
from itbg_constructor import ITBGConstructor

events = [json.loads(l) for l in open("data/data/clean/requests.jsonl")]
model = TGNEncoder(num_nodes=5000)
constructor = ITBGConstructor(model)

final_dna = constructor.replay_session(events)
print("Final DNA vector shape:", final_dna.shape)
print("Total nodes created:", constructor.node_ids.next_id)
