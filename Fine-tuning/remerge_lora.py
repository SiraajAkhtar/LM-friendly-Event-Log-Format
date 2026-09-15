import argparse
import os

import torch
from transformers import AutoModelForCausalLM, AutoModelForImageTextToText, AutoTokenizer
from peft import PeftModel

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_NAME = os.environ.get("MODEL_NAME", "google/gemma-3-4b-it")
HF_TOKEN = os.environ.get("HF_TOKEN")
HF_AUTH = HF_TOKEN if HF_TOKEN else True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--adapter-dir", default=os.path.join(SCRIPT_DIR, "gemma3-4b-lora-output", "lora-adapter"))
    parser.add_argument("--out-dir", default=os.path.join(SCRIPT_DIR, "gemma3-4b-lora-output", "merged-model-fixed"))
    args = parser.parse_args()

    print(f"Loading base model ({MODEL_NAME}) on CPU in fp32 ...")
    try:
        base_model = AutoModelForImageTextToText.from_pretrained(
            MODEL_NAME, torch_dtype=torch.float32, device_map={"": "cpu"}, token=HF_AUTH
        )
    except Exception:
        base_model = AutoModelForCausalLM.from_pretrained(
            MODEL_NAME, torch_dtype=torch.float32, device_map={"": "cpu"}, token=HF_AUTH
        )

    tokenizer = AutoTokenizer.from_pretrained(args.adapter_dir, token=HF_AUTH)

    print(f"Applying LoRA adapter from {args.adapter_dir} ...")
    lora_model = PeftModel.from_pretrained(base_model, args.adapter_dir, device_map={"": "cpu"})

    print("Merging (fp32) ...")
    merged = lora_model.merge_and_unload()
    merged = merged.half()


    lm_head = merged.get_output_embeddings()
    lm_head.weight = torch.nn.Parameter(lm_head.weight.detach().clone())
    merged.config.tie_word_embeddings = False

    os.makedirs(args.out_dir, exist_ok=True)
    print(f"Saving fixed merged model to {args.out_dir} ...")
    merged.save_pretrained(args.out_dir, safe_serialization=True)
    tokenizer.save_pretrained(args.out_dir)
    print("Done.")


if __name__ == "__main__":
    main()
