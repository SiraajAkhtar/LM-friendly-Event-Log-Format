import argparse

from huggingface_hub import snapshot_download

import config

DOWNLOAD_KEYS = ["gemma-base", "bloomz", "phi3"]


def download(model_key: str):
    spec = config.MODEL_REGISTRY[model_key]
    if spec["hf_id"] is None:
        print(f"[{model_key}] no hf_id (local-only model) -- skipping download")
        return
    print(f"[{model_key}] downloading {spec['hf_id']} -> {spec['local_dir']} ...")
    spec["local_dir"].mkdir(parents=True, exist_ok=True)
    snapshot_download(
        repo_id=spec["hf_id"],
        local_dir=str(spec["local_dir"]),
        token=config.HF_TOKEN,
    )
    print(f"[{model_key}] done")


def smoke_test(model_key: str):
    from model_loader import build_prompt, generate, load_model

    print(f"[{model_key}] smoke test: loading + one generation ...")
    model, tokenizer = load_model(model_key)
    spec = config.MODEL_REGISTRY[model_key]
    prompt = build_prompt(spec["chat_style"], tokenizer, "18/8/26 13:34:36, test event, this is a smoke test entry")
    output = generate(model, tokenizer, prompt)
    print(f"[{model_key}] output: {output[:200]!r}")
    del model
    import gc
    import torch
    gc.collect()
    torch.cuda.empty_cache()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", choices=DOWNLOAD_KEYS, default=None,
                         help="download just this one model (default: all 3)")
    parser.add_argument("--skip-smoke-test", action="store_true")
    args = parser.parse_args()

    keys = [args.model] if args.model else DOWNLOAD_KEYS
    for key in keys:
        download(key)

    if not args.skip_smoke_test:
        for key in keys:
            smoke_test(key)

    print("\nAll requested models ready.")


if __name__ == "__main__":
    main()
