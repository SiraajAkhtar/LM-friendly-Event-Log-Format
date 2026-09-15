import os
import re

import torch
from peft import PeftModel
from transformers import (
    AutoModelForCausalLM,
    AutoModelForImageTextToText,
    AutoTokenizer,
    BitsAndBytesConfig,
)

import config

SYSTEM_INSTRUCTION = (
    "You are a Windows event log analyst. Given a single Windows event log "
    "entry, identify the problem and explain how to resolve it."
)


OUTPUT_FORMAT_INSTRUCTION = (
    "Your response must ALWAYS follow this exact format and nothing else:\n\n"
    "Problem Identified: <short description of the issue, or 'No issues found'>\n"
    "How to resolve: <step-by-step actions to fix it, or 'No action needed'>\n\n"
    "Do NOT include the input log in your answer. Do NOT repeat or reformat "
    "the log's fields. Do NOT add any extra commentary, explanations, "
    "headers, or sections."
)

MAX_NEW_TOKENS = int(os.environ.get("MAX_NEW_TOKENS", "180"))
MAX_INPUT_TOKENS = int(os.environ.get("MAX_INPUT_TOKENS", "1024"))


_TRAILING_JUNK = re.compile(
    r"(\n\s*\n|\n\s*[*#-]|\n\s*\d+\.|\*\*Event\b|\*\*Timestamp\b)", re.IGNORECASE
)

_HOW_TO_RESOLVE = re.compile(r"How to resolve:", re.IGNORECASE)


def _trim_to_answer(text: str) -> str:
    search_from = 0
    how_to_resolve = _HOW_TO_RESOLVE.search(text)
    if how_to_resolve:
        search_from = how_to_resolve.end()
    match = _TRAILING_JUNK.search(text, search_from)
    if match:
        text = text[: match.start()]
    return text.strip()


_RESERVED_WRAPPER_TOKENS = 220


def _truncate_entry_for_budget(tokenizer, entry_text: str, max_tokens: int) -> str:
    ids = tokenizer(entry_text, add_special_tokens=False)["input_ids"]
    if len(ids) <= max_tokens:
        return entry_text
    return tokenizer.decode(ids[:max_tokens], skip_special_tokens=True)


def build_prompt(chat_style: str, tokenizer, entry_text: str) -> str:
    instruction = f"{SYSTEM_INSTRUCTION} {OUTPUT_FORMAT_INSTRUCTION}"
    entry_budget = MAX_INPUT_TOKENS - _RESERVED_WRAPPER_TOKENS
    user_content = _truncate_entry_for_budget(tokenizer, entry_text, entry_budget)

    if chat_style == "gemma":
        return (
            f"<start_of_turn>user\n{instruction}\n\n{user_content}<end_of_turn>\n"
            f"<start_of_turn>model\n"
        )
    if chat_style == "chat_template":
        messages = [
            {"role": "system", "content": instruction},
            {"role": "user", "content": user_content},
        ]
        return tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
    return f"{instruction}\n\n{user_content}\n\nProblem Identified:"


def _bnb_config():
    compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16
    return BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=compute_dtype,
        bnb_4bit_use_double_quant=True,
    )


def _load_base_causal_lm(source, chat_style, trust_remote_code):
    load_kwargs = dict(
        quantization_config=_bnb_config(),
        device_map="auto",
        token=config.HF_TOKEN,
        trust_remote_code=trust_remote_code,
    )
    if chat_style == "gemma":
        try:
            return AutoModelForImageTextToText.from_pretrained(source, **load_kwargs)
        except Exception:
            return AutoModelForCausalLM.from_pretrained(source, **load_kwargs)
    return AutoModelForCausalLM.from_pretrained(source, **load_kwargs)


def load_model(model_key: str):
    spec = config.MODEL_REGISTRY[model_key]

    if spec.get("is_adapter"):
        adapter_dir = spec["local_dir"]
        if not adapter_dir.exists():
            raise FileNotFoundError(
                f"{model_key}: adapter dir {adapter_dir} not found -- does "
                "GEMMA_FINETUNED_DIR point at the lora-adapter folder "
                "(not merged-model)?"
            )
        base_spec = config.MODEL_REGISTRY["gemma-base"]
        base_source = base_spec["local_dir"] if base_spec["local_dir"].exists() else base_spec["hf_id"]

        print(f"[{model_key}] loading base from {base_source}, adapter from {adapter_dir} ...")
        tokenizer = AutoTokenizer.from_pretrained(str(adapter_dir), token=config.HF_TOKEN)
        if tokenizer.pad_token is None:
            tokenizer.add_special_tokens({"pad_token": tokenizer.eos_token})

        base_model = _load_base_causal_lm(base_source, spec["chat_style"], spec["trust_remote_code"])
        model = PeftModel.from_pretrained(base_model, str(adapter_dir))
        model.eval()
        return model, tokenizer

    source = spec["local_dir"] if spec["local_dir"].exists() else spec["hf_id"]
    if source is None:
        raise FileNotFoundError(
            f"{model_key}: local dir {spec['local_dir']} not found and there's no "
            "hf_id to fall back to."
        )

    print(f"[{model_key}] loading from {source} ...")
    tokenizer = AutoTokenizer.from_pretrained(
        source, token=config.HF_TOKEN, trust_remote_code=spec["trust_remote_code"]
    )
    if tokenizer.pad_token is None:
        tokenizer.add_special_tokens({"pad_token": tokenizer.eos_token})

    model = _load_base_causal_lm(source, spec["chat_style"], spec["trust_remote_code"])
    model.eval()
    return model, tokenizer


@torch.no_grad()
def generate(model, tokenizer, prompt: str) -> str:
    device = next(model.parameters()).device
    inputs = tokenizer(
        prompt, return_tensors="pt", truncation=True, max_length=MAX_INPUT_TOKENS
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}
    input_len = inputs["input_ids"].shape[1]

    outputs = model.generate(
        **inputs,
        max_new_tokens=MAX_NEW_TOKENS,
        min_new_tokens=16,
        do_sample=False,
        repetition_penalty=1.1,
        use_cache=True,
        pad_token_id=tokenizer.pad_token_id,
    )
    new_tokens = outputs[0][input_len:]
    text = tokenizer.decode(new_tokens, skip_special_tokens=True).strip()
    if prompt.rstrip().endswith("Problem Identified:"):
        text = f"Problem Identified: {text}"
    return _trim_to_answer(text)
