import os
import sys
import time
import subprocess

import torch
from datasets import load_dataset
from transformers import (
    AutoModelForImageTextToText,
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    TrainingArguments,
    Trainer,
)
from peft import LoraConfig, get_peft_model, PeftModel, prepare_model_for_kbit_training
from transformers.trainer_utils import get_last_checkpoint

# config
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_NAME = os.environ.get("MODEL_NAME", "google/gemma-3-4b-it")
DATASET_FILE = os.environ.get("DATASET_FILE", os.path.join(SCRIPT_DIR, "gemma_windows_log_dataset.jsonl"))
OUTPUT_DIR = os.environ.get("OUTPUT_DIR", os.path.join(SCRIPT_DIR, "gemma3-4b-lora-output"))


HF_TOKEN = os.environ.get("HF_TOKEN")
HF_AUTH = HF_TOKEN if HF_TOKEN else True


BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "1"))
GRAD_ACCUM_STEPS = int(os.environ.get("GRAD_ACCUM_STEPS", "8"))
EPOCHS = int(os.environ.get("EPOCHS", "3"))
MAX_LENGTH = int(os.environ.get("MAX_LENGTH", "384"))

start_time = time.time()

# tokenizer and model load
print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, token=HF_AUTH)

if tokenizer.pad_token is None:
    tokenizer.add_special_tokens({"pad_token": tokenizer.eos_token})

compute_dtype = torch.bfloat16 if torch.cuda.is_bf16_supported() else torch.float16

bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=compute_dtype,
    bnb_4bit_use_double_quant=True,
)

print(f"Loading {MODEL_NAME} in 4-bit (compute dtype={compute_dtype})...")
try:
    model = AutoModelForImageTextToText.from_pretrained(
        MODEL_NAME,
        quantization_config=bnb_config,
        device_map="auto",
        token=HF_AUTH,
    )
except Exception:
    # fallback for text-only checkpoints
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        quantization_config=bnb_config,
        device_map="auto",
        token=HF_AUTH,
    )

model = prepare_model_for_kbit_training(model)

# lora config
print("Configuring LoRA...")
lora_config = LoraConfig(
    r=16,
    lora_alpha=32,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)

model = get_peft_model(model, lora_config)
model.print_trainable_parameters()

# dataset formatting
print(f"Loading dataset from {DATASET_FILE}...")
dataset = load_dataset("json", data_files=DATASET_FILE)

def format_example(example):
    messages = example.get("messages", [])
    system_msg = next((m["content"] for m in messages if m["role"] == "system"), "")
    user_msg = next((m["content"] for m in messages if m["role"] == "user"), "")
    model_msg = next((m["content"] for m in messages if m["role"] == "model"), "")

    
    prompt_text = f"<start_of_turn>user\n{system_msg}\n\n{user_msg}<end_of_turn>\n<start_of_turn>model\n"
    response_text = f"{model_msg}<end_of_turn>\n"

    prompt_ids = tokenizer(prompt_text, add_special_tokens=True, truncation=True, max_length=MAX_LENGTH)["input_ids"]
    response_ids = tokenizer(response_text, add_special_tokens=False, truncation=True, max_length=MAX_LENGTH)["input_ids"]

    input_ids = (prompt_ids + response_ids)[:MAX_LENGTH]
    # loss only on model response
    labels = ([-100] * len(prompt_ids) + response_ids)[:MAX_LENGTH]

    pad_len = MAX_LENGTH - len(input_ids)
    attention_mask = [1] * len(input_ids) + [0] * pad_len
    input_ids = input_ids + [tokenizer.pad_token_id] * pad_len
    labels = labels + [-100] * pad_len

    return {"input_ids": input_ids, "attention_mask": attention_mask, "labels": labels}

print("Tokenizing...")
tokenized_dataset = dataset["train"].map(
    format_example,
    remove_columns=dataset["train"].column_names,
)

# trainer setup
print("Setting up Trainer...")
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    per_device_train_batch_size=BATCH_SIZE,
    gradient_accumulation_steps=GRAD_ACCUM_STEPS,
    num_train_epochs=EPOCHS,
    learning_rate=2e-4,
    logging_steps=10,
    save_strategy="steps",
    save_steps=50,
    save_total_limit=3,  # keep disk usage bounded 
    bf16=(compute_dtype == torch.bfloat16),
    fp16=(compute_dtype == torch.float16),
    optim="adamw_torch",
    gradient_checkpointing=True,
    gradient_checkpointing_kwargs={"use_reentrant": False},
    dataloader_num_workers=0,  # safer default on Windows
    report_to="none",
)

trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_dataset,
)

# resume from last checkpoint
last_checkpoint = get_last_checkpoint(OUTPUT_DIR) if os.path.isdir(OUTPUT_DIR) else None
if last_checkpoint:
    print(f"Found existing checkpoint, resuming from: {last_checkpoint}")
else:
    print("No existing checkpoint found, starting training from scratch.")

trainer.train(resume_from_checkpoint=last_checkpoint)

# save adapter
adapter_path = os.path.join(OUTPUT_DIR, "lora-adapter")
os.makedirs(adapter_path, exist_ok=True)

print("Saving LoRA adapter...")
model.save_pretrained(adapter_path)
tokenizer.save_pretrained(adapter_path)

print("Loading base model on CPU for merge...")
try:
    base_model = AutoModelForImageTextToText.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float32,
        device_map={"": "cpu"},
        token=HF_AUTH,
    )
except Exception:
    base_model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME,
        torch_dtype=torch.float32,
        device_map={"": "cpu"},
        token=HF_AUTH,
    )

print("Applying LoRA weights...")
lora_model = PeftModel.from_pretrained(base_model, adapter_path, device_map={"": "cpu"})

print("Merging...")
merged = lora_model.merge_and_unload()
merged = merged.half()  


lm_head = merged.get_output_embeddings()
lm_head.weight = torch.nn.Parameter(lm_head.weight.detach().clone())
merged.config.tie_word_embeddings = False

merged_dir = os.path.join(OUTPUT_DIR, "merged-model")
os.makedirs(merged_dir, exist_ok=True)

print("Saving merged model...")
merged.save_pretrained(merged_dir, safe_serialization=True)
tokenizer.save_pretrained(merged_dir)

# gguf export
convert_script = os.path.join("llama.cpp", "convert_hf_to_gguf.py")
quant_bin = os.path.join("llama.cpp", "build", "bin", "llama-quantize.exe" if os.name == "nt" else "llama-quantize")

gguf_out = os.path.join(OUTPUT_DIR, "gemma3-4b.gguf")
gguf_q = os.path.join(OUTPUT_DIR, "gemma3-4b-q4.gguf")

try:
    if os.path.exists(convert_script):
        subprocess.run([
            sys.executable, convert_script, merged_dir,
            "--outtype", "f16",
            "--outfile", gguf_out,
        ], check=True)

    if os.path.exists(quant_bin) and os.path.exists(gguf_out):
        subprocess.run([quant_bin, gguf_out, gguf_q, "Q4_K_M"], check=True)

except Exception as e:
    print("GGUF conversion failed:", str(e))

print(f"Finished in {(time.time() - start_time) / 60:.2f} minutes.")
