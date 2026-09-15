import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
CODE_DIR = SCRIPT_DIR.parent

# local weights cache 
MODELS_DIR = Path(os.environ.get("MODELS_DIR", SCRIPT_DIR / "models"))

# 20-scenario path
RESULTS_DIR = Path(os.environ.get(
    "RESULTS_DIR",
    CODE_DIR / "Testing Script" / "dist" / "Results" / "With all tools",
))

# LoRA adapter diary
GEMMA_FINETUNED_DIR = Path(os.environ.get(
    "GEMMA_FINETUNED_DIR",
    CODE_DIR / "Fine-tuning" / "gemma3-4b-lora-output" / "lora-adapter",
))

EVAL_OUTPUT_DIR = Path(os.environ.get("EVAL_OUTPUT_DIR", SCRIPT_DIR / "eval-results"))

# model registry

MODEL_REGISTRY = {
    "gemma-base": {
        "hf_id": "google/gemma-3-4b-it",
        "local_dir": MODELS_DIR / "gemma-3-4b-it",
        "chat_style": "gemma",
        "trust_remote_code": False,
    },
    "gemma-finetuned": {
        "hf_id": None,  #local
        "local_dir": GEMMA_FINETUNED_DIR,  
        "chat_style": "gemma",
        "trust_remote_code": False,
        "is_adapter": True,  
    },
    "bloomz": {
        "hf_id": "bigscience/bloomz-3b",
        "local_dir": MODELS_DIR / "bloomz-3b",
        "chat_style": "plain",
        "trust_remote_code": False,
    },
    
    "phi3": {
        "hf_id": "microsoft/Phi-3-mini-4k-instruct",
        "local_dir": MODELS_DIR / "phi-3-mini-4k-instruct",
        "chat_style": "chat_template",  
        "trust_remote_code": False,
    },
}

# format registry
FORMAT_REGISTRY = {
    "my_format": "My format",
    "original": "Original",
    "silketw": "SilkETW",
    "sysmon": "Sysmon",
    "winlogbeat": "Winlogbeat",
}

# 8 fixed tests
TESTS = {
    1: {"model": "gemma-base", "format": "my_format"},
    2: {"model": "bloomz", "format": "my_format"},
    3: {"model": "phi3", "format": "my_format"},
    4: {"model": "gemma-base", "format": "original"},
    5: {"model": "gemma-base", "format": "silketw"},
    6: {"model": "gemma-base", "format": "winlogbeat"},
    7: {"model": "gemma-base", "format": "sysmon"},
    8: {"model": "gemma-finetuned", "format": "my_format"},
}

SCENARIO_DIRS = sorted(
    [p for p in RESULTS_DIR.iterdir() if p.is_dir() and p.name[:2].isdigit()]
) if RESULTS_DIR.exists() else []


HF_TOKEN = os.environ.get("HF_TOKEN") or False
