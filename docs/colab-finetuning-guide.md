# Google Colab Fine-Tuning Guide for System 1 SOC Decision Models

This guide prepares you to fine-tune small decision models (<500MB) using the fine-tuning dataset exported at `locals/finetune/system1_colab_finetune.jsonl`.

## Target Models (<500MB)
1. **SmolLM2-135M / 360M** (`HuggingFaceTB/SmolLM2-360M-Instruct`) - Fast, compact SLM under 400MB.
2. **Qwen2.5-0.5B-Instruct** (`Qwen/Qwen2.5-0.5B-Instruct`) - State-of-the-art sub-1B parameter reasoning model (~490MB in float16/int8).
3. **DistilBERT-base-uncased** (`distilbert-base-uncased`) - Fast discriminative classification model (~260MB).

---

## Colab Notebook Code (Ready to Run)

```python
# 1. Install dependencies in Colab
!pip install -q -U unsloth transformers datasets trl peft bitsandbytes torch

# 2. Upload dataset: locals/finetune/system1_colab_finetune.jsonl
from google.colab import files
uploaded = files.upload()

# 3. Load Model with Unsloth / Hugging Face
import torch
from unsloth import FastLanguageModel

max_seq_length = 512
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name="Qwen/Qwen2.5-0.5B-Instruct",
    max_seq_length=max_seq_length,
    load_in_4bit=True,
)

# 4. Set up LoRA Adapters
model = FastLanguageModel.get_peft_model(
    model,
    r=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_alpha=16,
    lora_dropout=0,
    bias="none",
)

# 5. Format Dataset for Instruction Tuning
from datasets import load_dataset

prompt_template = """<|im_start|>system
You are a sub-millisecond System 1 SOC Triage Classifier. Determine the classification, category, severity, and MITRE technique.<|im_end|>
<|im_start|>user
{input}<|im_end|>
<|im_start|>assistant
{output}<|im_end|>"""

def formatting_prompts_func(examples):
    inputs = examples["input"]
    outputs = examples["output"]
    texts = []
    for inp, out in zip(inputs, outputs):
        text = prompt_template.format(input=inp, output=out)
        texts.append(text)
    return {"text": texts}

dataset = load_dataset("json", data_files="system1_colab_finetune.jsonl", split="train")
dataset = dataset.map(formatting_prompts_func, batched=True)

# 6. Train with SFTTrainer
from trl import SFTTrainer
from transformers import TrainingArguments

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=dataset,
    dataset_text_field="text",
    max_seq_length=max_seq_length,
    args=TrainingArguments(
        per_device_train_batch_size=4,
        gradient_accumulation_steps=4,
        warmup_steps=5,
        max_steps=60,
        learning_rate=2e-4,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        logging_steps=1,
        output_dir="outputs",
    ),
)
trainer.train()

# 7. Export GGUF / ONNX for local deployment (<500MB)
model.save_pretrained_gguf("locals/models/system1_qwen_0.5b", tokenizer, quantization_method="q4_k_m")
```

Once fine-tuned, the exported GGUF or ONNX weights can be dropped directly into `locals/models/` and loaded by `backend/agents/system1_decision.py` for ultra-fast, local, private, sub-millisecond neural decision making!
