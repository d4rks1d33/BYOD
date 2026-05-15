# Local LLM Models

Place your `.gguf` model files here before running `docker compose up -d --build`.

This directory is mounted as `/models` (read-only) in all backend containers.

## How to use

1. Download a `.gguf` model:
   ```bash
   # Example: Llama 3.1 8B quantized
   curl -L -o ./models/llama-3.1-8b-q4.gguf \
     https://huggingface.co/MaziyarPanahi/Meta-Llama-3.1-8B-Instruct-GGUF/resolve/main/Meta-Llama-3.1-8B-Instruct.Q4_K_M.gguf
   ```

2. (Re)build containers:
   ```bash
   docker compose up -d --build
   ```

3. In the dashboard, go to **AI Models** → **Add Model**:
   - Provider: **Local .gguf**
   - GGUF Path: `/models/llama-3.1-8b-q4.gguf`
   - Click **Create & Activate**

## Recommended Models

- **Llama 3.1 8B** — Good balance (4-8 GB VRAM)
- **Llama 3.1 70B Quantized** — Better reasoning (24+ GB)
- **Codellama 13B** — For SAST/code analysis
- **Qwen 2.5 Coder** — Code-focused

## Notes

- GPU acceleration enabled automatically (n_gpu_layers=-1)
- Context window: 8192 tokens by default
- Function calling: Best-effort via JSON parsing (less reliable than cloud LLMs)
