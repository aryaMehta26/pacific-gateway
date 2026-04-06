FROM python:3.11-slim

WORKDIR /app

# System deps for Presidio NLP models
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Presidio requires a spacy language model
RUN python -m spacy download en_core_web_lg

COPY . .

EXPOSE 8000

# Ollama must be reachable at OLLAMA_BASE_URL (default: host.docker.internal:11434)
ENV OLLAMA_BASE_URL=http://host.docker.internal:11434

CMD ["python", "-m", "uvicorn", "api.dashboard:app", "--host", "0.0.0.0", "--port", "8000"]
