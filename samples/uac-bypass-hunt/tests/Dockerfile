FROM python:3.12-slim-bookworm

# Verifier-own tooling, baked at build time (never installed at verify time).
RUN pip install --no-cache-dir \
    pytest==8.4.1 \
    pytest-json-ctrf==0.3.5

# Bring the test scripts and the baked ground truth into the verifier image.
# ground_truth.json lives only here — it never enters the agent container.
COPY . /tests/
WORKDIR /tests
