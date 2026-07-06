FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root

COPY data /tmp/task-data
RUN mkdir -p /root/data && \
    python3 /tmp/task-data/build_inputs.py && \
    rm -rf /tmp/task-data

# Claude Code
COPY skills /root/.claude/skills
# Codex
COPY skills /root/.codex/skills
# OpenCode
COPY skills /root/.opencode/skill
# Goose
COPY skills /root/.goose/skills
# Factory
COPY skills /root/.factory/skills
# Portable agents format
COPY skills /root/.agents/skills
# GitHub Copilot
COPY skills /root/.github/skills
# Gemini
COPY skills /root/.gemini/skills
