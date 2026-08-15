FROM python:3.12-slim

WORKDIR /app

# Unbuffered stdout — without this, print() output from behavior_detector.py
# and case_builder.py sits in Python's buffer and never reaches `docker logs`
# until the buffer fills or the process exits, making both daemons look hung.
ENV PYTHONUNBUFFERED=1

# Dependencies first so `docker compose build` only reinstalls them when
# requirements.txt actually changes, not on every source edit.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py behavior_detector.py case_builder.py hunt_engine.py process_tree_builder.py seed_argus.py hosts.json ip_overrides.json ./

# No CMD here on purpose — this image backs three different services
# (api, behavior_detector, case_builder) that each need a different
# entrypoint. The command is supplied per-service in docker-compose.yml.
