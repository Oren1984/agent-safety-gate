# Sandbox image for agent tool execution. The restrictions that matter
# (no network, read-only rootfs, dropped capabilities, limits) are applied at
# `docker run` time in safety_gate/sandbox.py.
FROM python:3.12-slim

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin agent
COPY tool_runner.py /opt/tool_runner.py

USER 10001:10001
WORKDIR /workspace
ENTRYPOINT ["python", "-I", "/opt/tool_runner.py"]
