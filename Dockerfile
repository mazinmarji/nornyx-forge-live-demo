FROM python:3.13-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CREWAI_DISABLE_TELEMETRY=true OTEL_SDK_DISABLED=true

# Install first, from only what the editable install needs. The governance
# contracts and the BRD are runtime data, so copying them afterwards keeps the
# dependency layer cached when a contract is rebound to a new revision — that
# rebinding happens on every governed change.
COPY pyproject.toml README.md /app/
COPY src /app/src
RUN pip install --no-cache-dir -e '.[demo]'

COPY .nornyx /app/.nornyx
COPY BRD.md /app/BRD.md
EXPOSE 8000
CMD ["uvicorn", "demo_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
