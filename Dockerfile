FROM python:3.13-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CREWAI_DISABLE_TELEMETRY=true OTEL_SDK_DISABLED=true
COPY pyproject.toml README.md /app/
COPY src /app/src
COPY .nornyx /app/.nornyx
COPY BRD.md /app/BRD.md
RUN pip install --no-cache-dir -e '.[demo]'
EXPOSE 8000
CMD ["uvicorn", "demo_app.main:app", "--host", "0.0.0.0", "--port", "8000"]
