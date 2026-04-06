FROM python:3.11-slim

WORKDIR /workspace

COPY apps/backend/requirements.txt /workspace/apps/backend/requirements.txt
RUN pip install --no-cache-dir -r /workspace/apps/backend/requirements.txt

COPY apps/backend /workspace/apps/backend
COPY shared/python /workspace/shared/python

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--app-dir", "/workspace/apps/backend"]
