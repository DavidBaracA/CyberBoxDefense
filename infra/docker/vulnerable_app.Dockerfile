FROM python:3.11-slim

WORKDIR /workspace/targets/vulnerable_app

COPY targets/vulnerable_app/requirements.txt /workspace/targets/vulnerable_app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY targets/vulnerable_app /workspace/targets/vulnerable_app

CMD ["python", "app.py"]
