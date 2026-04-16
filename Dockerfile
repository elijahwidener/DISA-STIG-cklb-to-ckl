FROM python:3.11-slim

WORKDIR /app

COPY cklb_to_ckl.py .

ENTRYPOINT ["python", "/app/cklb_to_ckl.py"]