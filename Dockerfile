FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt /app/

RUN pip install -r requirements.txt

COPY upload.py message_broker.py chunker.py task.py converter.py /app/

CMD ["python3", "upload.py"]