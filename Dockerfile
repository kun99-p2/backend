FROM python:3.10-slim

EXPOSE 5000

WORKDIR /app

COPY requirements.txt /app/

RUN pip install -r requirements.txt

COPY test_backend.py message_broker.py chunker.py task.py converter.py /app/

CMD ["python3", "test_backend.py"]