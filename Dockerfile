FROM python:3.10-slim

EXPOSE 5000

WORKDIR /app

COPY requirements.txt /app/

RUN pip install -r requirements.txt

COPY test_backend.py message_broker.py chunker.py task.py converter.py /app/

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "test_backend:app"]