FROM python:3.13-slim AS builder

WORKDIR /app

COPY server.py /app/
COPY core/ /app/core/
COPY requirements.txt /app/
COPY scripts/wait-for-it.sh /wait-for-it.sh

RUN chmod +x /wait-for-it.sh
RUN pip install --no-cache-dir -r /app/requirements.txt

RUN useradd -M chat_usr
RUN chown -R root:chat_usr /app
RUN chmod -R 750 /app

USER chat_usr

CMD ["/wait-for-it.sh", "db:3306", "--", "python3", "server.py"]