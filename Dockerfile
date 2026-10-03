# NEOS Guard — self-host image.  docker build -t neosguard . && docker run -p 8080:8080 neosguard
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY neosguard/ ./neosguard/
COPY data/ ./data/
COPY sdk/ ./sdk/
COPY server.py .
ENV PORT=8080
EXPOSE 8080
CMD ["python", "server.py"]
