FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN mkdir -p /data && chown 10001:10001 /data
COPY app.py /app/app.py
EXPOSE 8081 8082 8083
USER 10001:10001
CMD ["python", "/app/app.py"]
