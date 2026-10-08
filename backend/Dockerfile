FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
# Host/port come from the environment so a staging instance can run beside
# prod on the same host-networked box. Defaults are the prod values.
ENV API_HOST=0.0.0.0 API_PORT=8000
CMD ["sh", "-c", "exec uvicorn main:app --host \"$API_HOST\" --port \"$API_PORT\""]
