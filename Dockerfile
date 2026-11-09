FROM python:3.12-slim

WORKDIR /app

# Install dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Bind gunicorn to all interfaces inside the container so it's reachable
# from outside via the port mapping in docker run / docker-compose.
# Dev-mode OTP logging is on by default so codes print to `docker logs`
# instead of requiring SMTP — override with -e MFA_GUARD_DEV_LOG_OTP=false
# if you ever build a non-demo image from this same Dockerfile.
ENV MFA_GUARD_BIND=0.0.0.0:8000
ENV MFA_GUARD_DEV_LOG_OTP=true

EXPOSE 8000

CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:application"]
