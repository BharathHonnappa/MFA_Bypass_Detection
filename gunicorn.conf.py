import multiprocessing
import os


bind = os.environ.get("MFA_GUARD_BIND", "127.0.0.1:8000")
workers = int(os.environ.get("WEB_CONCURRENCY", multiprocessing.cpu_count() * 2 + 1))
threads = int(os.environ.get("MFA_GUARD_THREADS", "2"))
timeout = int(os.environ.get("MFA_GUARD_TIMEOUT", "30"))
accesslog = os.environ.get("MFA_GUARD_ACCESS_LOG", "-")
errorlog = os.environ.get("MFA_GUARD_ERROR_LOG", "-")
loglevel = os.environ.get("MFA_GUARD_LOG_LEVEL", "info")
