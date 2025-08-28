import os
from dotenv import load_dotenv

load_dotenv()

# ==================== #
#   RabbitMQ Settings  #
# ==================== #
AMQP_URL = os.getenv("AMQP_URL")
QUEUE_NAME = os.getenv("QUEUE_NAME")
AUTH_LOG_QUEUE = os.getenv("AUTH_LOG_QUEUE", "auth_log_queue")

# ==================== #
#   Network Settings   #
# ==================== #
SOCKET_TIMEOUT = os.getenv("SOCKET_TIMEOUT", "10")
CONNECTION_ATTEMPTS = os.getenv("CONNECTION_ATTEMPTS", "3")
RETRY_DELAY = os.getenv("RETRY_DELAY", "5")
PREFETCH_COUNT = os.getenv("PREFETCH_COUNT", "100")

# ==================== #
#  CLickhouse Settings #
# ==================== #
CLICKHOUSE_HOST = os.getenv("CLICKHOUSE_HOST")
CLICKHOUSE_PORT = os.getenv("CLICKHOUSE_PORT")
CLICKHOUSE_USER = os.getenv("CLICKHOUSE_USER")
CLICKHOUSE_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD")
