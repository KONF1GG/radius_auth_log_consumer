"""
RabbitMQ consumer for ClickHouse auth logs
"""

import logging
import signal
import ssl
import threading
import time
from typing import Any, Dict, List
import json
from datetime import datetime

import pika
from clickhouse_driver import Client
from dateutil.parser import parse as dt_parse

import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)


# ----------------------------- #
#         CLICKHOUSE CLIENT     #
# ----------------------------- #
class ClickHouseClient:
    """ClickHouse client"""

    def __init__(self) -> None:
        self.client = Client(
            host=config.CLICKHOUSE_HOST,
            port=config.CLICKHOUSE_PORT,
            user=config.CLICKHOUSE_USER,
            password=config.CLICKHOUSE_PASSWORD,
        )

    def insert_auth_batch(self, batch: List[Dict[str, Any]]) -> None:
        """Insert auth batch into ClickHouse (data already validated)."""
        if not batch:
            return

        try:
            # Подготовка данных для вставки
            validated_rows = []
            for item in batch:
                validated_data = DataValidator.validate_auth_data(item)
                validated_rows.append(prepare_auth_row(validated_data))

            self.client.execute(
                "INSERT INTO radius.log_auth (*) VALUES",
                validated_rows,
            )

        except Exception as e:
            # Логируем критическую ошибку
            logging.error("ClickHouse auth batch insert error: %s", e)
            raise


# ----------------------------- #
#         VALIDATION / PREP     #
# ----------------------------- #
class ValidationError(Exception):
    """Кастомное исключение для ошибок валидации"""

    def __init__(self, field: str, value: Any, message: str):
        self.field = field
        self.value = value
        self.message = message
        super().__init__(f"Field '{field}': {message} (value: {value})")


class DataValidator:
    """Валидатор данных для аутентификации"""

    # Поля таблицы radius.log_auth согласно схеме
    AUTH_REQUIRED_FIELDS = {"username"}

    AUTH_STRING_FIELDS = {
        "username",
        "password",
        "callingstationid",
        "nasipaddress",
        "reply",
        "reason",
        "pool",
        "agentremoteid",
        "agentcircuitid",
    }

    AUTH_DATETIME_FIELDS = {"authdate"}

    AUTH_FLOAT_FIELDS = {"speed", "uplink"}

    @staticmethod
    def validate_auth_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Валидация данных аутентификации"""
        if not isinstance(data, dict):
            raise ValidationError("root", data, "Data must be a dictionary")

        # Проверка обязательных полей
        for field in DataValidator.AUTH_REQUIRED_FIELDS:
            if field not in data or data[field] is None or data[field] == "":
                raise ValidationError(
                    field, data.get(field), "Required field is missing or empty"
                )

        validated_data = {}

        # Валидация строковых полей
        for field in DataValidator.AUTH_STRING_FIELDS:
            if field in data:
                value = data[field]
                if value is not None:
                    validated_data[field] = str(value)[:255]  # Ограничиваем длину
                else:
                    validated_data[field] = ""

        # Валидация DateTime полей
        for field in DataValidator.AUTH_DATETIME_FIELDS:
            if field in data:
                validated_data[field] = DataValidator._parse_datetime(
                    field, data[field]
                )

        # Валидация Float полей
        for field in DataValidator.AUTH_FLOAT_FIELDS:
            if field in data:
                validated_data[field] = DataValidator._parse_float(field, data[field])
            else:
                validated_data[field] = 0.0  # DEFAULT значение

        return validated_data

    @staticmethod
    def _parse_datetime(field: str, value: Any) -> datetime:
        """Парсинг DateTime значения"""
        if value is None or value == "":
            return datetime(1970, 1, 1, 5, 0, 0)

        if isinstance(value, datetime):
            return value

        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value)
            except (ValueError, OSError) as e:
                raise ValidationError(field, value, f"Invalid timestamp: {e}")

        if isinstance(value, str):
            try:
                return dt_parse(value)
            except Exception:
                raise ValidationError(field, value, "Invalid datetime format")

        raise ValidationError(field, value, "Unsupported type for datetime parsing")

    @staticmethod
    def _parse_float(field: str, value: Any) -> float:
        """Парсинг Float значения"""
        if value is None or value == "":
            return 0.0

        try:
            result = float(value)
            return result
        except (ValueError, TypeError) as e:
            raise ValidationError(field, value, f"Cannot convert to Float: {e}")


# Поля для аутентификации в правильном порядке
AUTH_FIELDS = [
    "authdate",
    "username",
    "password",
    "callingstationid",
    "nasipaddress",
    "reply",
    "reason",
    "speed",
    "uplink",
    "pool",
    "agentremoteid",
    "agentcircuitid",
]


def prepare_auth_row(validated_data: Dict[str, Any]) -> List[Any]:
    """Подготовка строки для вставки в таблицу log_auth"""
    row = []
    for field in AUTH_FIELDS:
        value = validated_data.get(field)

        # Обработка отсутствующих значений
        if value is None:
            if field in DataValidator.AUTH_DATETIME_FIELDS:
                row.append(datetime(1970, 1, 1, 5, 0, 0))
            elif field in DataValidator.AUTH_FLOAT_FIELDS:
                row.append(0.0)
            elif field in DataValidator.AUTH_STRING_FIELDS:
                row.append("")
            else:
                row.append(None)
            continue

        # Явное преобразование типов
        try:
            if field in DataValidator.AUTH_STRING_FIELDS:
                row.append(str(value))
            elif field in DataValidator.AUTH_DATETIME_FIELDS:
                if not isinstance(value, datetime):
                    raise ValueError(f"Field {field} must be datetime")
                row.append(value)
            elif field in DataValidator.AUTH_FLOAT_FIELDS:
                row.append(float(value))
            else:
                row.append(value)
        except (ValueError, TypeError) as e:
            raise ValueError(
                f"Invalid value for field {field}: {value} ({type(value)}). Error: {str(e)}"
            )

    return row


# ----------------------------- #
#         RABBITMQ BASE         #
# ----------------------------- #
class RabbitConsumer:
    """RabbitMQ consumer base class"""

    def __init__(self, queue: str) -> None:
        self.queue = queue
        self.conn = None
        self.channel = None
        self.running = False
        self.ssl_ctx = None

    def connect(self) -> None:
        """Connect to RabbitMQ"""
        params = pika.URLParameters(config.AMQP_URL)
        if self.ssl_ctx:
            params.ssl_options = pika.SSLOptions(self.ssl_ctx)
        params.socket_timeout = int(config.SOCKET_TIMEOUT)
        params.connection_attempts = int(config.CONNECTION_ATTEMPTS)
        params.retry_delay = int(config.RETRY_DELAY)

        self.conn = pika.BlockingConnection(params)
        self.channel = self.conn.channel()
        self._setup_infrastructure()

    def _setup_infrastructure(self) -> None:
        ch = self.channel
        # Используем существующий exchange dlx для мертвых очередей
        ch.queue_declare(
            "radius_log_dlq", durable=True, arguments={"x-queue-mode": "lazy"}
        )
        ch.queue_bind("radius_log_dlq", "dlx", "dlq")

        ch.exchange_declare("auth_log_exchange", "direct", durable=True)
        ch.queue_declare(
            self.queue,
            durable=True,
            arguments={
                "x-dead-letter-exchange": "dlx",
                "x-dead-letter-routing-key": "dlq",
            },
        )
        ch.queue_bind(self.queue, "auth_log_exchange", self.queue)
        ch.basic_qos(prefetch_count=int(config.PREFETCH_COUNT))

    def start(self) -> None:
        """Start the consumer"""
        raise NotImplementedError

    def stop(self) -> None:
        """Stop the consumer"""
        self.running = False
        if self.channel:
            self.channel.stop_consuming()
        if self.conn:
            self.conn.close()


# ----------------------------- #
#         AUTH CONSUMER         #
# ----------------------------- #
class AuthConsumer(RabbitConsumer):
    """Auth consumer for auth_log_queue"""

    def __init__(self) -> None:
        super().__init__(queue=config.AUTH_LOG_QUEUE)
        self.ch_client = ClickHouseClient()
        self.batch: List[Dict[str, Any]] = []
        self.tags: List[int] = []
        self.last_flush = time.time()
        self.flush_interval = 5  # секунд

    def start(self) -> None:
        self.running = True
        try:
            self.connect()

            for method, _, body in self.channel.consume(
                self.queue, inactivity_timeout=1
            ):
                if not self.running:
                    break
                if body is None:
                    self._maybe_flush()
                    continue
                self._handle(body, method)

        except Exception as e:
            logging.error("AuthConsumer failed: %s", e)
            raise

    def _handle(self, body: bytes, method) -> None:
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            logging.error("Auth JSON decode failed: %s", e)
            self.channel.basic_nack(method.delivery_tag, requeue=False)
            return

        # Валидация данных
        try:
            DataValidator.validate_auth_data(data)
        except ValidationError as e:
            logging.warning("Auth validation failed: %s", e)
            self.channel.basic_nack(method.delivery_tag, requeue=False)
            return

        # Если всё ок — добавляем в batch
        self.batch.append(data)
        self.tags.append(method.delivery_tag)
        self._maybe_flush()

    def _maybe_flush(self) -> None:
        batch_size = len(self.batch)
        time_since_flush = time.time() - self.last_flush

        # Флашим если батч большой или прошло много времени
        should_flush = batch_size >= int(config.PREFETCH_COUNT) or (
            batch_size > 0 and time_since_flush > self.flush_interval
        )

        if should_flush:
            self._flush()

    def _flush(self) -> None:
        if not self.batch:
            return

        batch_size = len(self.batch)

        try:
            self.ch_client.insert_auth_batch(self.batch)

            # Подтверждаем все сообщения в батче
            for tag in self.tags:
                self.channel.basic_ack(tag)

            logging.info("Successfully processed batch of %s auth records", batch_size)

        except Exception as e:
            logging.exception("Auth batch processing failed: %s", e)
            # Логируем проблемный батч для отладки
            logging.debug("Failed batch: %s...", self.batch[:3])  # Первые 3 элемента

            for tag in self.tags:
                self.channel.basic_nack(tag, requeue=False)

        finally:
            self.batch.clear()
            self.tags.clear()
            self.last_flush = time.time()

    def stop(self) -> None:
        # Флашим оставшиеся данные перед остановкой
        if self.batch:
            logging.info("Flushing remaining %s records on shutdown", len(self.batch))
            self._flush()
        super().stop()


# ----------------------------- #
#         MAIN ENTRYPOINT       #
# ----------------------------- #
def main() -> None:
    """Main entrypoint"""
    consumer = AuthConsumer()
    thread = threading.Thread(target=consumer.start, daemon=True)

    def shutdown(sig, frame):
        consumer.stop()

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    thread.start()
    thread.join()


if __name__ == "__main__":
    main()
