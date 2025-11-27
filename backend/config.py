import os

DB_CONFIG = {
    "host": os.getenv("DATABASE_HOST", "localhost"),
    "port": int(os.getenv("DATABASE_PORT", 5432)),
    "dbname": os.getenv("DATABASE_NAME", "ngfw_db"),
    "user": os.getenv("DATABASE_USER", "postgres"),
    "password": os.getenv("DATABASE_PASSWORD", "1234")
}
