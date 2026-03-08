from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

# Determine which database to use:
# - Local Development: Use local PostgreSQL database
# - Production (Railway/Replit): Use DATABASE_URL environment variable

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:Sql2606%23@localhost:5432/InsightGuard"  # Your local PostgreSQL database
)

# Railway sometimes uses 'postgres://' but SQLAlchemy needs 'postgresql://'
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

print(f"Using database: {DATABASE_URL[:50]}...")  # Print only first 50 chars for security

# Create database engine with connection pooling
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,      # Test connections before using them
    pool_recycle=300,        # Recycle connections every 5 minutes
    echo=False,              # Set to True for SQL debugging
    connect_args=connect_args
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    """
    Dependency for database sessions.
    Use with FastAPI's Depends() to get a database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()