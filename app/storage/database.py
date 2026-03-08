from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

# Determine which database to use:
# - On Railway: Use the DATABASE_URL environment variable (Railway sets this automatically)
# - Locally: Use your local PostgreSQL database

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:Sql2606%23@localhost:5432/InsightGuard"  # Your local database
)

# Railway sometimes uses 'postgres://' but SQLAlchemy needs 'postgresql://'
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

print(f"Database URL: {DATABASE_URL[:30]}...")  # Print only first 30 chars for security

# Create database engine with connection pooling
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,      # Test connections before using them
    pool_recycle=300,        # Recycle connections every 5 minutes
    echo=False               # Set to True for SQL debugging
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