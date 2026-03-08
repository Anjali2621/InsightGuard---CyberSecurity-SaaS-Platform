from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os

# Determine which database to use:
# - On Railway: Use the DATABASE_URL environment variable (Railway sets this automatically)
# - On Replit: Use Replit's database or fallback to SQLite
# - Locally: Use your local PostgreSQL database

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    # Check if we're on Replit (has REPLIT_DB_URL)
    replit_db = os.getenv("REPLIT_DB_URL")
    if replit_db:
        DATABASE_URL = replit_db
    else:
        # Fallback to SQLite for local development or Replit
        DATABASE_URL = "sqlite:///./insightguard.db"

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