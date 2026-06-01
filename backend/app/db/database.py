from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
import os

# Ensure the data directory exists
data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../data"))
os.makedirs(data_dir, exist_ok=True)

# Update database URL if needed to absolute path for sqlite
# settings.DATABASE_URL might be a relative path "sqlite:///../data/intelisecure.db"
# let's extract the sqlite path and ensure it creates the db properly.
db_url = settings.DATABASE_URL
if db_url.startswith("sqlite:///"):
    db_path = db_url.replace("sqlite:///", "")
    if not os.path.isabs(db_path):
        db_path = os.path.join(os.path.dirname(__file__), "../../", db_path)
    db_url = f"sqlite:///{os.path.abspath(db_path)}"

# connect_args is needed only for SQLite
engine = create_engine(
    db_url, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
