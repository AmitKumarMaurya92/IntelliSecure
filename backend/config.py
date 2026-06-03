import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    PROJECT_NAME: str = "IntelliSecure"
    _db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'intelisecure.db')
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{_db_path}")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "supersecretkey_pleasechangeinproduction_intelisecure_2026")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))

settings = Settings()
