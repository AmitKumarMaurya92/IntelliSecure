import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    PROJECT_NAME: str = "InteliSecure"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./database/intelisecure.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "supersecretkey_pleasechangeinproduction_intelisecure_2026")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

settings = Settings()
