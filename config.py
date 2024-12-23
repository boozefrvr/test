import os
from dotenv import load_dotenv

load_dotenv()

config = {
    "DD_API_URL": os.getenv("DD_API_URL"),
    "DD_API_KEY": os.getenv("DD_API_KEY"),
    "DD_ENGAGEMENT_ID": os.getenv("DD_ENGAGEMENT_ID"),
}
