from config import config
from defect_dojo import DefectDojo


def main():
    instance = DefectDojo(
        dd_api_url=config["DD_API_URL"],
        dd_api_key=config["DD_API_KEY"],
        dd_engagement_id=config["DD_ENGAGEMENT_ID"],
    )
    instance.start()

if __name__ == "__main__":
    main()
