from pathlib import Path

from dotenv import load_dotenv

from app import create_app

load_dotenv(Path(__file__).parent / ".env")

app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"],
    )
