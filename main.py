if __name__ == '__main__':
    from sys import argv
    from src.ingest import AlertIngest
    import asyncio
    import logging
    import os
    try:
        os.makedirs("logs/")
    except FileExistsError: print("./logs exists")
    try:

        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                            handlers=[
                                logging.FileHandler("logs/app.log"),
                                logging.StreamHandler()
                            ])
        filepath = argv[1]

        alertIngest = AlertIngest(filepath)
        asyncio.run(alertIngest.load_alert())

    except FileNotFoundError: logging.error("File not Found")
    except IndexError: logging.error("Usage: python3 main.py <filepath>")
    except Exception as e: logging.error(e)





