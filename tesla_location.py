#!python

import requests
import argparse
import logging
import sqlite3
import json
import time
import os


'''
Purpose: poll for car location on a regular interval and spit out daily reports in json format

environmental variables used: TESLA_PASSWORD, TESLA_EMAIL, TESLA_TOKEN
'''
TESLA_CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
TESLA_CLIENT_SECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3"
TESLA_URL = "https://owner-api.teslamotors.com"
AUTH_STRING = "/oauth/token?grant_type=password"


def store_gps_sqlite(vehicle_info: dict = None, filename: str = "output.json", logger: logging.Logger = None) -> None:
    """
    Open sqlite connection.  If file doesn't exist, create new sqlite file, and create new table.  Store GPS information
    and close connection
    :param vehicle_info: vehicle info returned from tesla API
    :param filename: path of sqlite file.  Assume relative
    :param logger: logging object
    :return:
    """
    create_table_sql = "CREATE TABLE IF NOT EXISTS gps (\
                        id integer PRIMARY KEY,\
                        latitude text NOT NULL,\
                        longitude text NOT NULL,\
                        heading int NOT NULL,\
                        gps_time int NOT NULL UNIQUE);"
    # create sql connection
    logger.debug(f"storing gps info to {filename}")
    conn = sqlite3.connect(filename)
    cursor = conn.cursor()
    cursor.execute(create_table_sql)

    # store gps info
    latitude = vehicle_info["response"]["drive_state"]["native_latitude"]
    longitude = vehicle_info["response"]["drive_state"]["native_longitude"]
    heading = vehicle_info["response"]["drive_state"]["heading"]
    gps_time = vehicle_info["response"]["drive_state"]["gps_as_of"]
    # create gps_store sqlite insert command
    gps_store = "INSERT INTO gps (latitude, longitude, heading, gps_time) \
                VALUES(?, ?, ?, ?)"
    values = (latitude, longitude, heading, gps_time)

    logger.debug(values)
    logger.debug([type(i) for i in values])
    try:
        cursor.execute(gps_store, values)
    except sqlite3.IntegrityError:
        logger.info("no change since last update")
        pass
    conn.commit()
    cursor.close()
    conn.close()


def grab_envs(logger: logging.Logger = None):
    """
    Grab email/password or token from environmental variables.  If only email/passwd is found,
    invoke grab_token().  Otherwise just return token (modified with "Bearer " prepended
    :param logger: logging object
    :return: return a token
    """
    if os.getenv("TESLA_TOKEN"):
        return "Bearer " + os.getenv("TESLA_TOKEN")
    elif os.getenv("TESLA_EMAIL") and os.getenv("TESLA_PASSWORD"):
        return grab_token(os.getenv("TESLA_EMAIL"), os.getenv("TESLA_PASSWORD"))
    else:
        logger.error("Missing either TESLA_TOKEN or TESLA_EMAIL and TESLA PASSWORD envs")


def initialize_logging(debug_enabled: bool = False) -> logging.Logger:
    """
    :param debug_enabled: bool to enable debugging log level
    :return:
    """
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    assert isinstance(debug_enabled, bool)
    if debug_enabled:
        logger.setLevel(logging.DEBUG)
        logger.debug("debug active")
    return logger


def grab_token(email: str, password: str) -> str:
    """
    :param email:   string of user email address
    :param password: string of user password
    :return:
    """
    grant_type = "password"
    client_id = TESLA_CLIENT_ID
    client_secret = TESLA_CLIENT_SECRET
    base_uri = TESLA_URL
    auth_string = AUTH_STRING
    request_uri = f'{base_uri}/{auth_string}'

    data = {"grant_type": grant_type, "client_id": client_id, "client_secret": client_secret,
            "email": email, "password": password}
    response = requests.post(url=request_uri, data=data)

    return "Bearer " + response.json()["access_token"]


def select_vehicle(base_uri: str, token: str, index: int = 0, logger: logging.Logger = None) -> str:
    """
    :param base_uri: base uri for tesla OAUTH requests
    :param token: OAUTH token
    :param index: index of vehicles if you have more than one.  default 0
    :param logger: logging object
    :return: vehicle ID
    """
    # set variables
    headers = {"Authorization": token}
    vehicle_uri = "/api/1/vehicles"
    request_url = base_uri + vehicle_uri
    logger.debug(f"sending vehicle list request to {request_url}")

    logging.debug(headers)
    logging.debug(request_url)
    # send POST
    vehicle_request = requests.get(url=request_url, headers=headers)
    # pull vehicle ID from response
    logger.debug(vehicle_request.json())
    vehicle_id = str(vehicle_request.json()["response"][index]["id"])
    return vehicle_id


def wake_car(base_uri: str, token: str, vehicle_id: str, logger: logging.Logger = None) -> None:
    """
    :param base_uri: base uri for tesla OAUTH requests
    :param token: OAUTH token
    :param vehicle_id: id of the vehicle you're waking
    :param logger: logging object
    :return:
    """
    headers = {"Authorization": token}
    wake_url = f"/api/1/vehicles/{vehicle_id}/wake_up"
    request_url = base_uri + wake_url

    logger.debug(f'Sending wake command to vehicle id {vehicle_id}')
    logger.debug(request_url)

    # send wake message
    vehicle_request = requests.post(url=request_url, headers=headers)
    logger.debug(vehicle_request)
    if not vehicle_request.status_code == 200:
        logger.info("Failed to wake up car")


def grab_gps(base_uri: str, token: str, vehicle_id: str, logger: logging.Logger = None) -> str:
    """
    :param base_uri: base OAUTH url to prepend to request url
    :param token: OAUTH token
    :param vehicle_id: id of the vehicle you're querying.
    :param logger: logging object
    :return: gps values
    """

    # set variables
    headers = {"Authorization": token}
    vehicle_info_url = f"/api/1/vehicles/{vehicle_id}/vehicle_data"
    # vehicle_info_url = f"/api/1/vehicles/{vehicle_id}/data"
    request_url = base_uri + vehicle_info_url

    logger.debug(request_url)

    # send POST for vehicle info
    response = requests.get(url=request_url, headers=headers)
    logger.debug(response)
    logger.debug(response.json())
    return response.json()


def main():

    # establish uri strings
    base_uri = TESLA_URL

    # parse arguments with argparse
    parser = argparse.ArgumentParser(description='Pull Tesla information')
    parser.add_argument('--debug_enabled', default=False, action="store_true",
                        help="Enable debugging messages")
    parser.add_argument('--use_env', default=False, action="store_true",
                        help="Use environmental variables for username/password/token")
    parser.add_argument('--grab_token', default=False, action="store_true",
                        help="Grab OAuth token with username/password")
    parser.add_argument('-p', '--password', type=str, help="Account password")
    parser.add_argument('-e', '--email', type=str, help="Tesla account email address")
    parser.add_argument('-t', '--token', type=str, help="OAuth token",)
    parser.add_argument('-o', '--output_path', default=False,
                        help="Output filename")
    parser.add_argument('-s', '--store_sqlite', help="store value in sqlite at filename")
    args = parser.parse_args()

    # initialize logging
    logger = initialize_logging(args.debug_enabled)

    # grab token if we don't already have one
    if not args.token:
        token = grab_token(args.email, args.password)
        logger.info(f"Token: {token}")
    else:
        token = "Bearer " + args.token

    # grab vehicle ID
    vehicle_id = select_vehicle(base_uri=base_uri,
                                token=token,
                                index=0,
                                logger=logger,
                                )

    # wake up the car
    wake_car(base_uri=base_uri,
             token=token,
             vehicle_id=vehicle_id,
             logger=logger
             )
    # grab vehicle info
    vehicle_info = grab_gps(base_uri=base_uri,
                            token=token,
                            vehicle_id=vehicle_id,
                            logger=logger,
                            )
    logger.info(vehicle_info)
    if args.output_path:
        with open(args.output_path, 'w') as outfile:
            outfile.write(json.dumps(vehicle_info))
    if args.store_sqlite:
        store_gps_sqlite(vehicle_info=vehicle_info, filename=args.store_sqlite, logger=logger)


if __name__ == "__main__":
    main()
