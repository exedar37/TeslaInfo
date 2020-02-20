#!python

import requests
import argparse
import logging
import json

'''
Purpose: poll for car location on a regular interval and spit out daily reports in json format
'''
TESLA_CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
TESLA_CLIENT_SECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3"
TESLA_URL = "https://owner-api.teslamotors.com"
AUTH_STRING = "/oauth/token?grant_type=password"


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
    headers = {"Authorization": token}

    logging.debug(headers)
    logging.debug(request_url)
    # send POST
    vehicle_request = requests.get(url=request_url, headers=headers)
    # pull vehicle ID from response
    logger.debug(vehicle_request.json())
    vehicle_id = int(vehicle_request.json()["response"][index]["id"])
    return str(vehicle_id)


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
    headers = {"Authorization":token}
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
    vehicle_id = str(select_vehicle(base_uri=base_uri,
                                    token=token,
                                    index=0,
                                    logger=logger,
                                    ))

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


if __name__ == "__main__":
    main()