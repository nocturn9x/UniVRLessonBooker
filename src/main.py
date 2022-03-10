#!/usr/bin/env python3

# Copyright (C) 2021 nocturn9x
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#   http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import json
import httpx
import logging
import asyncio
import argparse
from typing import Union
from hashlib import sha256
from getpass import getpass
from pyppeteer import launch
from base64 import b64decode
from signal import SIGINT, SIGTERM
from pyppeteer.errors import PyppeteerError, NetworkError


GET_ALL_LESSONS_URL = "https://logistica.univr.it/easylesson/api/leggi_insegnamenti/{}"
GET_BOOKABLE_LESSONS_URL = "https://logistica.univr.it/easylesson/api/lezioni_prenotabili/{}"
BOOK_LESSON_URL = "https://logistica.univr.it/easylesson/api/salva_prenotazioni"
AUTH_APP_URL = "https://logistica.univr.it/auth/auth_app.php"


async def send_request(
    client: httpx.AsyncClient, method: str, *args, **kwargs
) -> Union[httpx.Response, httpx.RequestError]:
    """
    Small wrapper around the async http client to avoid lots
    of redundant try/except blocks. All but the first two
    arguments are passed directly to the desired method

    :param client: The HTTPX async client instance to use
    :type client: :class:httpx.AsyncClient
    :param method: The method of the client object that should
        be called. This wrapper verifies that the client
        has a callable attribute with said name and passes
        it all extra positional and keyword arguments
    :type method: str
    :return: A response object if the request succeeds or an exception if it
        it fails entirely
    :raises ValueError: If the given method does not exist or is invalid
    :raises TypeError: If method is not a string (checked via isinstance())
    """

    if not isinstance(method, str):
        raise TypeError(f"'method' must be a string, not {type(method).__name__!r}")
    if not hasattr(client, method) or not callable(m := getattr(client, method)):
        raise ValueError(f"invalid value {method!r} for method")
    try:
        response = await m(*args, **kwargs)
    except httpx.RequestError as request_error:
        return request_error
    return response


def check_response(
    logger: logging.Logger, value: Union[httpx.Response, httpx.RequestError], verbose: bool = False
) -> bool:
    """
    Small utility function to avoid repeating the same error printing code many times.
    Returns True if the application should exit, false otherwise

    :param logger: The logger object
    :type logger: :class:logging.Logger
    :param value: The result from send_request
    :type value: Union[httpx.Response, httpx.RequestError]
    :param verbose: The value of arguments.verbose inside main(), defaults to False
    :type verbose: bool, optional
    :return: True if the application should exit (error occurred), false otherwise
    """

    if isinstance(value, httpx.RequestError):
        if verbose:
            logger.error(
                f"A fatal HTTP exception occurred while sending request to {value.request.url!r}, details follow: "
                f"{type(value).__name__} -> {value}"
            )
        else:
            logger.error(
                "A fatal error occurred while sending request, run the program using the --verbose "
                "command-line option to find out more about the error"
            )
        return True
    elif value.status_code >= 400:
        if verbose:
            logger.error(f"An unexpected HTTP response code ({value.status_code}) was given by {value.url!r}")
        else:
            logger.error(
                "A fatal error occurred while sending request, run the program using the --verbose "
                "command-line option to find out more about the error"
            )
        return True
    return False


async def login_with_gia(
    logger: logging.Logger, username: str, password: str, verbose: bool = False
) -> str:
    """
    Performs authentication via the GIA SSO provider and a headless
    chromium instance. Note this uses a different httpx.AsyncClient
    instance with different headers and cookies since it uses
    separate configuration from the app

    :param logger: The logger object
    :type logger: :class:logging.Logger
    :param username: The GIA username
    :type username: str
    :param password: The GIA password associated to the username
    :type password: str, optional
    :param verbose: Whether log messages should feature enhanced
        verbosity. Defaults to False
    :type verbose: bool, optional
    :return: The access token (JWT) to set as cookie inside main().
        Empty upon error
    """

    async with httpx.AsyncClient(
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Upgrade-Insecure-Requests": "1",
            "X-Requested-With": "it.easystaff.univr",
            "Connection": "Keep-Alive",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7",
        }
    ) as client:
        logger.debug(f"Sending request to {AUTH_APP_URL}")
        # We request the GIA SSO URL to authenticate ourselves
        if check_response(logger, result := await send_request(client, "get", AUTH_APP_URL)):
            return ""
        else:
            logger.debug(
                f"Request to {AUTH_APP_URL} sent, status code is {result.status_code}"
            )
            try:
                logger.debug("Launching headless browser instance")
                browser = await launch(headless=True)
                logger.debug("Headless browser instance launched, opening new page")
                page = await browser.newPage()
                logger.debug(f"New page opened, going to redirect URL: {result.url}")
                await page.goto(str(result.url))
                logger.debug("Page loaded, typing credentials")
                # Types username and password with 100ms delay between key presses
                await page.type('#IDToken1', username, delay=100)
                await page.type('#IDToken2', password, delay=100)
                logger.debug("Submitting login form")
                await page.click('[type="button"]')
                try:
                    if "failed" in (await page.title()).lower():
                        logger.error("SSO authentication failed: invalid credentials")
                        return ""
                except NetworkError:
                    pass   # TODO: This now fails when login is successful for some reason(?)
                return page.url.split("#")[1].strip("access_token=")
            except PyppeteerError as browser_error:
                if verbose:
                    logger.error(
                        f"A fatal browser exception has occurred: {type(browser_error).__name__}: {browser_error}"
                    )
                else:
                    logger.error(
                        "A fatal error occurred while authenticating with GIA, run the program using the --verbose "
                        "command-line option to find out more about the error"
                    )
                return ""
            finally:
                await browser.close()


async def main(arguments: argparse.Namespace) -> int:
    """
    Main program entry point

    :param arguments: The namespace containing argparse arguments
    :type arguments: :class: argparse.Namespace
    :return:
    """

    logger = logging.Logger("UniVRLessonBooker")
    logger.setLevel(logging.DEBUG if arguments.verbose else logging.INFO)
    formatter = logging.Formatter(datefmt="%H:%M:%S %p", fmt="[%(levelname)s - %(asctime)s] %(message)s")
    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    if arguments.log_file:
        file_handler = logging.FileHandler(arguments.log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        logger.debug(f"Skipping logging to file as no -l/--log-file option was provided")
    logger.info("UniVRAutoLessonBooker v0.1 starting up!")
    if not arguments.tax_code:
        logger.info("You have not provided your tax/fiscal code, but I can get it for you. Please provide your GIA SSO"
                    " credentials below")
        try:
            username = input("Type your GIA SSO username: ")
            password = getpass("Type your GIA SSO password (hidden): ")
        except KeyboardInterrupt:
            # Asyncio's signal handlers won't work
            # when blocked in synchronous code like
            # this
            return
        logger.info(f"Logging in as {username!r}")
        if access_token := await login_with_gia(logger, username, password, arguments.verbose):
            logger.debug(f"Access token is {access_token!r}")
            # This is a JWT, so we take the payload segment, decode it and take
            # the tax code from there. This is pretty much what the app does and
            # why the GIA login is needed in the first place: it's entirely redundant,
            # and the tax code is enough
            arguments.tax_code = json.loads(b64decode(access_token.split(".")[1]))["fiscalCode"]
            logger.info("Logged in successfully!")
        else:
            return -1
    logger.info(f"Authenticating as '{arguments.tax_code}'")
    async with httpx.AsyncClient(
        # We mimic the app's headers. Specifically, this is my Xiaomi Mi 11i, lol
        headers={
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; M2012K11G Build/RKQ1.201112.002)",
            # I seriously have no idea what the app designers were thinking, but
            # I'll try to keep the cringe aside for a moment and explain why this
            # works. The original UniVR app sends HTTP requests to various endpoints
            # on the university's cluster and to authenticate those requests the server
            # requires an "Authorizations" header (NOT to be confused with the standard
            # "Authorization" header. Because why use standards?) that is just a hex-encoded
            # SHA256 digest of the student's tax code with a constant string appended to it
            # (so it's SHA256(c + m), NOT SHA256(c) + m). The incriminated hardcoded string
            # was taken from the decompiled source code of the app itself. I don't think
            # I need to elaborate further on why this shitfuckery is a bad idea
            "Authorizations": sha256(f"{arguments.tax_code}l_ht7fver".encode()).hexdigest(),
            "Content-Type": "application/json; charset=utf-8",
            "Accept-Encoding": "gzip",
            "Connection": "Keep-Alive",
        }
    ) as client:
        logger.debug(f"Sending request to {GET_ALL_LESSONS_URL.format(arguments.tax_code)}")
        if check_response(
            logger,
            result := await send_request(client, "get", GET_ALL_LESSONS_URL.format(arguments.tax_code)),
            arguments.verbose,
        ):
            return 1
        logger.debug(f"Request to {result.url} sent, status code is {result.status_code}")
        try:
            if json.loads(result.text) != {}:
                # The API returns an empty JSON object to unauthenticated
                # requests
                logger.info(f"Tax code is valid! You can now leave this program running in the background")
                while True:
                    if check_response(
                        logger,
                        result := await send_request(client, "get", GET_BOOKABLE_LESSONS_URL.format(arguments.tax_code)),
                        arguments.verbose,
                    ):
                        continue   # Tries again
                    else:
                        entries = []
                        for chunk in json.loads(result.text):
                            # Lessons are divided according to chunks of the
                            # day, usually from 7:00 to 14:00 and from 14:00 to 22:00
                            for lesson in chunk["prenotazioni"]:
                                if lesson["prenotabile"] and not lesson["prenotata"]:
                                    if lesson["presenti"] < lesson["capacita"]:
                                        logger.info(
                                            f"Booking lesson {lesson['nome']!r} ({lesson['entry_id']}) scheduled at "
                                            f"{chunk['data']} from {lesson['ora_inizio']} to"
                                            f" {lesson['ora_fine']} in {chunk['sede']!r} in classroom {lesson['aula']!r} "
                                            f"({lesson['capacita'] - lesson['presenti']}/{lesson['capacita']}"
                                            f" seats remaining)"
                                        )
                                        entries.append(lesson["entry_id"])
                                    else:
                                        logger.warning(
                                            f"Lesson {lesson['nome']!r} ({lesson['entry_id']}) scheduled at"
                                            f"{chunk['data']} from {lesson['ora_inizio']} to"
                                            f" {lesson['ora_fine']} in {chunk['sede']} in classroom"
                                            f" {lesson['aula']!r} has 0 remaining seats out of {lesson['capacita']}!"
                                        )
                        for entry in entries:
                            # We _could_ send all entries at once, since the entry parameter is an
                            # array, but this gives us finer error handling and makes it so that if
                            # one lesson is not bookable it doesn't affect the others. Maybe the API
                            # already does this, but I'm too lazy to find out
                            logger.debug(f"Sending request to {BOOK_LESSON_URL} for entry {entry}")
                            if check_response(
                                logger,
                                result := await send_request(
                                    client,
                                    "post",
                                    BOOK_LESSON_URL,
                                    data=json.dumps({"CodiceFiscale": arguments.tax_code, "entry": [entry]}),
                                ),
                                arguments.verbose,
                            ):
                                entries.remove(entry)
                            logger.debug(f"Request to {result.url} sent, status code is {result.status_code}, payload is {result.content}")
                    logger.info(
                        f"Booked {len(entries)} lesson{'' if len(entries) == 1 else 's'}, sleeping for {arguments.delay} seconds"
                    )
                    await asyncio.sleep(arguments.delay)
            else:
                logger.error(f"The provided tax code does not appear to be valid, please check for any typos and try again")
                return -1
        except json.decoder.JSONDecodeError as json_error:
            logger.error(f"A fatal JSON decoding error occurred -> {type(json_error).__name__}: {json_error}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="UniVRAutoLessonBooker",
        description="Automatically books all the lessons for your course (selected via the"
        " UniVR Lessons app) to make sure you never lose class ever again!",
    )
    parser.add_argument("-c", "--tax-code", help="Your tax code ('codice fiscale'). If not provided,"
                                                 " the program will get it for you using your GIA"
                                                 " credentials", required=False)
    parser.add_argument(
        "-d",
        "--delay",
        help="The amount of time in seconds that the bot should sleep before querying"
        " the APIs again, defaults to 300 (5 minutes)",
        default=300,
        type=int,
    )
    parser.add_argument(
        "-v", "--verbose", help="Increase log message verbosity. For advanced users only!", action="store_true"
    )
    parser.add_argument("-l", "--log-file", help="Tells the script to also write logs on the specified file (relative"
                                                 " or absolute paths are both accepted). Defaults to no file (i.e. no"
                                                 " file logging)", default=None)
    loop = asyncio.get_event_loop()
    try:
        main_task = asyncio.ensure_future(main(parser.parse_args()))
        for sig in [SIGINT, SIGTERM]:
            loop.add_signal_handler(sig, main_task.cancel)
        sys.exit(loop.run_until_complete(main_task))
    except asyncio.exceptions.CancelledError:
        print()
    finally:
        loop.close()
