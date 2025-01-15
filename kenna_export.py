#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
"""KENNA DATA EXPORTER:
=======================================================================================
Utility CLI to export predefined Kenna export payloads.
"""
import json
import argparse
import os
import sys
from datetime import datetime
from http.client import HTTPConnection
from time import sleep
from loguru import logger
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings


# constants
DOWNLOADS = os.path.join(os.path.expanduser('~'), 'Downloads')
CWD = os.getcwd()
LOGS = os.path.join(CWD, 'logs')
SCRIPT_NAME = os.path.basename(__file__)[:-3]
DTTM_STR = datetime.now().strftime("%Y%m%d_%H%M%S")

# create logger and set log level
log_format = ("<g>{time}</g> | <lvl>{level}</lvl> | <c>{line}</c> | <m>{file}</m> "
              "| <m>{module}.{function}</m> | <e>{message}</e>")

logger.remove()
logger.add(sys.stdout, colorize=True, format=log_format, level="INFO")
logger.add(f"logs/{SCRIPT_NAME}.log", level="INFO", format=log_format, rotation="100 MB", retention="3 days")


class Kenna:
    """ Kenna Security API Class


    Attributes:
    -----------
        * download_ready
        * search_id


    Methods:
    --------
        * download_export_data
        * request_export_data
        * check-data_export_status
        * monitor_request_export_status

    Note:
    -----
          If sleep times (sleep_duration) are too long or not long enough,
          use the logging time stamp and log messages to obtain a rough
          estimate for sleep duration (message values: 'requesting Kenna data export'
          and 'Kenna data export ready').
    """
    def __init__(self, token: str, payload: dict, base_url: str = 'https://api.kennasecurity.com',
                 ssl_verify: bool = False, stream_resp: bool = False, search_id: int | None = None,
                 block_size: int | None = None, sleep_duration: float | None = None,
                 export_timeout: float | None = None, f_output: str | None = None):
        """

        :param token: API token (Kenna tenant specific)
        :param base_url: API base url (used to specify Kenna instance)
        :param ssl_verify: enable | disable SSL certificate verification
        :param stream_resp: enable | disable streaming of responses (export download will always stream)
        :param search_id: Existing or previous export search_id
        :param block_size: data stream block size
        :param sleep_duration: overrides default (sleep) interval to check export ready status
        :param export_timeout: overrides default data export monitoring timeout (in seconds)
        :param f_output: filepath to save data export gzip file
        """
        _headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-Risk-Token": token
        }

        _base_url: str = base_url if base_url is not None else "https://api.kennasecurity.com"
        self.payload: dict = payload

        self.session: requests.Session = requests.Session()
        self.session.headers = _headers
        self.session.verify = ssl_verify
        self.session.stream = stream_resp

        self.url_exports: str = f"{_base_url}/data_exports"
        self.url_export_status: str = f"{_base_url}/data_exports/status"

        self.search_id: int | None = search_id

        self.block_size: int = block_size if block_size is not None else 8192
        self.sleep_duration: float = sleep_duration if sleep_duration is not None else 600
        self.export_timeout: float = export_timeout if export_timeout is not None else 3600

        self.download_ready: bool = False

        self._file_type: str | None = None
        self.f_output: str | None = None

        self.__get_export_file_type_from_payload()
        self.__verify_output_filepath(filepath=f_output)

    def __get_export_file_type_from_payload(self):
        export_settings = self.payload.get("export_settings")

        if export_settings is not None:
            file_format = export_settings.get("format")
            if file_format is not None:
                self._file_type = file_format

    def __verify_output_filepath(self, filepath: str):
        basename = os.path.basename(filepath)
        dirname = os.path.dirname(filepath)

        path_update = None

        if basename.count('.') <= 1:
            file, ext = os.path.splitext(basename)
            fn = f"{file}.{self._file_type}{ext}"
            logger.warning(f"filepath's filename UPDATED from {basename} to {fn}")

            path_update = os.path.join(dirname, fn)

        else:
            # filepath was ok, return itself
            path_update = filepath

        self.f_output = path_update

    def download_export_data(self, search_id: int, filename: str, block_size: int = 8192) -> bool:
        """ Download Kenna Export Data

        :param search_id: Kenna export request search ID
        :param filename: full filepath to save the export data (gzipped JSON file)
        :param block_size: block size (in bytes) to read/save in response
        :return: download successful - True or False
        """
        self.session.params = {"search_id": search_id}
        self.session.stream = True

        try:
            logger.info(f"downloading export to {filename}")
            resp = self.session.get(url=self.url_exports)

            with open(filename, "wb") as file_gz:
                for block in resp.iter_content(block_size):
                    file_gz.write(block)

        except Exception as err:
            logger.exception(err)
            return False

        else:
            return True

    def request_export_data(self, payload: dict):
        """ Request Kenna Data Export

        Requires valid kenna export request payload.
        If you do not have a payload, see the Kenna API documentation
        for assistance to generate a valid payload.

        https://apidocs.kennasecurity.com/reference/request-data-export

        :param payload: JSON payload
        :return: None - sets Kenna search_id attribute (for class instance)
        """
        try:
            # logging request message needed to assist in determining sleep duration for exports
            logger.info("requesting Kenna data export")
            resp = self.session.post(url=self.url_exports, json=payload)

            if resp.status_code == 200:
                data = resp.json()
                search_id = data.get("search_id")

            else:
                err = f"HTTP {resp.status_code} - {resp.reason}"
                raise ValueError(err)

        except ValueError as val_err:
            logger.exception(val_err)
            self.search_id = None

        except Exception as err:
            logger.exception(err)
            self.search_id = None

        else:
            self.search_id = search_id

    def check_data_export_status(self, search_id: int) -> None | dict:
        """ Check Kenna Data Export Status

        Gets the status message from a previously created asynchronous search using the search_id.

        :param search_id: an ID returned by Request Data Export that identifies the data_export
        :return: a simplified Kenna API export status
        """
        self.session.params = {"search_id": search_id}
        status = None

        try:
            resp = self.session.get(url=self.url_export_status)

            if resp.status_code == 200:
                # message == Export ready for download
                data = resp.json()
                status = {"status": "download", "message": data.get("message")}

            elif resp.status_code == 206:
                # message == The export is currently enqueued/processing. Try again later.
                data = resp.json()
                status = {"status": "wait", "message": data.get("message")}

            else:
                err = f"HTTP {resp.status_code} - {resp.reason}"
                status = {"status": "error", "message": err}

                raise ValueError(err)

        except ValueError as val_err:
            logger.error(val_err)

        except Exception as err:
            logger.exception(err)

        return status

    def monitor_request_export_status(self, search_id: int, sleep_duration: float = 600, timeout: float = 3600):
        """ Monitor Kenna Export Status

        If timeout is reached without the export becoming ready, the script will terminate.

        :param search_id: Kenna export request search ID
        :param sleep_duration: status check interval - defaults to 10 minutes
        :param timeout: stop monitoring Kenna export status and fail after N-seconds
        :return: None - sets class instance download_ready attribute or terminates
        """
        start_time = datetime.now()

        runtime = 0

        while not self.download_ready:

            status_check = self.check_data_export_status(search_id=search_id)
            export_status = None

            if status_check is not None:
                export_status = status_check.get("status")

            logger.info(f"[Export Status] {export_status}")

            if export_status == "download":
                # logging ready status is needed to assist in determining sleep duration for exports
                logger.info("[Export Status] Kenna data export ready")
                self.download_ready = True

            elif export_status == "wait":
                self.download_ready = False

            elif export_status != "download" and export_status != "wait":
                self.download_ready = False
                logger.info(f"[Export Status] Encountered an error, {status_check} - terminating!")

            if not self.download_ready:
                logger.debug(f"[Export Status] not ready - sleeping {sleep_duration} seconds")

                sleep(sleep_duration)

            runtime = (datetime.now() - start_time).total_seconds()

            if runtime > timeout:
                logger.error(f"[Export Status] Monitoring for export status has reached "
                             f"the timeout specified, {timeout} seconds, - terminating!")
                sys.exit(1)


def main():
    token = args.t
    payload = args.p
    f_output = args.fo

    if f_output is None:
        f_output = os.path.join(CWD, f"{SCRIPT_NAME}_{DTTM_STR}.gz")

    if os.path.isfile(payload):
        payload = json.load(open(payload, 'r', encoding='utf-8'))

    else:
        logger.error('JSON path is not valid (data export payload file).')
        sys.exit(1)

    kenna_cfg = dict(token=token, payload=payload, base_url=args.url, ssl_verify=args.sv,
                     stream_resp=args.sr, search_id=args.s, block_size=args.bs,
                     sleep_duration=args.sd, export_timeout=args.et,
                     f_output=f_output)

    if args.d:
        tmp_cfg = kenna_cfg.copy()
        tmp_cfg['token'] = f"{token[:4]}{(len(token)- 6) * '*'}{token[-4:]}"
        logger.debug(f"Kenna Configs: {json.dumps(tmp_cfg)}")

    kenna = Kenna(**kenna_cfg)

    if kenna.search_id is None:
        # if search_id is not provided, perform export request as normal
        logger.debug(f"Search ID not provided, using payload to request Kenna Export.")

        logger.debug(f"[Export Payload] {json.dumps(kenna.payload)}")
        kenna.request_export_data(payload=kenna.payload)

    if kenna.search_id is not None:
        # if search_id is provided or export request has completed correctly,
        # update status or terminate if search_id is None
        logger.info(f"[Export Search ID] {kenna.search_id}")

    else:
        logger.info(f"Export Search ID is None - terminating!")

    # Monitor export status in a loop until timeout exceeded or export is ready for download
    kenna.monitor_request_export_status(search_id=kenna.search_id,
                                        sleep_duration=kenna.sleep_duration,
                                        timeout=kenna.export_timeout)

    if kenna.download_ready:
        logger.debug("[Export Status] export ready to download, requesting export file.")
        download_successful = kenna.download_export_data(search_id=kenna.search_id,
                                                         filename=kenna.f_output,
                                                         block_size=kenna.block_size)

        logger.info(f"Download successful: {download_successful}")

    else:
        logger.info(f"Export never reached a 'ready' status for download.")


if __name__ == '__main__':
    logger.info(f"Logging started")

    arg_prog = SCRIPT_NAME
    arg_usage = f"python {SCRIPT_NAME}.py -t <kenna token> -p <JSON payload filepath> [args]"
    # arg_help = '\nThe Help Message - BLA BLA'
    arg_epilog = f"""
{__doc__}

Output:
--------------------------------------------------------------------------
All data exports are gzip files containing JSON, JSONL, or XML defined in
the export payload.  If an output filepath is not provided, the file
format in the payload file will be used to define the default output
file.  For example, if the export format is JSON, the default output
file will be saved as *.json.gz

NOTE: If a search id is provided (from a previous export) and an output
file is not specified, the default output will not contain the correct
file extension when extracted.


Export Payload Creation:
--------------------------------------------------------------------------
See the Kenna API documentation at
https://apidocs.kennasecurity.com/reference/request-data-export.

After selecting the needed 'Body Params' settings, copy the payload from 
the code window on the right to a JSON file for use with the script.

Debug & Logging:
--------------------------------------------------------------------------
The script logs output at LEVEL 20 (INFO) but can be set to LEVEL 10 
(DEBUG) with the parameter -d.  If additional HTTP logging is needed,
use parameter -dd to enable HTTPClient debugging and logger debugging.
Do not use both -d and -dd.

Log files are created in the '/logs' directory from where the script runs.
"""
    parser = argparse.ArgumentParser(
        prog=arg_prog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=arg_usage,
        add_help=False,
        epilog=arg_epilog
    )

    parser.add_argument('-t', type=str, metavar='token', required=True,
                        help='Kenna API token (REQUIRED).')

    parser.add_argument('-p', type=str, metavar='payload', required=True,
                        help='Filepath to Export payload JSON file (REQUIRED).')

    parser.add_argument('-s', type=int, metavar='search_id', required=False,
                        help='Will ignore payload and skip to checking download status (valid payload still required).')

    parser.add_argument('-sd', type=float, metavar='sleep_duration', required=False,
                        help='Export Status sleep duration interval, default: 10 minutes.')

    parser.add_argument('-et', type=float, metavar='export_timeout', required=False,
                        help='Export Status timeout, default: 1 hour.')

    parser.add_argument('-bs', type=int, metavar='block_size', required=False,
                        help='Data stream block size, default: 8192 bytes.')

    parser.add_argument('-fo', type=str, metavar='f_output', required=False,
                        help='Output filepath, default: "./script_directory/script_filename_DTTM.gz".')

    parser.add_argument('-url', type=str, metavar='base_url',
                        required=False, help='Kenna API base URL, default: "https://api.kennasecurity.com"')

    parser.add_argument('-sv', required=False, action='store_true',
                        help='sets SSL verification to True')

    parser.add_argument('-sr', required=False, action='store_true',
                        help='sets stream API responses to True')

    parser.add_argument('-d', required=False, action='store_true',
                        help='sets logging level to DEBUG')

    parser.add_argument('-dd', required=False, action='store_true',
                        help='sets logging level to DEBUG')

    parser.add_argument('-h', '--help', dest='help', action='help', default=argparse.SUPPRESS)

    args = parser.parse_args()

    # SET DEBUGGING VALUES
    if args.d:
        # update logging level from INFO to DEBUG if parameter is provided
        logger.remove()
        logger.add(sys.stdout, colorize=True, format=log_format, level="DEBUG")
        logger.add(f"logs/{SCRIPT_NAME}.log", level="DEBUG", format=log_format, rotation="100 MB", retention="3 days")

    if args.dd:
        # log requests logging
        HTTPConnection.debuglevel = 1

    else:
        HTTPConnection.debuglevel = 0

    if not args.sv:
        # ignore SSL Verification warnings
        disable_warnings(InsecureRequestWarning)

    main()
