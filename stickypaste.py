#!/usr/bin/python3

import sys
import argparse
import httplib2
import urllib3

VERSION = 20170128
args = None


def create_paste():
    pass


def main():
    global args

    parser = argparse.ArgumentParser(description='Paste scripts to a sticky-notes API (by default paste.kde.org)')
    parser.add_argument("--version", help="print the version and exit", action="store_true")
    parser.add_argument("--verbose", "-v", help="be more verbose", action="count")

    parser.add_argument("--host", help="the API url (defaults to paste.kde.org of omitted)", nargs=1, default="https://paste.kde.org")
    parser.add_argument("--project", help="Whether to associate the paste with a project (may not be supported by all hosts)", nargs=1)
    subparsers = parser.add_subparsers(title="actions", description="what to do", help="use '%(prog)s <action> --help' for more")

    # parse 'paste' command
    parser_paste = subparsers.add_parser('paste', help='create a new paste')
    parser_paste.add_argument("--title", "-t", help="The paste title, random if omitted", nargs=1)
    parser_paste.add_argument("--private", "-p", help="Make the paste private", action="store_true")
    parser_paste.add_argument("--expire", help="Time in minutes after which paste will be deleted from server", metavar="SECONDS", type=int, nargs=1)
    parser_paste.add_argument("data", help="the text to paste")

    # parse 'show' command
    parser_show = subparsers.add_parser('show', help='show an existing paste')
    parser_show.add_argument("id", help="The unique paste identifier")
    parser_show.add_argument("--hash", "-k", help="Hash/key for the paste (only for private pastes)")
    parser_show.add_argument("--password", "-p", help="Password to unlock the paste (only for protected pastes)")

    # parse 'list' command
    parser_list = subparsers.add_parser('list', help='get a list of pastes IDs')
    parser_list.add_argument("page", help="The list page to be fetched")

    args = parser.parse_args()


    if args.version:
        print("Version: " + str(VERSION))
        exit(0)

    create_paste()


if __name__ == '__main__':
    main()
