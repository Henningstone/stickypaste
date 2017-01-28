#!/usr/bin/python3

import sys
import argparse
import requests
import json

VERSION = 20170128

args = None


def dbg_msg(msg="", verbosity=0):
    # intended verbosity levels: 0-2
    if args.verbose >= verbosity:
        print(msg)


def optarg(name):
    res = getattr(args, name, None)
    if res is None:
        return None
    elif isinstance(res, type([])):
        return res[0]
    else:
        return res


def fix_hostname(host):
    if not host.startswith("http"):  # allow for https://
        return "http://" + host  # default to http://
    return host


def get_endpoint_url(host, action):
    host = fix_hostname(host)
    return host + "/api/json/" + action


def payload_add(payload, key, value):
    if payload is None:
        payload = {}
    if value is not None:
        payload[key] = value


def action_paste():
    global args
    # arguments processed by this function:
    #  title    opt str     None    omit
    #  private  def bool    false   omit
    #  password opt str     None    omit
    #  expire   opt int     None    omit
    #  data     req str
    # inherited from global:
    #  host     opt str "paste.kde.org"
    #  project  opt str     None    omit

    host = optarg('host')

    data = args.data
    language = args.language
    title = optarg('title')
    private = args.private
    password = optarg('password')
    expire = optarg('expire')
    project = optarg('project')

    dbg_msg("Creating paste on " + host, 0)

    dbg_msg("Title is {}".format(title if title is not None else "chosen based on the paste's ID"), 1)
    dbg_msg("No password given" if password is None else "Password is '{}'".format(password), 1)
    dbg_msg("Paste will be {}".format("private" if private else "public"), 2)
    dbg_msg("Using default expire" if expire is None else "Using expire of {} minutes".format(expire), 2)
    dbg_msg("Language is " + language)
    dbg_msg("Host is " + host, 2)
    dbg_msg("Project is {}".format("omitted" if project is None else project), 2)
    dbg_msg("DATA: " + data, 3)

    # the api endpoint
    url = get_endpoint_url(host, 'create')

    # mandatory parts of the payload
    payload = {}
    payload_add(payload, 'data', data)
    payload_add(payload, 'language', language)
    payload_add(payload, 'title', title)
    payload_add(payload, 'private', private)
    payload_add(payload, 'password', password)
    payload_add(payload, 'expire', expire)
    payload_add(payload, 'project', project)
    dbg_msg("PAYLOAD: " + str(payload), 3)

    dbg_msg()
    r = requests.post(url, json=payload)
    dbg_msg("RESULT: " + str(r.status_code), 2)
    try:
        r.raise_for_status()
    except requests.exceptions.HTTPError:
        dbg_msg("Failed to create the paste")
        return 1

    dbg_msg(r.text, 2)
    result = json.loads(r.text)

    # check for errors returned by the API
    try:
        error = result['result']['error']

        if error == 'err_cannot_post':
            dbg_msg("The site has disabled public posting")
        elif error == 'err_title_max_30':
            dbg_msg("Title cannot be longer than 30 characters")
        elif error == 'err_data_required':
            dbg_msg("Paste body was not sent")
        elif error == 'err_data_too_big':
            dbg_msg("Paste body exceeds maximum size configured for the site")
        elif error == 'err_lang_required':
            dbg_msg("Paste language was not specified")
        elif error == 'err_lang_invalid':
            dbg_msg("An invalid language was used")
        elif error == 'err_expire_integer':
            dbg_msg("The paste expiration value must be an integer")
        elif error == 'err_expire_invalid':
            dbg_msg("An invalid expiration time was used")  # TODO param action
        return 1

    except KeyError:  # no errors
        paste_addr = fix_hostname(host) + "/" + result['result']['id']
        if private or password is not None:
            paste_addr = paste_addr + "/" + result['result']['hash']
        dbg_msg(paste_addr, -1)
        if password is not None:
            dbg_msg("Password: '{}'".format(password), -1)

    return 0


def action_show():
    pass


def action_list():
    pass


def main():
    global args

    parser = argparse.ArgumentParser(description='Paste scripts to a sticky-notes API (by default paste.kde.org)')
    parser.add_argument("--version", help="print the version and exit", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--verbose", "-v", help="be more verbose", action="count", default=0)
    group.add_argument("--quiet", "-q", help="only output the resulting paste's url, or nothing on failure (useful for usage in scripts)", action="store_true")

    parser.add_argument("--host", help="the API url (defaults to paste.kde.org of omitted)", nargs=1, default="https://paste.kde.org")
    parser.add_argument("--project", help="Whether to associate the paste with a project (may not be supported by all hosts)", nargs=1)

    subparsers = parser.add_subparsers(title="actions", description="Tells stickypaste what to do", help="use '%(prog)s <action> --help' for help on the actions and their individual arguments")

    # parse 'paste' command
    parser_paste = subparsers.add_parser('paste', help='create a new paste', aliases=['p'])
    parser_paste.add_argument("data", help="the text to paste")
    parser_paste.add_argument("--language", "-l", help="The paste's language; defaults to 'text'", nargs=1, default="text")
    parser_paste.add_argument("--title", "-t", help="The paste title; will be based on generated ID if omitted", nargs=1)
    parser_paste.add_argument("--private", "-p", help="Make the paste private", action="store_true")
    parser_paste.add_argument("--password", help="A password string to protect the paste", nargs=1)
    parser_paste.add_argument("--expire", help="Time in minutes after which paste will be deleted from server", metavar="SECONDS", type=int, nargs=1)
    parser_paste.set_defaults(func=action_paste)

    # parse 'show' command
    parser_show = subparsers.add_parser('show', help='show an existing paste', aliases=['s'])
    parser_show.add_argument("id", help="The unique paste identifier", nargs=1)
    parser_show.add_argument("--hash", "-k", help="Hash/key for the paste (only for private pastes)", nargs=1)
    parser_show.add_argument("--password", "-p", help="Password to unlock the paste (only for protected pastes)", nargs=1)
    parser_show.set_defaults(func=action_show)

    # parse 'list' command
    parser_list = subparsers.add_parser('list', help='get a list of pastes IDs', aliases=['l'])
    parser_list.add_argument("page", help="The list page to be fetched", nargs=1)
    parser_list.set_defaults(func=action_list)

    args = parser.parse_args()

    if args.version:
        print("Version: " + str(VERSION))
        exit(0)

    if args.quiet:
        args.verbose = -1

    if hasattr(args, 'func'):
        return args.func()
    else:
        print("Invalid usage, try {} --help".format(sys.argv[0]))
        exit(1)


if __name__ == '__main__':
    main()
