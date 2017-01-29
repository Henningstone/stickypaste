#!/usr/bin/python3

import sys
import io
import argparse
import requests
import json

VERSION = 20170129

args = None


def dbg_msg(msg="", verbosity=0):
    # intended verbosity levels: 0-3
    if args.verbose >= verbosity:
        if verbosity > 0:
            msg = "[dbg_lvl={}] {}".format(verbosity, msg)
        print(msg)


def dbg_err(msg):
    print("Error: " + msg, file=sys.stderr)


def optarg(name):
    res = getattr(args, name, None)
    return res


def fix_hostname(host):
    if not host.startswith("http"):  # allow for https://
        return "http://" + host  # default to http://
    return host


def get_endpoint_url(host, action):
    host = fix_hostname(host)
    return host + "/api/json/" + action


def payload_add(payload: dict, key, value):
    if payload is None:
        payload = {}
    if value is not None:
        payload[key] = value


def net_perform_to_json(url, payload, method) -> dict or None:
    """
    Does net_perform and turns the response into json automatically
    """

    response = net_perform(url, payload, method)
    if response is None:
        return None

    return response_to_json(response.text)


def net_perform(url, payload: dict, method: str) -> requests.Response or None:
    try:
        r = None
        if method.upper() == 'POST':
            r = requests.post(url, json=payload, timeout=(2.0, 3.0))  # timeout=(connect, read)
        elif method.upper() == 'GET':
            r = requests.get(url, json=payload, timeout=(2.0, 3.0))  # timeout=(connect, read)

        if r is None:
            raise Exception("field 'method' must be either 'GET' or 'POST'")

        dbg_msg("URL: " + r.url, 3)
        dbg_msg("RESULT: " + str(r.status_code) + " " + r.reason, 2)
        try:
            r.raise_for_status()
        except requests.exceptions.HTTPError:
            dbg_err("HTTP Error: {}".format(str(r.status_code) + " " + r.reason))
            return None
        return r

    except Exception as e:
        dbg_err("network error{}".format("" if e.strerror is None else ": "+e.strerror))
        return None


def response_to_json(plaintext) -> dict or None:
    """Converts the answer to json and performs error checking

    :return: 'None' if errors occurred, otherwise the result as json
    """

    # handle the answer
    dbg_msg(plaintext, 2)
    result = json.loads(plaintext)

    # check for errors returned by the API
    try:
        error = result['result']['error']
        dbg_err(error_to_string(error))
        return None

    except KeyError:  # no errors
        return result


def error_to_string(error):
    # compare https://sayakb.github.io/sticky-notes/pages/api/
    if error == 'err_cannot_post':
        return "The site has disabled public posting"
    elif error == 'err_title_max_30':
        return "Title cannot be longer than 30 characters"
    elif error == 'err_data_required':
        return "Paste body was not sent"
    elif error == 'err_data_too_big':
        return "Paste body exceeds maximum size configured for the site"
    elif error == 'err_lang_required':
        return "Paste language was not specified"
    elif error == 'err_lang_invalid':
        return "An invalid language was used (try '{} param language' to get possible values)".format(sys.argv[0])
    elif error == 'err_expire_integer':
        return "The paste expiration value must be an integer"
    elif error == 'err_expire_invalid':
        return "An invalid expiration time was used (try '{} param expire' to get possible values)".format(sys.argv[0])
    elif error == 'err_not_found':
        return "Paste not found"
    elif error == 'err_invalid_hash':
        return "Invalid hash code for a private paste"
    elif error == 'err_password_required':
        return "Password required to view the paste"
    elif error == 'err_invalid_password':
        return "Incorrect password supplied"
    elif error == 'err_no_pastes':
        return "No pastes found"
    elif error == 'err_invalid_param':
        return "Value list not available for specified parameter"


def fileext_to_lang(extension: str):
    """
    looks up the language which belongs to the given file extension

    Remark: the extension must start with a .
    """
    extension = extension.lower()
    if not extension.startswith('.'):
        return extension

    langdict = {
        'c++': 'cpp',
        'c#': 'cs',
        # TODO: add more as necessary
    }

    # remove the leading period
    extension = extension[1:]

    language = langdict.get(extension)
    if language is None:
        dbg_msg("could not find a language for '.{}', using the file's extension instead (provide --language to prevent this)".format(extension), 3)
        return extension

    dbg_msg("guessed extension '{}' to be language '{}'".format(extension, language), 3)
    return language


def guess_file_language(filepath: str):
    filename = filepath.split('/')[-1]
    dbg_msg("guessing language of file; path='{}', filename='{}'".format(filepath, filename), 3)
    if filename.find('.') == -1:
        return "text"

    extension = filename[filename.rfind('.'):]
    language = fileext_to_lang(extension)
    return language


def action_paste():
    global args
    # arguments processed by this function:
    #  title    opt str     None    omit
    #  private  def bool    false   omit
    #  password opt str     None    omit
    #  expire   opt int     None    omit
    #  file     opt bool    false
    #  data     req str
    # inherited from global:
    #  host     opt str "paste.kde.org"
    #  project  opt str     None    omit

    host = optarg('host')
    project = optarg('project')

    data = args.data
    language = optarg('language')
    title = optarg('title')
    private = args.private
    password = optarg('password')
    expire = optarg('expire')
    from_file = optarg('file')
    filename = data if from_file else "command line"

    if from_file:
        try:
            f = io.open(filename)
            data = f.read()
            f.close()
        except IOError as e:
            dbg_err("Failed to read from file '{}': {}".format(e.filename, e.strerror))
            return 1

    language_auto = False
    if language is None:
        if from_file:
            language = guess_file_language(filename)
            language_auto = True
        else:
            language = "text"

    dbg_msg("Creating {} paste on {}".format("private" if private else "public", host), 0)

    dbg_msg("Title is {}".format(title if title is not None else "chosen based on the paste's ID"), 1)
    dbg_msg("No password given" if password is None else "Password is '{}'".format(password), 1)
    dbg_msg("Using default expire time" if expire is None else "Paste will expire after {} minutes".format(expire), 2)
    dbg_msg("Paste's language is set to '{}'{}".format(language, " (auto set, provide '--language <lang>' to prevent this)" if language_auto else ""), 1)
    dbg_msg("Project is {}".format("omitted" if project is None else project), 3)
    dbg_msg("Data is read from {}".format(filename if from_file else "command line"), 2)
    dbg_msg("DATA: " + data, 4)

    # the api endpoint
    url = get_endpoint_url(host, 'create')

    # prepare the payload
    payload = {}
    payload_add(payload, 'project', project)
    payload_add(payload, 'language', language)
    payload_add(payload, 'title', title)
    payload_add(payload, 'private', private)
    payload_add(payload, 'password', password)
    payload_add(payload, 'expire', expire)
    payload_add(payload, 'data', data)
    dbg_msg("FULL PAYLOAD: " + str(payload), 4)
    dbg_msg()

    # send the request
    result = net_perform_to_json(url, payload, 'POST')
    if result is None:
        return 1

    # handle the response
    paste_addr = fix_hostname(host) + "/" + result['result']['id']
    if private or password is not None:
        paste_addr = paste_addr + "/" + result['result']['hash']
    dbg_msg(paste_addr, -1)
    if password is not None:
        dbg_msg("Password: '{}'".format(password), -1)

    return 0


def action_show():
    global args
    pass


def action_list():
    global args
    pass


def action_param():
    global args
    # arguments processed by this function:
    #  param    req str
    # inherited from global:
    #  host     opt str "paste.kde.org"
    #  project  opt str     None    omit

    host = optarg('host')
    project = optarg('project')

    param = args.param

    # the api endpoint
    url = get_endpoint_url(host, 'parameter') + "/" + param

    # prepare the payload
    payload = {}
    payload_add(payload, 'project', project)
    payload_add(payload, 'param', param)
    dbg_msg("PAYLOAD: " + str(payload), 3)
    dbg_msg()

    # send the request
    result = net_perform_to_json(url, payload, 'GET')
    if result is None:
        return 1

    # handle the response
    dbg_msg("Values for parameter '{}':".format(param))
    accepted = result['result']['values']
    dbg_msg(accepted, -1)

    return 0


def main():
    global args

    parser = argparse.ArgumentParser(description='Paste text to a sticky-notes API (by default paste.kde.org)')
    parser.add_argument("--version", help="print the version and exit", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--verbose", "-v", help="be more verbose", action="count", default=0)
    group.add_argument("--quiet", "-q", help="only output the resulting paste's url, or nothing on failure (useful for usage in scripts)", action="store_true")

    parser.add_argument("--host", help="the API url (defaults to paste.kde.org of omitted)", default="https://paste.kde.org")
    parser.add_argument("--project", help="Whether to associate the paste with a project (may not be supported by all hosts)")

    subparsers = parser.add_subparsers(title="actions", description="Tells stickypaste what to do", help="use '%(prog)s <action> --help' for help on the actions and their individual arguments")

    # parse 'paste' command
    parser_paste = subparsers.add_parser('paste', help='create a new paste', aliases=['p'])
    parser_paste.add_argument("data", help="the text to paste (in combination with --file: the path to the file to paste")
    parser_paste.add_argument("--language", "-l", help="The paste's language; defaults to 'text'")
    parser_paste.add_argument("--title", "-t", help="The paste title; will be based on generated ID if omitted")
    parser_paste.add_argument("--private", "-p", help="Make the paste private", action="store_true")
    parser_paste.add_argument("--password", help="A password string to protect the paste")
    parser_paste.add_argument("--expire", "-e", help="Time in minutes after which paste will be deleted from server", metavar="SECONDS", type=int)
    parser_paste.add_argument("--file", "-f", help="take the data from this file instead of the commandline", action="store_true")
    parser_paste.set_defaults(func=action_paste)

    # parse 'show' command
    parser_show = subparsers.add_parser('show', help='show an existing paste', aliases=['s'])
    parser_show.add_argument("id", help="The unique paste identifier")
    parser_show.add_argument("--hash", "-k", help="Hash/key for the paste (only for private pastes)")
    parser_show.add_argument("--password", "-p", help="Password to unlock the paste (only for protected pastes)")
    parser_show.set_defaults(func=action_show)

    # parse 'list' command
    parser_list = subparsers.add_parser('list', help='get a list of pastes IDs', aliases=['l'])
    parser_list.add_argument("page", help="The list page to be fetched")
    parser_list.set_defaults(func=action_list)

    # parse 'param' command
    parser_param = subparsers.add_parser('param', help='get certain server-side parameters', aliases=['setting'])
    parser_param.add_argument("param", help="which parameter to request", choices=['expire', 'language', 'version', 'theme'])
    parser_param.set_defaults(func=action_param)

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
