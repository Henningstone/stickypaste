
# StickyPaste
Python-based command-line client for https://sayakb.github.io/sticky-notes/

This script was initally written to be used for pasting stuff to https://paste.kde.org from the commandline, but as they just use [sayakb](https://github.com/sayakb)'s [sticky-notes backend](https://github.com/sayakb/sticky-notes), it can be used for anything that is built upon it.

Please note that this is still alpha.

## Getting started quickly
### Synopsis
```
usage: stickypaste.py [-h] [--version] [--verbose | --quiet] [--host HOST]
                      [--project PROJECT]
                      {paste,p,show,s,list,l,param,setting} ...
```
**Pasting text** is as simple as `stickypaste.py paste "this is my text"`. This will create a paste on paste.kde.org, containing the text. The resulting url will be printed to `stdout`.


The script expects at least a command (also called action) and it's mandatory argument(s).

Commands are `paste`, `show`, `list` and `param`. (_show_ and _list_ are not yet implemented)

To get general help, use `stickypaste.py --help`.
To get help concerning a command, use `stickypaste.py <command> --help`.



### Advanced options

| Argument        | Description |
|-----------------|-------------|
| `-h` / `--help` | Show help   |
| todo | |
| | todo |



## TODO / planned features
-[ ] Finish the script; implement `show` and `list`
-[x] allow for piping input into the script (`cat somefile.txt | stickypaste.py paste`)
-[x] let the script read the input text directly from a file (`stickypaste.py paste --file somefile.txt`)
-[ ] base the auto-set language on the file's actualy mimetype
-[ ] make some kind of better docs
