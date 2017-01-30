
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
**Pasting text** is as simple as `stickypaste.py paste --data "this is my text"`. This will create a paste on paste.kde.org, containing the text. The resulting url will be printed to `stdout`.

But usually, you don't want to paste a simple line of text. Well, good news: **pasting files** is as easy. Just use `stickypaste.py paste --file <filename>`.

The `--data` and `--file` parameters are both optional, so when you omit both, input will be read from stdin. (See section 'use in scripts')

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


### Use in scripts
If neither `--data` nor `--file` is given, the text to paste will be read from stdin. That means, if you've got an unix shell handly, you can use fancy things like this: `stickypaste.py paste < file.txt`. Of course this also works for piping input into the script: `dpkg -l | stickypaste.py paste`

Taking this even further, you can go ahead and pipe the stdout of the script into another command: `ls -al ~ | stickypaste.py -q paste -p | xclip`, which will copy the resulting url to clipboard.

Or, simply just open it in your browser directly: `xdg-open $(ls -al / | stickypaste.py -q paste -p -e 1800)`

- Note the extra argument `-q` to stickypaste, which will suppress anything but the resulting url being written to stdout (quiet mode). This is especially useful for scripts where you want to re-use the output.
- Also, there now are the arguments `-p` and `-e 1800` given to the `paste` subcommand. The first will make your paste private, the latter will make it expire after 30 minutes.



## TODO / planned features
-[ ] Finish the script; implement `show` and `list`
-[x] allow for piping input into the script (`cat somefile.txt | stickypaste.py paste`)
-[x] let the script read the input text directly from a file (`stickypaste.py paste --file somefile.txt`)
-[ ] base the auto-set language on the file's actualy mimetype
-[ ] make some kind of better docs
