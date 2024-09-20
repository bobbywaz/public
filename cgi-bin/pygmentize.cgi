#!/usr/bin/env python3

import sys
import os
from pygments import highlight
from pygments.lexers import get_lexer_for_filename
from pygments.formatters import HtmlFormatter

def main():
    filepath = os.getenv('PATH_TRANSLATED')
    if not filepath or not os.path.isfile(filepath):
        print("Status: 404 Not Found\n")
        print("File not found.")
        return

    lexer = get_lexer_for_filename(filepath)
    formatter = HtmlFormatter(full=True, linenos=True)

    with open(filepath, 'r') as f:
        code = f.read()

    highlighted_code = highlight(code, lexer, formatter)

    print("Content-Type: text/html\n")
    print(highlighted_code)

if __name__ == '__main__':
    main()
