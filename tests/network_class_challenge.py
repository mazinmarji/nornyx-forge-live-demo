"""The adversarial challenge of the network-capability defect class (A-053).

Every way this cycle's review found, or its builder could find, to reach a
network primitive -- a network module, an asyncio network helper, or an
accessor that reaches either by a string -- from a module OUTSIDE an explicit
side-effect directory, each as a subject source. `test_capability_guard.py`
holds each one refused by the verifier's static layer: the network marker,
the fail-closed reference rule, or the interpreter-control refusal that
already existed. What static analysis cannot reach is not here; A-053 lists
it as the limit.

Not collected (the name does not start with `test_`), never shipped.
"""

from __future__ import annotations

#: label -> subject source. Every one must be refused outside an adapter.
CHALLENGE = {
    # Every binding form of the accessor.
    "assign": "fetch = getattr\n",
    "annotated assign": "fetch: object = getattr\n",
    "walrus": "if (fetch := getattr):\n    pass\n",
    "tuple target": "fetch, size = getattr, len\n",
    "augmented assign": "accessors = []\naccessors += [getattr]\n",
    "for target": "for fetch in (getattr,):\n    pass\n",
    "default argument": "def pick(obj, fetch=getattr):\n    return fetch(obj, 'x')\n",
    "lambda body": "pick = lambda: getattr\n",
    "lambda default": "pick = lambda fetch=getattr: fetch\n",
    "comprehension": "accessors = [getattr for _ in range(1)]\n",
    "global rebinding": "def bind():\n    global fetch\n    fetch = getattr\n",
    "nonlocal name": "def outer():\n    getattr = len\n    def inner():\n        nonlocal getattr\n",
    "dict value": "TABLE = {'fetch': getattr}\n",
    "class attribute": "class Holder:\n    fetch = getattr\n",
    "instance attribute": "class Holder:\n    def __init__(self):\n        self.fetch = getattr\n",
    "decorator returning it": "def deco(function):\n    return getattr\n",
    "passed as an argument": "HANDLE = list(map(getattr, [], []))\n",
    "partial": "import functools\nHANDLE = functools.partial(getattr, object())\n",
    "starred call": "def pick(*arguments):\n    return getattr(*arguments)\n",
    "keyword call": "def pick(obj):\n    return getattr(obj, name='x')\n",
    "computed member": "import asyncio\nHANDLE = getattr(asyncio, 'open_' + 'connection')\n",
    "rebound name": "getattr = print\n",
    "function named like it": "def getattr(obj, name):\n    return name\n",
    "handler named like it": "try:\n    pass\nexcept Exception as getattr:\n    pass\n",
    "pattern capture": "match 1:\n    case getattr:\n        pass\n",
    # Imported aliases and star imports.
    "module alias": "import socket as wire\n",
    "member alias": "from socket import create_connection as dial\n",
    "parent alias": "from urllib import request as fetch_url\n",
    "helper alias": "from asyncio import open_connection as dial\n",
    "helper from a submodule": "from asyncio.base_events import BaseEventLoop\nHANDLE = BaseEventLoop.create_connection\n",
    "socket star": "from socket import *\n",
    "asyncio star": "from asyncio import *\n",
    "builtins star": "from builtins import *\n",
    "accessor imported": "from builtins import getattr as fetch\n",
    "import inside a function": "def late():\n    import socket\n    return socket\n",
    "logging handlers": "import logging.handlers\n",
    "logging handlers by attribute": "import logging\nHANDLE = logging.handlers.SMTPHandler\n",
    # Attribute access on any object.
    "helper on a loop": "def go(loop):\n    return loop.create_connection\n",
    "sock helper on a loop": "def go(loop):\n    return loop.sock_connect\n",
    "server helper on anything": "def go(thing):\n    return thing.start_server\n",
    "helper on a class": "def go(loop):\n    return type(loop).create_server\n",
    "socket another module imported": "import email.utils\nHANDLE = email.utils.socket\n",
    "urllib another module imported": "import xml.sax.saxutils\nHANDLE = xml.sax.saxutils.urllib\n",
    "sendfile": "import os\nHANDLE = os.sendfile\n",
    "helper matched by a class pattern": (
        "def go(loop):\n    match loop:\n        case object(create_connection=dial):\n"
        "            return dial\n"),
    # Lookups by a literal.
    "literal getattr naming a helper": "def go(loop):\n    return getattr(loop, 'create_server')\n",
    "vars lookup": "import asyncio\nHANDLE = vars(asyncio)['open_connection']\n",
    "globals lookup": "HANDLE = globals()['__builtins__']\n",
    "locals reference": "HANDLE = locals\n",
    "module dict lookup": "import asyncio\nHANDLE = asyncio.__dict__['open_connection']\n",
    "sys.modules subscript": "import sys\nHANDLE = sys.modules['socket']\n",
    "sys.modules get": "import sys\nHANDLE = sys.modules.get('socket')\n",
    "attrgetter": "import operator\nHANDLE = operator.attrgetter('open_connection')\n",
    "attrgetter imported": "from operator import attrgetter\n",
    "methodcaller": "import operator\nHANDLE = operator.methodcaller('create_connection')\n",
    "format field": "import string\nHANDLE = string.Formatter().get_field\n",
    "getattribute": "def go(loop):\n    return object.__getattribute__(loop, 'create_server')\n",
    "module getattr hook": "import asyncio\nHANDLE = asyncio.__getattr__\n",
    # The builtins namespace and the import machinery.
    "builtins name": "HANDLE = __builtins__\n",
    "builtins module": "import builtins\n",
    "dunder import": "HANDLE = __import__('socket')\n",
    "dunder import reference": "loader = __import__\n",
    "importlib": "import importlib\nHANDLE = importlib.import_module('socket')\n",
    "importlib util": "import importlib.util\n",
    "module loader": "HANDLE = __loader__\n",
    "module spec": "HANDLE = __spec__\n",
    "pkgutil": "import pkgutil\nHANDLE = pkgutil.resolve_name('socket')\n",
    "runpy": "import runpy\n",
    "pickle": "import pickle\n",
    "marshal": "import marshal\n",
    "timeit": "import timeit\n",
    "doctest": "import doctest\n",
    "code": "import code\n",
    # Split so that this file's own text holds no call the repository's
    # security gate refuses; the subject source is the joined string.
    "eval": "HANDLE = ev" "al('1')\n",
    "exec": "ex" "ec('x = 1')\n",
    "compile": "HANDLE = compile('x = 1', 'x', 'exec')\n",
    "type hints": "import typing\nHANDLE = typing.get_type_hints\n",
    "breakpoint": "breakpoint()\n",
    "help": "help('socket')\n",
    "subclasses walk": "HANDLE = ().__class__.__base__.__subclasses__()\n",
    "ctypes": "import ctypes\n",
}

#: label -> subject source that must stay accepted outside an adapter.
CONTROLS = {
    "a direct literal getattr": "def name_of(obj):\n    return getattr(obj, '__name__')\n",
    "a direct literal getattr with a default": (
        "def label_of(obj):\n    return getattr(obj, 'label', '')\n"),
    "asyncio for non-network work": (
        "import asyncio\n\nTIMEOUT = asyncio.TimeoutError\n\n"
        "def queue():\n    return asyncio.Queue()\n"),
    "urllib.parse": "import urllib.parse\nHANDLE = urllib.parse.quote\n",
    "a list called requests": "requests = []\nrequests.append(1)\n",
    "a method called request": "class Book:\n    def request(self, operation):\n        return operation\n",
    "json and pathlib": "import json\nfrom pathlib import Path\nHANDLE = json.loads(Path('x').name)\n",
}
