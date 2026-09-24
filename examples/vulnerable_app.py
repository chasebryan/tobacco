"""Intentionally unsafe source for demonstrating Tobacco. Do not deploy it.

Scan this file; there is no need to run it. All values are synthetic.
"""

import pickle
import subprocess
import tempfile


def search_users(cursor, username):
    return cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")


def inspect_host(host):
    return subprocess.run("ping -c 1 " + host, shell=True)


def restore_session(payload):
    return pickle.loads(payload)


def calculate(expression):
    return eval(expression)


def temporary_path():
    return tempfile.mktemp()
