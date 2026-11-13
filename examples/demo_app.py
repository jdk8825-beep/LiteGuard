"""Deliberately insecure demo file. Run `liteguard scan examples` to see LiteGuard catch these."""
import hashlib
import subprocess

import requests


def run(cmd):
    return subprocess.run(cmd, shell=True)  # command injection risk


def calc(expr):
    return eval(expr)  # arbitrary code execution


def fetch(url):
    return requests.get(url, verify=False)  # TLS checks disabled


def fingerprint(data):
    return hashlib.md5(data).hexdigest()  # weak hash


def find_user(cur, name):
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")  # SQL injection
