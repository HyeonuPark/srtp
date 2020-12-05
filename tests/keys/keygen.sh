#!/usr/bin/env bash

openssl req -newkey rsa:4096 -nodes -keyout pkey.pem -x509 -days 36500 -out cert.pem
