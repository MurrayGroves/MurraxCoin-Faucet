#!/bin/bash
nohup gunicorn -b "localhost:8000" faucet.wsgi &