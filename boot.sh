#!/bin/bash
nohup gunicorn -b "localhost:8001" faucet.wsgi &