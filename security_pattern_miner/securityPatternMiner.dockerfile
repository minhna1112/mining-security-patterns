
# Dockerfile for the code search project
# This Dockerfile sets up a Python environment with necessary dependencies for the project.
# Use a slim version of Python 3.11.13 to reduce image size
FROM python:3.11.13-slim-trixie


RUN apt-get update && apt-get install -y git
COPY ./requirements.txt /security_pattern_miner/requirements.txt
RUN pip install --no-cache-dir -r /security_pattern_miner/requirements.txt
COPY ./src /security_pattern_miner/

WORKDIR /security_pattern_miner/
CMD [ "python", "./runner.py" ]