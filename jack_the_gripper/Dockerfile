FROM python:3.12 AS requirements-stage

WORKDIR /tmp

RUN pip install poetry

COPY ./pyproject.toml ./poetry.lock* /tmp/

RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM python:3.12

WORKDIR /jack_the_gripper

COPY --from=requirements-stage /tmp/requirements.txt /jack_the_gripper/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /jack_the_gripper/requirements.txt

COPY ./jack_the_gripper .env /jack_the_gripper/

CMD ["fastapi", "dev", "api/main.py", "--host", "0.0.0.0", "--port", "8080"]
