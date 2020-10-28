#   Note: Makefiles need TABS.

install: bin requirements.txt
	mkdir -p var/log var/media var/static
	bin/pip install -r requirements.txt
	bin/python manage.py collectstatic --noinput

requirements.txt: requirements.in setup.py
	bin/pip-compile

bin:
	python3 -m venv .
	bin/pip  install --upgrade pip wheel setuptools pip-tools

beautiful:
	isort -rc lizard_auth_server
	black setup.py lizard_auth_server

clean:
	rm -rf bin lib share
