#   Note: Makefiles need TABS.

install: bin
	mkdir -p var/log var/media var/static
	bin/pip install -r requirements.txt
	bin/python manage.py collectstatic --noinput

bin:
	python3 -m venv .
	bin/pip  install --upgrade pip wheel setuptools

beautiful:
	isort -rc lizard_auth_server
	black setup.py lizard_auth_server

clean:
	rm -rf bin lib share
