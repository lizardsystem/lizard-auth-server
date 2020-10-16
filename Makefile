#   Note: Makefiles need TABS.

install:
	mkdir -p var/log var/media var/static
	pip install -r requirements.txt
	python3 manage.py collectstatic --noinput

beautiful:
	isort -rc lizard_auth_server
	black setup.py lizard_auth_server
