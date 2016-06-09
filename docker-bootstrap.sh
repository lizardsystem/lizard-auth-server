#!/bin/bash
echo $PWD
python bootstrap.py
bin/buildout
bin/django syncdb --noinput
bin/django migrate
