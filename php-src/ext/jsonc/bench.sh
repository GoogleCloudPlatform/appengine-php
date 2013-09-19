#!/usr/bin/bash

cd $(dirname $0)

ext=$(php -r 'echo ini_get("extension_dir");')

php -n -d extension_dir=$ext    -d extension=json.so bench.php
php -n -d extension_dir=modules -d extension=json.so bench.php

