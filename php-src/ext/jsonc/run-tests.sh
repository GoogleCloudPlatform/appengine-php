#!/usr/bin/bash

cd $(dirname $0)

TEST_PHP_EXECUTABLE=$(which php) \
TEST_PHP_ARGS="-n -d extension_dir=$PWD/modules -d extension=json.so" \
NO_INTERACTION=1 \
REPORT_EXIT_STATUS=1 \
php -n run-tests.php $* | tee STATUS

sed -e 's/^TEST.*\x0d//' -i STATUS

