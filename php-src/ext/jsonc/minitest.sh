#!/usr/bin/bash

#php -n -d extension_dir=modules -d extension=json.so --re json

old=$(mktemp)
new=$(mktemp)
ext=$(php -r 'echo ini_get("extension_dir");')

php -n -d extension_dir=$ext    -d extension=json.so minitest.php >$old
php -n -d extension_dir=modules -d extension=json.so minitest.php >$new

if ! diff -u $old $new; then
    echo 'Perfect !'
fi
rm -f $old $new

