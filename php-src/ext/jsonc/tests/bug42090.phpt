--TEST--
Bug #42090 (json_decode causes segmentation fault)
--SKIPIF--
<?php if (!extension_loaded("json")) print "skip"; ?>
--XFAIL--
New parser is less strict, produce different result, but don't crash.
--FILE--
<?php
var_dump(
	json_decode('""'),
	json_decode('"..".'),
	json_decode('"'),
	json_decode('""""'),
	json_encode('"'),
	json_decode(json_encode('"')),
	json_decode(json_encode('""'))
);
?>
--EXPECT--
string(0) ""
NULL
NULL
NULL
string(4) ""\"""
string(1) """
string(2) """"
