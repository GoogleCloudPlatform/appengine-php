--TEST--
json_decode() with large integers
--SKIPIF--
<?php
if (!extension_loaded("json")) print "skip"; 
if (PHP_INT_SIZE != 8) die("skip this test is for 64bit platform only");
?>
--FILE--
<?php
$json = '{"largenum":123456789012345678901234567890}';
$x = json_decode($json);
var_dump($x->largenum);
$x = json_decode($json, false, 512, JSON_BIGINT_AS_STRING);
var_dump($x->largenum);
echo "Done\n";
?>
--EXPECTF--
int(9223372036854775807)

Warning: json_decode(): option JSON_BIGINT_AS_STRING not implemented in %s/008-jsonc.php on line 5
int(9223372036854775807)
Done
