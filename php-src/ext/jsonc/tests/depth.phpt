--TEST--
json_decode() with max recursion depth
--SKIPIF--
<?php if (!extension_loaded("json")) print "skip"; ?>
--FILE--
<?php
var_dump(json_decode("[[1]]", false, 3));
var_dump(json_last_error(), json_last_error_msg());
var_dump(json_decode("[[[1]]]", false, 3));
var_dump(json_last_error(), json_last_error_msg());
var_dump(json_decode("[[[[1]]]]", false, 3));
var_dump(json_last_error(), json_last_error_msg());
echo "Done\n";
?>
--EXPECT--
array(1) {
  [0]=>
  array(1) {
    [0]=>
    int(1)
  }
}
int(0)
string(8) "No error"
NULL
int(1)
string(28) "Maximum stack depth exceeded"
NULL
int(1)
string(28) "Maximum stack depth exceeded"
Done
