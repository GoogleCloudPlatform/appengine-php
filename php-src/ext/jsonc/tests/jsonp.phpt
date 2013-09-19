--TEST--
json_decode() with comments
--SKIPIF--
<?php if (!extension_loaded("json")) print "skip"; ?>
--FILE--
<?php

$jsons = array(
	"/* hello */\"foo\"",
	"// hello\n\"foo\"",
	"[\"\\n\"]",
	"  {\"one\":1}  ",
);
	
foreach ($jsons as $json) {
	echo "$json: ";
	var_dump(json_decode($json));
}

echo "Done\n";
?>
--EXPECTF--	
/* hello */"foo": string(3) "foo"
// hello
"foo": string(3) "foo"
["\n"]: array(1) {
  [0]=>
  string(1) "
"
}
  {"one":1}  : object(stdClass)#1 (1) {
  ["one"]=>
  int(1)
}
Done
