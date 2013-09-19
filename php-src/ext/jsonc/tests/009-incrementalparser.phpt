--TEST--
JsonIncremantalParser::parse() simple test
--SKIPIF--
<?php if (!extension_loaded("json")) print "skip"; ?>
--FILE--
<?php
$parser = new JsonIncrementalParser();

var_dump($parser->getError());
// Simple parse
var_dump($parser->parse('"foo"'));
var_dump($parser->get());
// Simple parse
var_dump($parser->parse('thisisnotjson'));
var_dump($parser->get());
// Reset test
var_dump($parser->reset());
var_dump($parser->get());
// Partial parse
var_dump($parser->parse('["foo",'));
var_dump($parser->get());
// Complete parse
var_dump($parser->parse('"bar"]'));
var_dump($parser->get());
// Object get twice
var_dump($parser->parse('{"One":"foo",'));
var_dump($parser->parse('"Two":"bar"}'));
var_dump($parser->get());
var_dump($parser->get(JSON_OBJECT_AS_ARRAY));
echo "Done\n";
?>
--EXPECT--
int(0)
int(0)
string(3) "foo"
int(6)
NULL
int(0)
NULL
int(1)
NULL
int(0)
array(2) {
  [0]=>
  string(3) "foo"
  [1]=>
  string(3) "bar"
}
int(1)
int(0)
object(stdClass)#2 (2) {
  ["One"]=>
  string(3) "foo"
  ["Two"]=>
  string(3) "bar"
}
array(2) {
  ["One"]=>
  string(3) "foo"
  ["Two"]=>
  string(3) "bar"
}
Done
