--TEST--
JsonIncremantalParser::parseFile() test
--SKIPIF--
<?php if (!extension_loaded("json")) print "skip"; ?>
--FILE--
<?php
class Foo {
	public $one  = 1;
	public $arr  = array("foo", "bar");
	public $hash = array("One" => 1, "Two" => 2, "Three" =>3);
	public $pi   = 3.14159;
}
$parser = new JsonIncrementalParser();

$fic  = __DIR__.'/minitest.json';
$txt  = "/*\nTest file\n*/\n";
$txt .= json_encode(new Foo(), JSON_PRETTY_PRINT);

file_put_contents($fic, $txt);
var_dump($parser->parseFile($fic));
var_dump($parser->get());	
unlink($fic);

echo "Done\n";
?>
--EXPECT--
int(0)
object(stdClass)#2 (4) {
  ["one"]=>
  int(1)
  ["arr"]=>
  array(2) {
    [0]=>
    string(3) "foo"
    [1]=>
    string(3) "bar"
  }
  ["hash"]=>
  object(stdClass)#3 (3) {
    ["One"]=>
    int(1)
    ["Two"]=>
    int(2)
    ["Three"]=>
    int(3)
  }
  ["pi"]=>
  float(3.14159)
}
Done
