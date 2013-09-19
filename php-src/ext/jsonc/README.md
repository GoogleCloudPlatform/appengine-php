pecl-json-c
===========

JSON-C wrapper

Should be a drop-in alternative to PHP json extension.

json_encode is the same than current PHP one.

json_decode use the json-c library and is mostly compatible.
- > 64 bits integer are always parsed as integer (never float or string)
- 33 to 64 bits bits integer are parsed as float (or string) on 32 bits build
- comments are allowed in json string/files

Also provide a new incremental parser object:

	$parser = new JsonIncrementalParser();
	$fic = fopen("somefile.json", "r");
	do {
		$buf = fgets($fic);
		$ret = $parser->parse($buf);
	} while ($buf && ($ret==JsonIncrementalParser::JSON_PARSER_CONTINUE));
	$result = $parser->get();

or, even simpler:

	$ret = $parser->parseFile("somefile.json");
	$result = $parser->get();

Debian DEB available in unstable for PHP 5.5
- http://packages.debian.org/sid/php5-json

Fedora 19 RPM are available in official repo
- https://apps.fedoraproject.org/packages/php-pecl-jsonc

Fedora RPM are available in remi repo
- http://blog.famillecollet.com/post/2013/06/04/php-pecl-json-1.3.0-en

Windows build are available
- http://windows.php.net/downloads/pecl/releases/jsonc/
- http://windows.php.net/downloads/pecl/deps/

Merged PR in upstream json-c library (release pending)
- number must not have leading zeroes
  https://github.com/json-c/json-c/pull/90

Pending PR in upstream json-c library
- string must be double-quoted
  https://github.com/json-c/json-c/pull/94

> The world will not be destroyed by those who do evil,
> but by those who watch them without doing anything.
> -- Albert Einstein
