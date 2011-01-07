--TEST--
set_compile_file() with a stream
--FILE--
<?php
set_compile_file_overload(function($old) {
    $fp = fopen("data:text/plain,FOO\n", 'r');
    return $fp;
});
echo "Readable Stream:\n";
include(__DIR__.'/dummy.inc');

$filename = __FILE__.'.tmp';
set_compile_file_overload(function($old) use ($filename) {
    return fopen($filename, 'w');
});
echo "Not-readable stream:\n";
include(__DIR__.'/dummy.inc');
unlink($filename);
echo "done";
--EXPECTF--
Readable Stream:
FOO
Not-readable stream:
done
