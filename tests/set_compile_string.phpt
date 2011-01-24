--TEST--
set_compile_file()
--FILE--
<?php
set_compile_string_overload(function($code, $filename) { var_dump($code); var_dump($filename); return 'echo "Hello world!\n";'; });
eval("some random text, just to amuse you!");
--EXPECTF--
string(36) "some random text, just to amuse you!"
string(83) "%s : eval()'d code"
Hello world!
