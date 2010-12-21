--TEST--
set_compile_file()
--FILE--
<?php
set_compile_file_overload(function($old) { return '<?php echo "Hello World ('.$old.')\n";'; });
include(__DIR__.'/dummy.inc');
include('/this/better/not/exists/else/it/is/weird.php');

set_compile_file_overload(function($old) {});
include(__DIR__.'/dummy.inc');

set_compile_file_overload(function($old) { return '<?php this is a compile error'; });
include(__DIR__.'/dummy.inc');
--EXPECTF--
Hello World (%sdummy.inc)
Hello World (/this/better/not/exists/else/it/is/weird.php)
dummy!

Parse error: syntax error, unexpected T_STRING in %sdummy.inc on line 1
