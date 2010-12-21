--TEST--
unset_compile_file()
--FILE--
<?php
set_compile_file_overload(function($old) { return '<?php echo "Hello World";'; });
unset_compile_file_overload();

include(__DIR__.'/dummy.inc');
--EXPECT--
dummy!
