# Sigscan - Python external signature scanner
Mainly was made to dump League of Legends offsets
###
**Attention**: This one can not find strings or xref function calls

This script iterates through processes' (or module's) memory to find certain pattern and obtain different offsets, *thanks to pymem*

* Takes file with patterns `pattern.txt`, takes pattern from each line as well as it's name and trying to find it inside `.text` sector of the module.
* Prints in console each found offset for you to copy.
#
*- Some examples are on the screen below. (Patch 13.1)*
##
![image](https://user-images.githubusercontent.com/66436418/213015913-a61b1039-3a93-4339-92c4-71633d683256.png)
