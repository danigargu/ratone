# ratone
A console for assemble/disassemble code using capstone/keystone

![ratone](https://cloud.githubusercontent.com/assets/1675387/22099706/b8528a18-de2c-11e6-8623-79912abba00c.png)

## Dependencies

* Capstone python binding: http://www.capstone-engine.org/documentation.html
* Keystone python binding: http://www.keystone-engine.org/docs/


## Interactive commands

### > asm
```
(ratone)> asm
Assemble instructions

usage: asm [-i INPUT_FILE] [-o OUTPUT_FILE] [-c CODE] [-x]

optional arguments:
  -h, --help      show this help message and exit
  -i INPUT_FILE   Input file
  -o OUTPUT_FILE  Output file
  -c CODE         Instruction/s
  -x              Interactive
```

### > disas
```
(ratone)> disas
Disassemble instructions

usage: disas [-h] [-b BASE_ADDR] [-i INPUT_FILE] [-o OUTPUT_FILE]
             [-c HEXCODE]

optional arguments:
  -h, --help      show this help message and exit
  -b BASE_ADDR    Base address
  -i INPUT_FILE   Input file
  -o OUTPUT_FILE  Output file
  -c HEXCODE      Hex code

(ratone)>
```

### > set
```
usage: set <opt> <value>
```

### Available options:

   * **output**: json, string, hex, c, b64
   * **arch**: ppc, x16, x86, x64, ppc64, mips64, sparc, arm_t, arm64, mips32, hexagon, systemz, arm
   * **syntax**: intel, nasm, masm, att
