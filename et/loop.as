;python core/assembler.py core/et/loop.as loop.b
PUSH 10000000
loop:
PUSH 1
SUB
DUP
NOT
JZ loop
