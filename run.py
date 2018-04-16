from sys import argv

with open(argv[1]) as f:
    code = f.read()

from parser import parse
state = parse(code)
#print(list(code))
from vm import run, annotated, d, s, STATUS, MEMORY, VOLRETURN
#print(len(state)*32, "bytes")
# Run state
from vmutils import minify
minify(state)

while True:
    state = d(state)

    inp = input("Ready>")
    if len(inp):
        state[MEMORY].append([int(inp)])
    else:
        state = s(state)
        break
    print(state)
    state = s(state)

    state = run(state, 1000, 1000, debug=False)

    state = d(state)
    if state[STATUS] == VOLRETURN:
        #if state[MEMORY][0][0] == 1:
        if len(state[MEMORY]) > 1:
            print("Returned: ", state[MEMORY][-1])
            state[MEMORY] = state[MEMORY][:-1]

        state = s(state)
    else:
        print(state[MEMORY])
        print("NORETURN")
        exit(1)
#print(d(state))

print(annotated(d(state)))

from PIL import Image

SIZE = 32
SCALE = 8
img = Image.new("RGB", (SIZE,SIZE))
for i,v in enumerate(state):
    img.putpixel((int(i%SIZE), int(i/SIZE)), int(v%256)<<20)
img = img.resize((SIZE*SCALE, SIZE*SCALE))
#img.show()
"""
import sys, select
import os
from time import sleep
clear = lambda : os.system('tput reset')
while False:
    state = run(state, 0xffffffff, 100)
    state = d(state)
    clear()
    i, o, e = select.select( [sys.stdin], [], [], 0)
    print(state)
    if i:
        inp = [int(sys.stdin.readline().strip())]
        state[MEMORY].append(inp)#.append(int(inp))#

    state = s(state)
    sleep(0.1)
"""
