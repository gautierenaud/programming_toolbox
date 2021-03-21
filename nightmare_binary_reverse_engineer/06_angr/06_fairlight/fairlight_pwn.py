import angr
import claripy


target = angr.Project('fairlight', auto_load_libs=False)

# Establish our input as an array of 0xe bytes
inp = claripy.BVS("inp", 0xe*8)

entry_state = target.factory.entry_state(args=["./fairlight", inp])
simulation = target.factory.simulation_manager(entry_state)

# address of denied_access method
wrong_addr = 0x0040074d

desired_addr = 0x00401a5a

simulation.explore(find=desired_addr, avoid=wrong_addr)

solution = simulation.found[0]

print(solution.solver.eval(inp, cast_to=bytes))