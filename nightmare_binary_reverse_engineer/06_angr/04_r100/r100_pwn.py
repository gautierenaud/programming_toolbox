import angr

target = angr.Project('r100')

# success: 0x004007a1
desired_addr = 0x004007a1

# failure: 0x00400790
wrong_addr = 0x00400790

entry_state = target.factory.entry_state()
simulation = target.factory.simulation_manager(entry_state)

simulation.explore(find=desired_addr, avoid=wrong_addr)

solution = simulation.found[0].posix.dumps(0)

print(solution)