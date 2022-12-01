from generate_access_graph import generate_iam_test
import time
from z3 import Solver, sat, StringVal

params1 = {
    'num_role_groups': 2,
    'role_branching_factor': 3,
    'num_users': 10,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params2 = {
    'num_role_groups': 5,
    'role_branching_factor': 3,
    'num_users': 20,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params3 = {
    'num_role_groups': 5,
    'role_branching_factor': 10,
    'num_users': 20,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params4 = {
    'num_role_groups': 5,
    'role_branching_factor': 20,
    'num_users': 20,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params5 = {
    'num_role_groups': 10,
    'role_branching_factor': 3,
    'num_users': 40,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params5 = {
    'num_role_groups': 20,
    'role_branching_factor': 3,
    'num_users': 80,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params6 = {
    'num_role_groups': 40,
    'role_branching_factor': 3,
    'num_users': 160,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params7 = {
    'num_role_groups': 80,
    'role_branching_factor': 3,
    'num_users': 240,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params8 = {
    'num_role_groups': 160,
    'role_branching_factor': 3,
    'num_users': 480,
    'max_n_objects': 4,
    'max_n_actions': 3
}

params8 = {
    'num_role_groups': 320,
    'role_branching_factor': 3,
    'num_users': 960,
    'max_n_objects': 4,
    'max_n_actions': 3
}

# params3 = {
#     'num_role_groups': 500,
#     'role_branching_factor': 40,
#     'num_users': 10000,
#     'max_n_objects': 4,
#     'max_n_actions': 3
# }

def time_function(f, *args):
    start = time.perf_counter()
    result = f(*args)
    end = time.perf_counter()
    return (result, end-start)

def perform_test(params, id):
    test_instance = generate_iam_test(params)
    (user, action, res, path_len) = test_instance.generate_allow_test()
    print(user)
    print(action)
    print(res)
    s = Solver()
    s.add(test_instance.env['Allow'](StringVal(user), StringVal(action), StringVal(res)))
    (result, elapsed) = time_function(lambda: s.check())
    print(f"test-{id}: params={params}; path_length={path_len}; num_roles={len(test_instance.role_graph)} q=Allow({user}, {action}, {res}); elapsed={elapsed}")
    if result == sat:
        print('sat')
    else:
        print('unsat')

perform_test(params1, id=1)
perform_test(params2, id=2)
perform_test(params3, id=3)
perform_test(params4, id=4)
perform_test(params5, id=5)
perform_test(params6, id=6)
perform_test(params7, id=7)
perform_test(params8, id=8)