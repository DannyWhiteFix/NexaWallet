#!/usr/bin/env python3

import copy
import os

def test_api_wrapper_arg_res_types(methods):
    cur_dir = os.path.dirname(__file__)
    api_wrapper_rel_path = "./libnexa_api_wrapper.py"
    api_wrapper_abs_path = os.path.join(cur_dir, api_wrapper_rel_path)
    # probably a better way to do this but this is simple and quick enough
    list_arg_type = []
    list_res_type = []
    lines = []
    with open(api_wrapper_abs_path, 'r') as file:
        for line in file:
            line = line.strip()
            lines.append(line)
    for method in methods:
        for line in lines:
            if line.startswith("libnexa." + str(method) +".argtypes"):
                list_arg_type.append(method)
            if line.startswith("libnexa." + str(method) +".restype"):
                list_res_type.append(method)

    return list_arg_type == methods and list_res_type == methods



def get_libnexa_api_methods():
    cur_dir = os.path.dirname(__file__)
    libnexa_rel_path = '../../../../src/libnexa/libnexa.h'
    libnexa_abs_path = os.path.join(cur_dir, libnexa_rel_path)
    methods = []
    with open(libnexa_abs_path, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith("SLAPI"):
                line = line.split("(")[0]
                function_name = line.split(" ")[-1]
                methods.append(function_name)
    return methods
