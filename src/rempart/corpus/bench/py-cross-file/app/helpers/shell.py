import os


def run_tool(arg):
    # rempart-alt: CODE-CMD-INJECTION
    return os.system("convert " + arg)


def tool_name():
    return "convert"
