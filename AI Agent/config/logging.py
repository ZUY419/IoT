import util

class log_info:
    """
    level = 0(info), 1(warn), 2(error)
    """
    level = 0

    def info(log):
        if log_info.level >= 0:
            print(f"[INFO    ] {log}")

    def tool(tool):
        if log_info.level <= 0:
            print("")
            print(f"[TOOL    ] {tool}")

    def AI_prompt(prompt):
        if log_info.level <= 0:
            print(f"[PROMPT  ] {prompt}")

    def AI_response(response):
        if log_info.level <= 0:
            print(f"[RESPONSE] {response}")

    def warn(log):
        if log_info.level <= 1:
            print(f"[WARN    ] {log}")

    def error(log):
        if log_info.level <= 2:
            print(f"[ERROR   ] {log}")

    def share_memory(data):
        util.updated_share_momery(data)
        if log_info.level <= 2:
            print(f"[SHAREMEM] {data}")