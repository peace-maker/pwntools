env_server: str
env_port: str
env_file: str
env_exploit_name: str
env_target_host: str
env_team_name: str

def submit_flag(
    flag: str,
    exploit: str = ...,
    target: str = ...,
    server: str = ...,
    port: int = ...,
    team: str = ...,
) -> bytes | None: ...
