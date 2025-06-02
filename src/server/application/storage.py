from pathlib import Path


def get_root(base: str, identifier: str, version: str) -> Path:
    _path = Path('~', base, identifier, version).expanduser()
    _path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return _path

def info_root(identifier: str, version: str) -> Path:
    return get_root("Info", identifier, version)

def app_root(base: str, identifier: str) -> Path:
    return get_root("Apps", identifier, version)

def get_container(root: Path, identifier: str) -> Path:
    _path = Path(root, identifier).expanduser()
    _path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return _path

def get_resource(container: Path, identifier: str, suffix: str) -> Path:
    return Path(container, identifier).with_suffix(suffix)

def dotenv(root: Path) -> Path:
    dotenv_identifier = Path(root, '.env')
    with open(dotenv_identifier, 'w') as target:
        # Default key - value pairs
        key = "SECRET_KEY"
        value = uuid.uuid4().hex
        target.write(f'{key:s}="{value:s}"\n')

        key = "JWT_SECRET_KEY"
        value = uuid.uuid4().hex
        target.write(f'{key:s}="{value:s}"\n')

        key = "LOGGING_LEVEL"
        value = "DEBUG"
        target.write(f'{key:s}="{value:s}"\n')

