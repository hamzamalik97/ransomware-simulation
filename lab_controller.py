import docker
import io
import tarfile

VICTIM = "locker-victim"
TARGET_DIR = "/locker_data"

client = docker.from_env()


def get_victim():
    return client.containers.get(VICTIM)


def discover_files():
    container = get_victim()

    result = container.exec_run(
        [
            "sh",
            "-c",
            f"find {TARGET_DIR} -type f ! -name '*.locked' -print"
        ]
    )

    if result.exit_code != 0:
        raise RuntimeError(result.output.decode())

    output = result.output.decode().strip()

    if not output:
        return []

    return output.splitlines()


def read_file(filepath):
    container = get_victim()

    result = container.exec_run(
        ["cat", filepath]
    )

    if result.exit_code != 0:
        raise RuntimeError(result.output.decode())

    return result.output


def write_file(filepath, data):
    container = get_victim()

    directory, filename = filepath.rsplit("/", 1)

    archive = create_tar(filename, data)

    container.put_archive(directory, archive)


def create_tar(filename, data):

    stream = io.BytesIO()

    with tarfile.open(fileobj=stream, mode="w") as tar:

        info = tarfile.TarInfo(name=filename)

        info.size = len(data)
        info.mode = 0o600

        tar.addfile(
            info,
            io.BytesIO(data)
        )

    stream.seek(0)

    return stream


def delete_file(filepath):

    container = get_victim()

    result = container.exec_run(
        ["rm", "-f", filepath]
    )

    if result.exit_code != 0:
        raise RuntimeError(result.output.decode())
