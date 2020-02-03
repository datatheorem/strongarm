import pathlib
from pkgutil import iter_modules
from sys import platform
from typing import List

from invoke import Context, task


def _get_python_modules() -> List[str]:
    modules_in_dir = iter_modules([pathlib.Path(__file__).parent.as_posix()])
    return [m.name if m.ispkg else m.name + ".py" for m in modules_in_dir]


@task
def deps(ctx):
    # type: (Context) -> None
    if platform == "darwin":
        # On macOS - assuming we are going to be running the CLI
        ctx.run("brew install capstone")
    if platform == "linux":
        # On macOS - assuming we are going to be running the CI
        ctx.run("apt-get update")
        ctx.run(
            "apt-get install libcapstone3 libcapstone-dev -y --allow-unauthenticated"
        )


@task
def install(ctx):
    # type: (Context) -> None
    ctx.run("python setup.py install")
    ctx.run("python setup.py build_ext --inplace")


@task
def test(ctx):
    # type: (Context) -> None
    ctx.run("pipenv run mypy strongarm strongarm-cli.py --ignore-missing-imports")
    ctx.run("pipenv run pytest")


@task
def check_standards(ctx):
    # type: (Context) -> None
    """Check formatting of the code
    """
    _run_linters(ctx, check=True)


@task
def standards(ctx):
    # type: (Context) -> None
    """Run auto-formatting tools
    """
    _run_linters(ctx, check=False)


def _run_linters(ctx: Context, check: bool) -> None:
    # Get the files to process
    files_to_process = " ".join(_get_python_modules())

    # Find virtual environment for isort
    venv = ctx.run("pipenv --venv", hide=True).stdout.strip()
    autoflake_version = (
        ctx.run("autoflake --version", hide=True).stdout.strip().split()[1]
    )
    isort_version = (
        ctx.run("isort --version | grep VERSION", hide=True).stdout.strip().split()[1]
    )
    black_version = ctx.run("black --version", hide=True).stdout.strip().split()[2]
    mypy_version = ctx.run("mypy --version", hide=True).stdout.strip().split()[1]
    flake8_version = ctx.run("flake8 --version", hide=True).stdout.strip().split()[0]

    if check:
        # Check that validations pass without modifying the code
        print(f"Checking imports optimization (autoflake v{autoflake_version})")
        ctx.run(
            f"autoflake --recursive {files_to_process}"
        )  # Default behaviour is to print diff

        print(f"Checking imports sorting (isort v{isort_version})")
        ctx.run(
            f"isort --check --diff --virtual-env {venv} --recursive {files_to_process}"
        )

        print(f"Checking code Blackifying (black v{black_version})")
        ctx.run(f"black --check --diff {files_to_process}")

        print(f"Checking types (mypy v{mypy_version})")
        ctx.run(f"mypy {files_to_process}")

        print(f"Checking format (flake8 v{flake8_version})")
        ctx.run(f"flake8 {files_to_process}")
    else:
        # Run auto-formatting tools
        print("Optimizing imports")
        ctx.run(f"autoflake --in-place --recursive {files_to_process}")

        print("Sorting imports")
        ctx.run(f"isort --virtual-env {venv} --apply --recursive {files_to_process}")

        print("Blackifying code")
        ctx.run(f"black {files_to_process}")
