import pathlib
from pkgutil import iter_modules
from typing import List

from invoke import Context, task


def _get_python_modules() -> List[str]:
    modules_in_dir = iter_modules([pathlib.Path(__file__).parent.as_posix()])
    return [m.name if m.ispkg else m.name + ".py" for m in modules_in_dir]


@task
def install(ctx):
    # type: (Context) -> None
    ctx.run("python setup.py install")


@task
def test(ctx):
    # type: (Context) -> None
    ctx.run("mypy strongarm strongarm-cli.py")
    ctx.run("pytest -n 4")


@task
def autoformat_lint(ctx):
    # type: (Context) -> None
    """Check formatting of the code."""
    # Gather all the modules / files in the tree
    files_to_process = " ".join(_get_python_modules())

    autoflake_version = ctx.run("autoflake --version", hide=True).stdout.strip().split()[1]
    isort_version = ctx.run("isort --version | grep VERSION", hide=True).stdout.strip().split()[1]
    black_version = ctx.run("black --version", hide=True).stdout.strip().split()[2]
    flake8_version = ctx.run("flake8 --version", hide=True).stdout.strip().split()[0]

    # Check that validations pass without modifying the code
    print(f"Checking imports optimization (autoflake v{autoflake_version})")
    ctx.run(f"autoflake --recursive {files_to_process}")  # Default behaviour is to print diff

    print(f"Checking imports sorting (isort v{isort_version})")
    ctx.run(f"isort --check --diff {files_to_process}")

    print(f"Checking black format (black v{black_version})")
    ctx.run(f"black --check --diff {files_to_process}")

    print(f"Checking format (flake8 v{flake8_version})")
    ctx.run(f"flake8 {files_to_process}")


@task
def autoformat(ctx):
    # type: (Context) -> None
    """Run auto-formatting tools."""
    # Gather all the modules / files in the tree
    files_to_process = " ".join(_get_python_modules())

    # Run auto-formatting tools
    print("Optimizing imports")
    ctx.run(f"autoflake --in-place --recursive {files_to_process}")

    print("Sorting imports")
    ctx.run(f"isort {files_to_process}")

    print("Blackifying code")
    ctx.run(f"black {files_to_process}")
