from invoke import task, Context
from sys import platform


@task
def deps(ctx):
    # type: (Context) -> None
    if platform == 'darwin':
        # On macOS - assuming we are going to be running the CLI
        ctx.run('brew install capstone')
    if platform == 'linux':
        # On macOS - assuming we are going to be running the CI
        ctx.run('apt-get update')
        ctx.run('apt-get install libcapstone3 libcapstone-dev -y --allow-unauthenticated')


@task
def install(ctx):
    # type: (Context) -> None
    ctx.run('python setup.py install')
    ctx.run('python setup.py build_ext --inplace')


@task
def test(ctx):
    # type: (Context) -> None
    ctx.run('pipenv run mypy strongarm strongarm-cli.py --ignore-missing-imports')
    ctx.run('pipenv run pytest')
