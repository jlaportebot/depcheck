"""Shell completion scripts for depcheck.

Uses Click's built-in completion machinery so the scripts always match the
commands that are actually registered.
"""

from __future__ import annotations

import sys

import click

#: Shells this command can emit completion scripts for.
SUPPORTED_SHELLS = ("bash", "zsh", "fish")


@click.command(name="completions")
@click.argument(
    "shell",
    type=click.Choice(list(SUPPORTED_SHELLS), case_sensitive=False),
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output the completion script wrapped in a JSON object.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors.",
)
def command(shell: str, output_json: bool, quiet: bool) -> None:
    """Print a shell completion script for depcheck.

    SHELL is one of: bash, zsh, fish.

    \b
    bash:  depcheck completions bash > /etc/bash_completion.d/depcheck
    zsh:   depcheck completions zsh > "${fpath[1]}/_depcheck"
    fish:  depcheck completions fish > ~/.config/fish/completions/depcheck.fish
    """
    from depcheck.cli import main

    shell_name = shell.lower()
    script = _render_completion(main, shell_name)

    if output_json:
        from depcheck import jsonout

        jsonout.write_text(jsonout.to_json({"shell": shell_name, "script": script}))
    elif not quiet:
        click.echo(script, nl=False)

    sys.exit(0)


def _render_completion(main: click.Group, shell: str) -> str:
    """Render a completion script for the given shell.

    Args:
        main: The CLI group the completions are generated for.
        shell: Shell name ("bash", "zsh" or "fish").

    Returns:
        The completion script as a string.
    """
    from click.shell_completion import get_completion_class

    completion_cls = get_completion_class(shell)
    if completion_cls is None:
        raise click.ClickException(f"Unsupported shell: {shell}")

    completion = completion_cls(main, {}, "depcheck", "_DEPCHECK_COMPLETE")
    return completion.source()
