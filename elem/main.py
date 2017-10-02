#!/usr/bin/python

from elem import ConfigurationHandler
from elem import CliHandler
from elem import Elem
import logging
import log


def main():
    console_logger = log.setup_console_logger('console')
    cli_handler = CliHandler()
    cli_args = cli_handler.read_config()

    config_handler = ConfigurationHandler(cli_args.config)
    config = config_handler.read_config()

    elem = Elem(cli_args, config)
    if cli_args.which is 'refresh':
        elem.refresh()

    elif cli_args.which is 'list':
        elem.show(cli_args.eids, cli_args.cveids)

    elif cli_args.which is 'score':
        elem.score(cli_args.eid, cli_args.cpe, cli_args.kind, cli_args.value)

    elif cli_args.which is 'assess':
        elem.assess()

    elif cli_args.which is 'stage':
        elem.stage(cli_args.eid, 
                   cli_args.cpe, 
                   cli_args.command, 
                   cli_args.selinux, 
                   cli_args.packages, 
                   cli_args.services)

    elif cli_args.which is 'copy':
        elem.copy(cli_args.source,
                  cli_args.eids,
                  cli_args.destination,
                  cli_args.stage,
                  cli_args.cpe)

if __name__ == "__main__":
    main()
