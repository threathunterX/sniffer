# -*- coding: utf-8 -*-
import click

import utils
from .. import settings


@click.group(invoke_without_command=True)
@click.version_option(settings.Sniffer_Version)
@click.pass_context
def cli(ctx, **kwargs):
    ctx.obj = utils.Storage()
    ctx.obj.update(kwargs)


@cli.command()
def create_conf():
    """
    根据settings配置成配置文件们
    """

    nebula_config = dict((k, v) for k, v in settings.__dict__.iteritems() if k[0].isupper())

    sniffer_conf = utils.render(settings.Sniffer_Conf_Tem, nebula_config)
    with open(settings.Sniffer_Conf_FN, 'w') as f:
        f.write(sniffer_conf)

    click.echo(u'生成配置成功完成')
    click.echo('')


if __name__ == '__main__':
    pass
