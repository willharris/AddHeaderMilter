#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import logging
import logging.handlers
import re
import socket
import sys
import time

import libmilter
import yaml

logger = logging.getLogger('AddHeaderMilter')


def configure_logging(level=None, config_file=None):
    level = getattr(logging, level, logging.INFO)
    logger.setLevel(level)
    syslog_handler = logging.handlers.SysLogHandler(address='/dev/log', facility=logging.handlers.SysLogHandler.LOG_MAIL)
    syslog_handler.setLevel(level)
    formatter = logging.Formatter('%(name)s[%(process)d]: %(levelname)s - %(message)s')
    syslog_handler.setFormatter(formatter)
    logger.addHandler(syslog_handler)


class AddHeaderMilter(libmilter.ForkMixin, libmilter.MilterProtocol):

    def __init__(self, opts={}, protos=0):
        # We must init our parents here
        milter_opts = opts['milter_opts']
        libmilter.MilterProtocol.__init__(self, milter_opts, protos)
        libmilter.ForkMixin.__init__(self)

        self.config = opts['config']
        self.rcpt_data = {}
        self.mail_data = {}
        self.message_id = 'not_set'

    def start(self):
        """Override method in ForkMixin"""
        logger.debug('Starting...')
        super(AddHeaderMilter, self).start()
        logger.debug('Started!')

    def run(self):
        """Override method in ForkMixin"""
        logger.debug('Running...')
        super(AddHeaderMilter, self).run()

    @libmilter.noReply
    def connect(self, hostname, family, ip, port, cmdDict):
        logger.info('Connect from %s:%d (%s) with family: %s', ip, port, hostname, family)
        logger.debug('cmdDict: %s', cmdDict)
        logger.debug('socket: %s', self.transport)
        self._socket = self.transport if self.transport else None
        return libmilter.CONTINUE

    @libmilter.noReply
    def helo(self, heloname):
        logger.debug('HELO: %s', heloname)
        return libmilter.CONTINUE

    @libmilter.noReply
    def mailFrom(self, frAddr, cmdDict):
        logger.debug('MAIL: %s', frAddr)
        logger.debug('cmdDict: %s', cmdDict)
        self.mail_data.update(cmdDict)
        return libmilter.CONTINUE

    @libmilter.noReply
    def rcpt(self, recip, cmdDict):
        logger.debug('RCPT: %s', recip)
        logger.debug('cmdDict: %s', cmdDict)
        self.rcpt_data.update(cmdDict)
        return libmilter.CONTINUE

    @libmilter.noReply
    def header(self, key, val, cmdDict):
        logger.debug('HEADER: %s: %s', key, val)
        logger.debug('cmdDict: %s', cmdDict)
        return libmilter.CONTINUE

    @libmilter.noReply
    def eoh(self, cmdDict):
        logger.debug('EOH')
        logger.debug('cmdDict: %s', cmdDict)
        return libmilter.CONTINUE

    def data(self, cmdDict):
        logger.debug('DATA')
        logger.debug('cmdDict: %s', cmdDict)
        return libmilter.CONTINUE

    @libmilter.noReply
    def body(self, chunk, cmdDict):
        logger.debug('Body chunk: %d', len(chunk))
        logger.debug('cmdDict: %s', cmdDict)
        return libmilter.CONTINUE

    def eob(self, cmdDict):
        logger.debug('EOB')
        logger.debug('cmdDict: %s', cmdDict)
        self.message_id = cmdDict.get('i', 'unknown')
        if self.rcpt_data['rcpt_mailer'] == 'smtp':
            #self.setReply('554', '5.7.1', 'Rejected because I said so')
            for action in self.config:
                for action_type, config in action.iteritems():
                    if action_type == 'sender':
                        logger.debug('%s: Checking sender pattern /%s/ against address %s',
                                     self.message_id, config['pattern'], self.mail_data['mail_addr'])
                        if re.search(config['pattern'], self.mail_data['mail_addr']):
                            self.addHeader(config['header_key'], config['header_value'])
                            logger.info('%s: Added header - %s: %s', self.message_id, config['header_key'], config['header_value'])
                        else:
                            logger.debug('%s: No match', self.message_id)
        else:
            logger.info('%s: Skipping non-smtp delivery: %s', self.message_id, self.rcpt_data['rcpt_mailer'])

        return libmilter.CONTINUE

    def close(self):
        logger.debug('Close called. QID: %s', self.message_id)
        logger.debug('Transport is %s', self.transport)
        logger.debug('Socket is %s', self._socket)
        if self._socket:
            try:
                self._socket.shutdown(socket.SHUT_RDWR)
                self._socket.close()
            except socket.error as ex:
                logger.debug('Exception while doing socket shutdown/close: %s', ex)
                pass
            logger.debug('Socket shutdown and closed')


def main(config_file):
    import signal, traceback

    with open(config_file, 'r') as input:
        config = yaml.load(input)

    opts = {
        #'milter_opts': libmilter.SMFIF_CHGFROM | libmilter.SMFIF_ADDRCPT | libmilter.SMFIF_QUARANTINE
        'milter_opts': libmilter.SMFIF_ADDHDRS,
        'config': config,
    }
    logger.debug("Configuration: %s", opts)

    # We initialize the factory we want to use (you can choose from an
    # AsyncFactory, ForkFactory or ThreadFactory.  You must use the
    # appropriate mixin classes for your milter for Thread and Fork)
    f = libmilter.ForkFactory('inet:127.0.0.1:5000', AddHeaderMilter, opts)
    #f = libmilter.ForkFactory('/var/run/add_header_milter.sock', AddHeaderMilter, opts)

    def sig_handler(num, frame):
        f.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)

    try:
        # run it
        f.run()
    except Exception as ex:
        f.close()
        logger.exception('Exception running AddHeaderMilter')
        sys.exit(3)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Milter for adding headers to an email.')
    parser.add_argument('-l', '--loglevel', choices=('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'),
                        default='INFO', help='Logging level. Default: %(default)s')
    parser.add_argument('config', help='YAML configuration file')

    args = parser.parse_args()

    configure_logging(level=args.loglevel)
    logger.info('AddHeaderMilter starting')

    main(args.config)

