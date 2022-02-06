#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import smtplib
import argparse

argparser = argparse.ArgumentParser(description="")
argparser.add_argument('--host', '-s', dest='host', help="SMTP host", default='127.0.0.1')
argparser.add_argument('--port', '-p', dest='port', help="SMTP port", default=1025)
argparser.add_argument('--user', '-u', dest='username', help="IMAP username", required=True)
argparser.add_argument('--password', '-P', dest='password', help="IMAP password", required=True)
argparser.add_argument('--from', '-f', dest='fromAddr', help="From", default=False)
argparser.add_argument('--to', '-t', dest='toAddr', help="To", default=False)
argparser.add_argument('file', help="File with message")
argparser.add_argument('--debug', dest='debug', help="Print message", default=False, action='store_true')
args = argparser.parse_args()

with open(args.file, "rb") as f:
    msg = f.read().decode('utf-8')

    if args.toAddr:
        msg = ("To: {}\r\n{}".format(args.toAddr, msg))
    if args.fromAddr:
        msg = ("From: {}\r\n{}".format(args.fromAddr, msg))
   
    if args.debug:
        print(msg)

    server = smtplib.SMTP(args.host, args.port)
    server.starttls()
    server.login(args.username, args.password)

    if args.debug:
    	server.set_debuglevel(1)

    server.sendmail(args.fromAddr, args.toAddr, msg.encode('utf-8'))
    server.quit()
