#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import imaplib
import mailbox
from mailbox import _mboxMMDFMessage
import getpass
import argparse
import time
import email
import base64
import time
import pprint
import re
import pipes
import sys
import hashlib
from imapclient.imap_utf7 import encode as encode_utf7, decode as decode_utf7
from imapclient.response_parser import parse_response, parse_message_list, parse_fetch_response

_RE_COMBINE_WHITESPACE = re.compile(r"\s+")

def parse_imap_value(s):
    print("String: " + s)
    pattern = re.compile("^[ ](?P<name>.+)[ ](?P<value>.+)\)$", re.VERBOSE)
    match = pattern.match(s)
    name = match.group("name")
    value = int(match.group("value"))
    return (name, value)

pp = pprint.PrettyPrinter(indent=4)

argparser = argparse.ArgumentParser(description="imaptool.py - Email IMAP tool for syncing, copying, migrating and archiving email mailboxes between imap servers and local storage.")

argparser.add_argument('--dry', dest='dry', help="Dry run", default=False, action='store_true')
argparser.add_argument('--debug', dest='debug', help="Debug output", default=False, action='store_true')
argparser.add_argument('--showpasswords', dest='showpassowords', help="Dry run", default=False, action='store_true')

argparser.add_argument('-a', '--eml1', dest='eml1', nargs="+", help='Append emls')
argparser.add_argument('-m', '--mbox1', dest='mbox1', help="File location of mbox1", default=False)
argparser.add_argument('-s', '--host1', dest='host1', help="IMAP host for host1", default=False)
argparser.add_argument('-p', '--prot1', dest='port1', help="IMAP port for host1", default=1143)
argparser.add_argument('-u', '--user1', dest='username1', help="IMAP username for host1", default='username')
argparser.add_argument('-P', '--password1', dest='password1', help="IMAP password for host1", default=False)
argparser.add_argument('--passfile1', dest='passfile1', help="IMAP password file for host1", default=False)
argparser.add_argument('--passrequest1', dest='passrequest1', help="IMAP password request for host1", default=False)
argparser.add_argument('--ssl1', dest='ssl1', help="Use SSL for host1", default=False, action='store_true')
argparser.add_argument('--gmail1', dest='gmail1', help="Gmail for host1", default=False, action='store_true')

argparser.add_argument('--eml2', dest='eml2', help="Export eml", default=False)
argparser.add_argument('--mbox2', dest='mbox2', help="Export mbox", default=False)
argparser.add_argument('--host2', dest='host2', help="IMAP host for host2", default=False)
argparser.add_argument('--prot2', dest='port2', help="IMAP port for host2", default=1143)
argparser.add_argument('--user2', dest='username2', help="IMAP username for host2", required=False)
argparser.add_argument('--password2', dest='password2', help="IMAP password for host2", default=False)
argparser.add_argument('--passfile2', dest='passfile2', help="IMAP password file for host2", default=False)
argparser.add_argument('--ssl2', dest='ssl2', help="Use SSL for host2", default=False, action='store_true')
argparser.add_argument('--gmail2', dest='gmail2', help="Gmail for host2", default=False, action='store_true')

argparser.add_argument('-f', dest='folders', help="IMAP folder", nargs="+")

#argparser.add_argument('-l', dest='local_folder', help="Local folder", default='.')
argparser.add_argument('-e', '--extended', dest='extended', help="Extended list", default=False, action='store_true')
argparser.add_argument('--extended2', dest='extended2', help="Extended list", default=False, action='store_true')
argparser.add_argument('-q', '--query', dest='query', nargs="+", help='Query messages')
argparser.add_argument('--from-ts', dest='fromts', help='Query messages from', type=int, default=False)
argparser.add_argument('--to-ts', dest='tots', help='Query messages to', type=int, default=False)
argparser.add_argument('--delete', dest='delete', help='Delete', default=False, action='store_true')

args = argparser.parse_args()

class Storage():
    def __init__(self):
        pass
    def selectMessageIds():
        pass
    def selectMessageById(id):
        pass
    def insertMessage(message):
        pass

class EMLSet(Storage):
    def __init__(sefl):
        pass

class IMAPStorage(Storage):
    def __init__(sefl, imap, folder):
        pass

class MBOXStorage(Storage):
    def __init__(sefl):
        pass

if args.passrequest1:
    args.password1 = getpass.getpass()

if args.debug:
    imaplib.Debug = 4
    print('Capabilities:', mail.capabilities)

if args.gmail1:
    args.ssl1 = true
    args.host1 = 'imap.gmail.com'
    args.port1 = 993

if args.gmail2:
    args.ssl2 = true
    args.host2 = 'imap.gmail.com'
    args.port2 = 993

if args.host1:
    if not args.ssl1:
        mail = imaplib.IMAP4(args.host1, args.port1)
        mail.starttls()
    else:
        mail = imaplib.IMAP4_SSL(args.host1, args.port1)

    mail.login(args.username1, args.password1)


print(" ".join(map(pipes.quote, sys.argv)), file=sys.stderr)

#UID, FLAGS

def smallhash(s):
    return int(hashlib.sha256(s).hexdigest(), 16) % 10**8 

def imap_delete(imap):
    imap.store("1:*", '+FLAGS', '\\Deleted')
    imap.expunge()

def mbox_add(mbox, message):
    try:
        timestamp = email.utils.parsedate_to_datetime(message.get('Date')).timestamp()
    except:
        timestamp = 0
    if args.fromts and timestamp < args.fromts:
        return
    if args.tots and timestamp > args.tots:
        return 
    mbox.add(message);


if (args.mbox1):
    mbox1 = mailbox.mbox(args.mbox1)
    if (args.mbox2):
        mbox2 = mailbox.mbox(args.mbox2)
        for msg_str in mbox1:
            try:
                timestamp = email.utils.parsedate_to_datetime(msg_str.get('Date')).timestamp()
            except:
                timestamp = 0
            if args.fromts and timestamp < args.fromts:
                continue
            if args.tots and timestamp > args.tots:
                continue
            mbox2.add(msg_str);
        mbox2.close()
    else:
        for msg_str in mbox1:
            try:
                timestamp = email.utils.parsedate_to_datetime(msg_str.get('Date')).timestamp()
            except:
                timestamp = 0
            try:
                message_id = email.header.make_header(email.header.decode_header(msg_str.get('Message-ID')))
            except:
                message_id = msg_str.get('Message-ID')
            try:
                subject = msg_str.get('Subject')
                if subject:
                    #subject = _RE_COMBINE_WHITESPACE.sub(" ", subject).strip()
                    subject = subject.replace('\n', ' ').replace('\r', ' ')
                subject = email.header.make_header(decode_utf7(email.header.decode_header(subject)))
            except:
                pass

            #print('%s\t%d\t%s\t%s' % (timestamp, size, message_id, subject))
            print('%s\t%s\t%s' % (timestamp, message_id, subject), end="\t")
            
            if args.extended2:
                for part in msg_str.walk():
                    if part.get_content_maintype() == 'multipart':
                        continue
                    fileName = part.get_filename()
                    payload = part.get_payload(decode=True)
                    if payload:
                        size = len(payload)
                        hashcode = smallhash(payload)
                    else:
                        size = 0
                        hashcode = 0
                    disposition = part.get('Contnet-Disposition')
                    #print("%d,%s,%s,%d" % (size, disposition, fileName, hashcode), end=";")
                    if fileName:
                        print("%d,%s,%s" % (size, disposition, fileName), end=";")
                    #if part.get('Content-Disposition') is None:
                    #    continue
                    #if part.get('Content-Disposition') == "inline":
                    #    continue
            print()
    mbox1.close();

if args.folders:
    for folder in args.folders:
        mail.select("\"" + decode_utf7(folder) + "\"")
        if args.delete:
            mail.store("1:*", '+FLAGS', '\\Deleted')
            mail.expunge()
        else:
            typ, data = mail.search(None, 'ALL')
            if args.eml2: # dump emls to folder
                for num in data[0].split():
                    typ, data = mail.fetch(num, '(UID RFC822)')
                    data = parse_fetch_response(data)
                    #f = open('%s/%010d.eml' %(args.local_folder, int(num)), 'w')
                    uid = next(iter(data))
                    f = open('%s/%s.eml' %(args.eml, uid), 'wb')
                    f.write(data[uid][b'RFC822'])
                    f.close()
            elif args.mbox2: # dump emls to mbox
                mbox = mailbox.mbox(args.mbox2)
                for num in data[0].split():
                    typ, data = mail.fetch(num, '(UID RFC822)')
                    data = parse_fetch_response(data)
                    uid = next(iter(data))
                    if b'RFC822' in data[uid]:
                        message = _mboxMMDFMessage(data[uid][b'RFC822'])
                        mbox.add(message)
                    else:
                        print("No RFC822 found for: %d" % uid, file=sys.stderr)
                    #message.set_from("%s@%s:%s/%d" % (args.username1, args.host1, folder, uid), time.gmtime())
                mbox.close()
            elif args.eml1: # append emls
                for file in args.eml1:
                    with open(file, "rb") as f:
                        data = f.read()#.decode('utf-8')
                        mail.append(args.remote_folder, '', imaplib.Time2Internaldate(time.time()), data)
            elif (args.query):
                queryset = frozenset(args.query)
                typ, data = mail.search(None, 'ALL')
                for num in data[0].split():
                    typ, data = mail.fetch(num, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')
                    for response_part in data:
                      if isinstance(response_part, tuple):
                        msg_str = email.message_from_string(response_part[1].decode('utf-8'))
                        message_id = msg_str.get('Message-ID')
                        if message_id in queryset:
                            print("match")
                            typ, data = mail.fetch(num, '(RFC822)')
                            for response_part in data:
                                if isinstance(response_part, tuple):
                                    msg_str = email.message_from_string(response_part[1].decode('utf-8'))
                                    for part in msg_str.walk():
                                        if part.get_content_maintype() == 'multipart':
                                            continue
                                        fileName = part.get_filename()
                                        print("%d %s" % (len(part.get_payload(decode=True)), fileName))
                                        if part.get('Content-Disposition') is None:
                                            continue
                                        if part.get('Content-Disposition') == "inline":
                                            continue
            else:
                for num in data[0].split():
                    if (args.delete):
                        pass
                        #mail.store(num, '+FLAGS', '\\Deleted')
                    elif (args.extended):
                        typ, data = mail.fetch(num, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT DATE)] RFC822.SIZE)')
                        #typ, data = mail.fetch(num, '(RFC822)')
                        #(name, size) = parse_imap_value(data[1].decode('utf-8'))
                        for response_part in data:
                          if isinstance(response_part, tuple):
                            msg_str = email.message_from_string(response_part[1].decode('utf-8'))
                            try:
                                timestamp = email.utils.parsedate_to_datetime(msg_str.get('Date')).timestamp()
                            except:    
                                timestamp = 0
                            try:
                                message_id = email.header.make_header(email.header.decode_header(msg_str.get('Message-ID')))
                            except:
                                message_id = msg_str.get('Message-ID')
                            try:
                                subject = email.header.make_header(decode_utf7(email.header.decode_header(msg_str.get('Subject'))))
                            except:
                                subject = msg_str.get('Subject')

                            #print('%s\t%d\t%s\t%s' % (timestamp, size, message_id, subject))
                            print('%s\t%s\t%s' % (timestamp, message_id, subject))
                    else:
                        typ, data = mail.fetch(num, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')
                        for response_part in data:
                          if isinstance(response_part, tuple):
                            msg_str = email.message_from_string(response_part[1].decode('utf-8'))
                            try:
                                message_id = email.header.make_header(email.header.decode_header(msg_str.get('Message-ID')))
                            except:
                                message_id = msg_str.get('Message-ID')
                            print(message_id);
                if (args.delete):
                    pass
                    #mail.expunge()

if args.host1 and not args.folders:
    for i in mail.list()[1]:
        print(i.decode('utf-8'))
        print(decode_utf7(i))

        #print(imaputf7decode(i.decode('utf-8')))
        #print(imaputf7encode(imaputf7decode(i.decode('utf-8'))))

if args.host1:
    mail.close()
    mail.logout()
