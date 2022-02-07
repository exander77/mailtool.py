#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import imaplib as imaplibbase
#import imaplibext as imaplib
import imaplibmailtool as imaplib
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
import datetime
import configparser
from pathlib import Path
from imapclient.imap_utf7 import encode as encode_utf7, decode as decode_utf7
from imapclient.response_parser import parse_response, parse_message_list, parse_fetch_response
from bloom_filter2 import BloomFilter

config = configparser.ConfigParser()

_RE_COMBINE_WHITESPACE = re.compile(r'\s+')
_RE_IMAP_VALUE = re.compile(r'^[ ](?P<name>.+)[ ](?P<value>.+)\)$')
_RE_LIST_RESPONSE = re.compile(r'\((?P<flags>.*?)\) "(?P<delimiter>.*)" (?P<name>.*)')
_RE_UID = re.compile(r'(?<=UID )(\d+)')

def parse_list_response(s):
    match = _RE_LIST_RESPONSE.match(s)
    flags, delimiter, mailbox_name = match.groups()
    mailbox_name = mailbox_name.strip('"')
    return (set(_RE_COMBINE_WHITESPACE.split(flags)), delimiter, mailbox_name)

def parse_imap_value(s):
    #s = bytes.decode(s)
    print("String: " + s)
    match = _RE_IMAP_VALUE.match(s)
    name = match.group("name")
    value = int(match.group("value"))
    return (name, value)

def message_uid(s):
    """the global ID for emails"""
    try:
        return _RE_UID.findall(s)[0]
    except:
        return None

pp = pprint.PrettyPrinter(indent=4)

argparser = argparse.ArgumentParser(description="imaptool.py - Email IMAP tool for syncing, copying, migrating and archiving email mailboxes between imap servers and local storage.")

argparser.add_argument('--dry', dest='dry', help="Dry run", default=False, action='store_true')
argparser.add_argument('--debug', dest='debug', help="Debug output", default=False, action='store_true')
argparser.add_argument('--showpasswords', dest='showpassowords', help="Show passwords in log and stdout", default=False, action='store_true')

argparser.add_argument('-a', '--eml1', dest='eml1', nargs="+", help='Append emls')
argparser.add_argument('-m', '--mbox1', dest='mbox1', help="File location of mbox1", default=False)
argparser.add_argument('-s', '--host1', dest='host1', help="IMAP host for host1", default=False)
argparser.add_argument('-p', '--port1', dest='port1', help="IMAP port for host1", default=1143)
argparser.add_argument('-u', '--user1', dest='username1', help="IMAP username for host1", default='username')
argparser.add_argument('-P', '--password1', dest='password1', help="IMAP password for host1", default=False)
argparser.add_argument('--passfile1', dest='passfile1', help="IMAP password file for host1", default=False)
argparser.add_argument('--passrequest1', dest='passrequest1', help="IMAP password request for host1", default=False)
argparser.add_argument('--ssl1', dest='ssl1', help="Use SSL for host1", default=False, action='store_true')
argparser.add_argument('--gmail1', dest='gmail1', help="Gmail for host1", default=False, action='store_true')

argparser.add_argument('--eml2', dest='eml2', help="Export eml", default=False)
argparser.add_argument('--mbox2', dest='mbox2', help="Export mbox", default=False)
argparser.add_argument('--host2', dest='host2', help="IMAP host for host2", default=False)
argparser.add_argument('--port2', dest='port2', help="IMAP port for host2", default=1143)
argparser.add_argument('--user2', dest='username2', help="IMAP username for host2", required=False)
argparser.add_argument('--password2', dest='password2', help="IMAP password for host2", default=False)
argparser.add_argument('--passfile2', dest='passfile2', help="IMAP password file for host2", default=False)
argparser.add_argument('--passrequest2', dest='passrequest2', help="IMAP password request for host2", default=False)
argparser.add_argument('--ssl2', dest='ssl2', help="Use SSL for host2", default=False, action='store_true')
argparser.add_argument('--gmail2', dest='gmail2', help="Gmail for host2", default=False, action='store_true')

argparser.add_argument('-f', dest='folders', help="IMAP folder", nargs="+")

argparser.add_argument('-l', dest='list', help="List", default="\"\"")
argparser.add_argument('-e', '--extended', dest='extended', help="Extended list", default=False, action='store_true')
argparser.add_argument('--extended2', dest='extended2', help="Extended list", default=False, action='store_true')
argparser.add_argument('-q', '--query', dest='query', nargs="+", help='Query messages')
argparser.add_argument('--from-ts', dest='fromts', help='Query messages from', type=int, default=False)
argparser.add_argument('--to-ts', dest='tots', help='Query messages to', type=int, default=False)
argparser.add_argument('--delete', dest='delete', help='Delete', default=False, action='store_true')
argparser.add_argument('--expunge', dest='expunge', help='Expunge', default=False, action='store_true')
argparser.add_argument('--expunge-all', dest='expungeall', help='Expunge (add \\\\Deleted)', default=False, action='store_true')

argparser.add_argument('--update', dest='update', help='Update', default=False, action='store_true')
argparser.add_argument('--bloom-max-elements', dest='bloom_max_elements', help="Maximum number of elements", default=1000000)
argparser.add_argument('--bloom-reverse-error-rate', dest='bloom_reverse_error_rate', help="Error rate equals 1/reverse_error_rate", default=1000000000)

#argparser.add_argument('-U', '--uid', dest='uid', help="UID", type=int, default=1)
#argparser.add_argument('-I', '--inc', dest='inc', help="Incremental update", default=False, action='store_true')

argparser.add_argument('-I', '--use-message-id', dest='use_message_id', help="Use Message-ID", default=False, action='store_true')
argparser.add_argument('-7', '--utf7', dest='utf7', help="Expect folders encoded in UTF7", default=False, action='store_true')

args = argparser.parse_args()


# Init

if args.passrequest1:
    args.password1 = getpass.getpass()

if args.passrequest2:
    args.password2 = getpass.getpass()

if args.gmail1:
    args.ssl1 = True
    args.host1 = 'imap.gmail.com'
    args.port1 = 993

if args.gmail2:
    args.ssl2 = True
    args.host2 = 'imap.gmail.com'
    args.port2 = 993

if args.debug:
    imaplibbase.Debug = 4

if args.host1:
    if not args.ssl1:
        imap1 = imaplib.IMAP4(args.host1, args.port1)
        imap1.starttls()
    else:
        imap1 = imaplib.IMAP4_SSL(args.host1, args.port1)
    imap1.login(args.username1, args.password1)
    if args.debug:
        print('imap1 capabilities:', imap1.capabilities, file=sys.stderr)

if args.host2:
    if not args.ssl2:
        imap2 = imaplib.IMAP4(args.host2, args.port2)
        imap2.starttls()
    else:
        imap2 = imaplib.IMAP4_SSL(args.host2, args.port2)
    imap2.login(args.username2, args.password2)
    if args.debug:
        print('imap2 capabilities:', imap2.capabilities, file=sys.stderr)

if (args.mbox1):
    mbox1 = mailbox.mbox(args.mbox1)

if (args.mbox2):
    mbox2 = mailbox.mbox(args.mbox2)

if args.debug:
    print(" ".join(map(pipes.quote, sys.argv)), file=sys.stderr)

#UID, FLAGS

# Use cases

def smallhash(s):
    return int(hashlib.sha256(s).hexdigest(), 16) % 10**8 

def imap_delete(imap):
    #imap.send(b'MOVE 1:* Trash')
    imap.copy("1:*", 'Trash')
    imap.select('Trash');
    imap.store("1:*", '+FLAGS', '\\Deleted')
    imap.expunge()

def imap_expunge(imap):
    if args.expungeall:
        imap.store("1:*", '+FLAGS', '\\Deleted')
    imap.expunge()

def imap_select(imap, folder):
    return imap.select("\"" + (folder if args.utf7 else encode_utf7(folder).decode('utf8')) + "\"")[1][0]

def imap_uidvalidity(imap):
    return bytes.decode(imap.untagged_responses.get('UIDVALIDITY', [None])[0])
def imap_uidnext(imap):
    return bytes.decode(imap.untagged_responses.get('UIDNEXT', [None])[0])
def imap_recent(imap):
    return bytes.decode(imap.untagged_responses.get('RECENT', [None])[0])

def imap_append(imap, folder, message, flags = ''):
    imap.append(folder, flags, imaplibbase.Time2Internaldate(time.time()), message)

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

def message_print(message):
    try:
        timestamp = email.utils.parsedate_to_datetime(message.get('Date')).timestamp()
    except:
        timestamp = 0
    try:
        message_id = email.header.make_header(email.header.decode_header(message.get('Message-ID')))
    except:
        message_id = message.get('Message-ID')
    try:
        subject = message.get('Subject')
        if subject:
            #subject = _RE_COMBINE_WHITESPACE.sub(" ", subject).strip()
            subject = subject.replace('\n', ' ').replace('\r', ' ')
        subject = email.header.make_header(decode_utf7(email.header.decode_header(subject)))
    except:
        pass

    #print('%s\t%d\t%s\t%s' % (timestamp, size, message_id, subject))
    print('%s\t%s\t%s' % (timestamp, message_id, subject), end="\t")

    if args.extended2:
        for part in message.walk():
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

# Mbox => Mbox
# Mbox => Imap
# Mbox => Print

if (args.mbox1):
    if (args.mbox2):
        for message in mbox1:
            mbox_add(mbox2, message)
    elif (args.host1):
        if len(args.folders) != 0:
            sys.exit("A single target folder needed!")
        for message in mbox1:
            imap_append(imap1, folders[0], message)
    else:
        for message in mbox1:
            message_print(message)

elif args.folders:
    # TODO: if folder * then find all folders
    for folder in args.folders:
        exists = imap_select(imap1, folder)
        if args.expunge:
            imap_expunge(imap1)
        if args.delete:
            imap_delete(imap1)
        if args.eml1: # append emls
            for file in args.eml1:
                with open(file, "rb") as f:
                    message = f.read()#.decode('utf-8')
                    imap_append(imap1, folder, message)
        else:
            uidnext, uidvaliditynext = int(imap_uidnext(imap1)), int(imap_uidvalidity(imap1))

            name = args.mbox2 if args.mbox2 else args.eml2
            config = configparser.ConfigParser()
            config['inc'] = {'uid': 1, 'uidvalidity': -1}
            config_name = f'{name}.ini'
            config.read(config_name)
            uid = int(config['inc']['uid'])
            uidvalidity = int(config['inc']['uidvalidity'])

            # reset uid on uid validity change and fallback to Message-ID
            if uidvaliditynext != uidvalidity:
                args.use_message_id = True
                uid = 1

            if uidnext <= uid: continue
            typ, data = imap1.uid('search', None, 'UID', f'{uid}:{uidnext-1}')
            # UID 1:* = ALL
            #typ, data = imap1.search(None, 'ALL')
            if args.eml2 or args.mbox2: # dump emls to mbox
                skip = False
                split = data[0].split()
                bloom = BloomFilter(
                        max_elements=args.bloom_max_elements, 
                        error_rate=1/args.bloom_reverse_error_rate, 
                        filename=(f'{name}.bloom', -1))

                incomplete = args.use_message_id and args.update
                for num in split:
                    while True:
                        try:
                            typ, data = imap1.uid('fetch', num, 
                                    '(UID BODY.PEEK[HEADER.FIELDS (DATE MESSAGE-ID)])' if incomplete else '(RFC822)')
                            break
                        except Exception as e: print(e, file=sys.stderr); continue
                    for response_part in data:
                        if isinstance(response_part, tuple):
                            try:
                                msg_str = email.message_from_string(response_part[1].split(b'\r\n\r\n')[0].decode('utf-8'))

                                message_id = msg_str.get('Message-ID')
                                if message_id in bloom and args.use_message_id: skip = True; break
                                else:
                                    print(f'Added message to bloom filter: {message_id}', file=sys.stderr)
                                    if incomplete: typ, data = imap1.uid('fetch', num, '(RFC822)')
                                    bloom.add(message_id)

                                dt = email.utils.parsedate_to_datetime(msg_str.get('Date'))
                                if args.mbox2: mbox = mailbox.mbox(dt.strftime(args.mbox2))
                            except Exception as e:
                                print(e, file=sys.stderr);
                                if args.mbox2: mbox = mailbox.mbox(args.mbox2)
                    if skip: skip = False; continue
                    data = parse_fetch_response(data)
                    uid = next(iter(data))
                    if b'RFC822' in data[uid]:
                        rfc822 = data[uid][b'RFC822']
                        if args.mbox2:
                            message = _mboxMMDFMessage(rfc822)
                            mbox.add(message)
                            mbox.close()
                        elif args.eml2:
                            directory = f'{args.eml2}/{uidvaliditynext}/'
                            Path(directory).mkdir(parents=True, exist_ok=True)
                            emlfile = open(f'{directory}{uid}.eml', 'wb')
                            emlfile.write(rfc822)
                            emlfile.close()
                        config['inc'] = {'uid': uid+1, 'uidvalidity': uidvaliditynext}
                        with open(config_name, 'w') as configfile:
                            config.write(configfile)
                    else: print("No RFC822 found for: %d" % uid, file=sys.stderr)
                    #message.set_from("%s@%s:%s/%d" % (args.username1, args.host1, folder, uid), time.gmtime())
                #mbox.close()
            elif (args.query):
                queryset = frozenset(args.query)
                typ, data = imap1.search(None, 'ALL')
                for num in data[0].split():
                    typ, data = imap1.fetch(num, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')
                    for response_part in data:
                        if isinstance(response_part, tuple):
                            msg_str = email.message_from_string(response_part[1].decode('utf-8'))
                            message_id = msg_str.get('Message-ID')
                            if message_id in queryset:
                                print("match")
                                typ, data = imap1.fetch(num, '(RFC822)')
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
                        #imap1.store(num, '+FLAGS', '\\Deleted')
                    elif (args.extended):
                        typ, data = imap1.fetch(num, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID SUBJECT DATE)] RFC822.SIZE)')
                        #typ, data = imap1.fetch(num, '(RFC822)')
                        #(name, size) = parse_imap_value(data[1].decode('utf-8'))
                        for response_part in data:
                          if isinstance(response_part, tuple):
                            msg_str = email.message_from_string(response_part[1].decode('utf-8'))
                            try:
                                timestamp = email.utils.parsedate_to_datetime(msg_str.get('Date')).timestamp()
                            except:    
                                timestamp = 0
                            try:
                                message_id = imap1.header.make_header(imap1.header.decode_header(msg_str.get('Message-ID')))
                            except:
                                message_id = msg_str.get('Message-ID')
                            try:
                                subject = imap1.header.make_header(decode_utf7(imap1.header.decode_header(msg_str.get('Subject'))))
                            except:
                                subject = msg_str.get('Subject')

                            #print('%s\t%d\t%s\t%s' % (timestamp, size, message_id, subject))
                            print('%s\t%s\t%s' % (timestamp, message_id, subject))
                    else:
                        #typ, data = imap1.fetch(num, '(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')
                        typ, data = imap1.uid('fetch', num, '(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])')
                        for response_part in data:
                            if isinstance(response_part, tuple):
                                print(message_uid(response_part[0].decode('utf-8')))
                                msg_str = email.message_from_string(response_part[1].decode('utf-8'))
                                try:
                                    message_id = imap1.header.make_header(imap1.header.decode_header(msg_str.get('Message-ID')))
                                except:
                                    message_id = msg_str.get('Message-ID')
                                print(message_id);
                if (args.delete):
                    pass
                    #imap1.expunge()

elif args.host1:
    #imap1.select("Sent")
    #imap1.search("UID", None, "2090:2312")
    #sys.exit()
    # * all, % - children
    for i in imap1.list(args.list, "*")[1]:
    #for i in imap1.list('(SPECIAL-USE)', '"" "*"')[1]:
    #for i in imap1.list('(SPECIAL-USE)', '"" "*"')[1]:
        #i.decode().split(' "/" ')
        if args.utf7:
            print(parse_list_response(i.decode('utf-8')))
        else:
            print(parse_list_response(decode_utf7(i)))

# Cleanup

if args.mbox1:
    mbox1.close()

if args.mbox2:
    mbox2.close()

if args.host1:
    #imap1.close()
    imap1.logout()

if args.host2:
    imap2.close()
    imap2.logout()
