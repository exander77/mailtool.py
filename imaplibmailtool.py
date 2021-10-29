import imaplibext as imaplib

#def imap_list:
#    return [parse_list_response(i.decode('utf-8')) for i in imap1.list(args.list, "*")[1]]

class IMAP4(imaplib.IMAP4):
    pass
class IMAP4_SSL(imaplib.IMAP4_SSL):
    pass
