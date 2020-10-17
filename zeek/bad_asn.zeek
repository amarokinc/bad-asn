
@load base/frameworks/notice
global rem_asn: count;
global REM_ASN: event(rem_asn: count, remote_ip: addr);

# Add Bad_ASN notice
export {

	redef enum Notice::Type += {
			Bad_ASN
		};
	}

# On connection end
event connection_state_remove(c: connection)
  	 {
	local remote_ip: addr;
	
	if ( Site::is_local_addr(c$id$orig_h) )
		{
		remote_ip = c$id$resp_h;
		
		}
	else
		{
		remote_ip = c$id$orig_h;
		
		}
	# Lookup the ASN
	rem_asn = lookup_asn(remote_ip);
	# Trigger an event
	event REM_ASN(rem_asn, remote_ip);
        # Publish to broker
        Broker::auto_publish("/topic/asns", REM_ASN);
	}

event BadASN(ranking_list: vector of string)
	{
	# Get the ASN from the list returned by python
	local asn=ranking_list[0];
	# Get the rank from the list returned by python
	local rank=ranking_list[1];
	# Get the IP from the list returned by python
	local py_ip=ranking_list[2];
	# Create the notice for writing to log
	NOTICE([$note=Bad_ASN, $msg=fmt("ASN crossed bad reputation threshold -- ASN: %s | IP: %s | Rank: %s ", asn, py_ip, rank)]);
	}

# Start the broker service when the script loads
event zeek_init()
        {
	Broker::listen("127.0.0.1", 9999/tcp);
	Broker::subscribe("/topic/asns");
	local sleep_command = Exec::Command($cmd=fmt("sleep 10"));
	local pybroker_command = Exec::Command($cmd=fmt("python3 /opt/zeek/share/zeek/site/bad_asn/bad_asn.py & sleep 1") );
	when ( local sleep = Exec::run(sleep_command) ){
		
		
		when ( local pybroker = Exec::run(pybroker_command)){
		
			}
		}

	}

# Kill the python process when Zeek shuts down
event zeek_done()
        {
        local kill_python = Exec::Command($cmd=fmt("ps axf | grep bad_asn.py | grep -v grep | awk \'{print \"kill -9 \" $1}\' | sh"));
        when (local  kill_command = Exec::run(kill_python)){
        }
        }
