import sys, broker, requests, datetime, json
from time import sleep

# Setup endpoint and connect to Zeek.
ep = broker.Endpoint()
subscriber = ep.make_subscriber("/topic/asns")
stat_stub = ep.make_status_subscriber(True);
ep.peer("127.0.0.1", 9999)

# Wait until connection is established, quit the script if it doesn't
st = stat_stub.get()
if not (type(st) == broker.Status and st.code() == broker.SC.PeerAdded):
    print("could not connect")
    sys.exit(0)

# ASN ranking endpoint
url = 'https://bgpranking-ng.circl.lu/json/asn'

# Initializing two dictionaries to hold rankings data and ASN:IP mappings
asn_rankings={}
asn_ips={}

#Initialize date for timekeeping, this will be used to reset the above dictionaries each day
tdate = datetime.date.today()

# While the script is running, do this
while True:
    # Get subscription from broker
    (t, d) = subscriber.get()
    # Get the event
    remote_event = (broker.zeek.Event(d))
    # Isolate the ASN and IP from the event
    remote_asn = str(remote_event.args()[0])
    remote_ip = str(remote_event.args()[1])

    # If the ASN isn't in 'asn_rankings' already, do the lookup to grab the ranking
    if remote_asn not in asn_rankings:
        # Create request data, call the API, and read the response
        post_data = {"asn" : remote_asn, "date": str(tdate)}
        post_data = json.dumps(post_data)
        asn_req = requests.post(url, data=post_data, allow_redirects=False)
        asn_data = asn_req.json()
        ranking = asn_data['response']['ranking']['rank']
        asn_rankings[remote_asn] = ranking
        asn_ips[remote_asn] = {str(remote_ip)}
        
        # Compare the ranking to our threshold - NOTE THAT THIS THRESHOLD MAY BE CHANGED
        if float(ranking) > 0.10:
        	# Create list for sending back to Broker
        	ranking_list = [str(remote_asn),str(ranking),str(remote_ip)]
        	# Create event
        	bad_asn = broker.zeek.Event("BadASN",ranking_list)
        	# Publish the event to the topic
        	ep.publish("/topic/asns", bad_asn)

        # Sleep for a moment since we just made a request
        sleep(0.75)
    else:
        if remote_ip in asn_ips[remote_asn]:
            # If the IP is already in the set, bottom out the ranking to avoid publishing it again
            ranking = 0
        else:
            # Get the rankings from the existing dictionary
            ranking = asn_rankings[remote_asn]
            # Add the remote IP to the set
            asn_ips[remote_asn].add(remote_ip)

    # Do a timecheck. Clear the dictionaries if it's a new day.
    timecheck = datetime.date.today()
    if tdate != timecheck:
        asn_rankings={}
        asn_ips={}
        tdate=datetime.date.today()