import sys
import broker
import requests
import datetime
import json
from time import sleep


# Setup endpoint and connect to Zeek.
ep = broker.Endpoint()

sub = ep.make_subscriber("/topic/asns")

ss = ep.make_status_subscriber(True);

ep.peer("127.0.0.1", 9999)


# Wait until connection is established.
st = ss.get()

# End if it doesn't connect
if not (type(st) == broker.Status and st.code() == broker.SC.PeerAdded):
    print("could not connect")
    sys.exit(0)


# URL for ASN ranking data
url='https://bgpranking-ng.circl.lu/json/asn'

# Initializing two dictionaries to hold rankings data and ASN:IP mappings
asn_rankings={}
asn_ips={}

#Initialize date for timekeeping, this will be used to reset the above dictionaries each day
today=datetime.date.today()

# While the script is running, do this
while True:
    # Get subscription from broker
    (t, d) = sub.get()
    # Get the event
    remote_event = (broker.zeek.Event(d))
    # Isolate the ASN and IP from the event
    remote_asn=str(remote_event.args()[0])
    remote_ip=str(remote_event.args()[1])

    # If the ASN isn't in 'asn_rankings' already, do the lookup to grab the ranking
    if remote_asn not in asn_rankings:
        # Create post request data
        post_data={"asn" : remote_asn, "date": str(today)}
        post_data=json.dumps(post_data)
        # Make request
        asn_req = requests.post(url, data=post_data, allow_redirects=False)
        asn_data=asn_req.json()
        # Extract ranking from json
        ranking=asn_data['response']['ranking']['rank']
        # Conditional statement on asn (this could be changed to increase or decrease tolerance for ASN rankings) 
        # Add IP, ASN, and ranking to appropriate lists   
        asn_rankings[remote_asn] = ranking
        asn_ips[remote_asn] = {str(remote_ip)}
        
        # Sleep for a moment since we just made a request
        sleep(0.5)
    else:
        if remote_ip in asn_ips[remote_asn]:
            # If the IP is already in the set, bottom out the ranking to avoid publishing it again
            ranking=0
        else:
            # Else, get the rankings from the existing dictionary
            ranking = asn_rankings[remote_asn]
            # Add the remote IP to the set
            asn_ips[remote_asn].add(remote_ip)
       
    # Do logic on the ranking
    if float(ranking)>0.10:
        # Create list from the response for sending back to Broker
        ranking_list=[str(remote_asn),str(ranking),str(remote_ip)]
        # Create event
        BadASN=broker.zeek.Event("BadASN",ranking_list)
        # Publish the event to the topic
        ep.publish("/topic/asns", BadASN)
       
    # If the conditional statement wasn't met, do nothing
    else:
        pass

    # Do a timecheck. Clear the dictionaries if it's a new day.
    timecheck=datetime.date.today()
    if today==timecheck:
        pass
    else:
        asn_rankings={}
        asn_ips={}
        today=datetime.date.today()
    

