# Using Zeek broker to alert on Bad ASNs as reported by [CIRCL](http://circle.lu/projects/bgpranking/)
--------------------------------------------------------------
The Zeek script will perform an ASN lookup on the remote connection's IP address from conn.log. It will then perform a call to CIRCL's Bad ASN API to retrieve a score/ranking. ASNs that cross a determined threshold will be written to notice.log. There are a couple of prerequisites noted below. Many rely on default settings but please double check before implementing.

--------------------------------------------------------------
## Notes:
- Written to work with Python 3.x
- Broker is utilized to pass data from Zeek to python and perform API lookups. Broker information and installation install instructions can be found [here](https://github.com/zeek/broker). Be sure to run `git clone` with the `--recursive` flag set.
- GeoLocation data and integration with MaxMind is required to perform the initial ASN lookups. You will need to install libmaxminddb and build from source. Zeek has documented this process [here](https://docs.zeek.org/en/current/frameworks/geoip.html)
- You can sign up for access to MaxMind's free GeoLite databases [here](https://dev.maxmind.com/geoip/geoip2/geolite2/)
- In order to update these databases monthly, follow MaxMind's [guide](https://dev.maxmind.com/geoip/geoipupdate/)
- The script leverages Zeek's [default locations](https://docs.zeek.org/en/current/frameworks/geoip.html) for the MaxMind databases - highly recommend using those or you will need to customize your configs
- Your local subnets are used to differentiate between local and remote IP addresses. These subnets are defined in networks.cfg and configured when using zeekctl-deploy. If not using zeekctl, you may configure using zeek's [example](https://docs.zeek.org/en/current/quickstart/index.html?highlight=Site%3A%3Alocal_nets#local-site-customization)
- The Zeek script uses the EXEC framework to start the companion python script upon Zeek startup. __The location of the python script is currently hardcoded into the command and this would need to be changed if packages are installed anywhere else.__
- This has been used mostly on small, internet-facing honeypots and we have not experienced any performance issues. However, we have not tested in an enterprise environment with high a volume of traffic - use with caution in such environments as this will perform numerous lookups and could impact performance.
- __Development and testing was performed using Zeek 3.2.0.__ Testing indicated that the scripts are not compatible with older Zeek versions.
