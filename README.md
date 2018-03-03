# fgsniff

`fgsniff` is a command-line program written in Go that will produce pcaps from a remote Fortigate using SSH and the `diagnose sniffer packet` command.

There is an application distributed by Fortinet called `fg2eth.pl` that is available [here](http://kb.fortinet.com/kb/documentLink.do?externalId=11186). However, I was not able to get it to work and it appeared to required copying the raw output into a file first.

## Motivation

I needed to cap some p's and my shinney new Fortigate 80e did not have the menu item available for producing the pcaps directly on the unit. Apparently Fortigate removed support for packet capture on devices that don't have a hard drive ([source](https://www.reddit.com/r/fortinet/comments/6pansn/fortigate_5456_packet_capture_gui/))

## How it works

`fgsniff` has a few command line flags that let you control the target fortigate, the username, and some of the parameters that go into the `diagnose sniffer packet ...` command. It connects to the Fortigate over SSH, issues the command, and streams the output into a pcap file, making the conversion as it goes.

Just kill the program once you have the traffic you need. Eventually I may add some graceful shutdown features, but none of my test pcap files were corrupted by killing this application to stop the capture.

## Building

`go install github.com/aerissecure/fgsniff`