# device-concord4
Concord 4 SmartThings Device Hander and SmartApp

Sorry documentation is rather poor... 

This is a project for connecting the Concord 4 alarm system to smartthings.   You will need a computer/rasperry pi/etc with a USB serial cable connected to the superbus 2000 automation module.


Instructions:
1.  Connect hardware (Usb serial ---> Superbus AM --- > Concord 4 Panel)
2.  Install python 2.7 
3.  Install python packages future,micropython-serial ,pyserial,requests
4.  Install device types in Smartthings IDE (graph.api.smartthings.com)
5.  Install SmartApp in Smartthings IDE(graph.api.smartthings.com)
6.  Gather the app id, device id, and [access token](http://docs.smartthings.com/en/latest/smartapp-web-services-developers-guide/tutorial-part2.html#get-an-access-token) from smartthings.
7.  Edit concordsvr.conf and fill in the ids
8.  Start python concordsvr
