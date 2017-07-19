# device-concord4
Concord 4 SmartThings Device Hander and SmartApp

This is a project for connecting the Concord 4 alarm system to SmartThings.  You will need a computer/rasperry pi/etc with a USB serial cable connected to the superbus 2000 automation module.

## Prerequisites

 - Hardware (Concord 4 or equivalent panel) with a Superbus 2000 automation module attached to it
 - RS232 connection (to the AM panel)
 - Python 2.7
 - Python packages: requests, future, pyserial (pip install)
 - Raspberry Pi (recommended)

## Installation

 1. Download all files from this repository
 2. Login to https://graph.api.smartthings.com/
 3. Click **My Locations**, then click on a location. This will change the URL to something like http://graph-xx.api.smartthings.com/ which is the one you should work with
 4. Click **My Device Handlers** 
 5. Click **Create New Device Handler**
 6. Click **From Code** and paste in the contents of all the *.groovy* files in in *st-devicehandler* folder (repeat steps 3-7 for each of them)
 7. Create **Create**
 8.  Click **Publish**
 9. Click **My Devices** from the top menu bar and then click **New Device**
 10. Give the device an appropriate name (ex. 'Alarm') .  Set the type to **Concord 4** at the bottom of the list. The network ID can be anything, such as 'ALARM-PANEL'
 11. Click 'Create'
 12. In the 'Preferences' section, click 'edit', and fill in the fields:
    * *concord_server_api_password* - any password you will use on the Pi itself so the REST calls are only executed by you
    * *concord_server_ip_address* - the LAN IP address of your Pi, this needs to be static
    * *concord_server_port* - by default it's 8066, but you can change it
 13. Note the current URL in the browser, ex. https://graph-xx.api.smartthings.com/device/show/xxx-xxx-xxx-xxx-xxx . The device ID is in the url after /show/. You will need this ID for the config file in a later step, so write it down
 14. Repeat steps (9-11) 3 more times using the other device types (**Concord 4 Virtual Contact**, **Concord 4 Virtual Smoke**, and **Concord 4 Virtual Motion Detector**) but you do not set any preferencers for them
 15. Click **My SmartApps**
 16.  Click **New Smartapp**
 17. Click **From Code** and paste in the contents of *smartapp-concord4int.groovy*
 18. Click **Publish**
 19.  Click **App Settings** then Oauth, the **Enable Oauth in Smart App**
 20.  Write down the **Client ID** and **Client Secret**
 21.  Open a web browser window in private mode (incognito).  Navigate to this URL into your browser, substituting in the Client Id:
 
https://graph-xx.api.smartthings.com/oauth/authorize?response_type=code&client_id=<Client Id>&scope=app&redirect_uri=http://localhost

    If you are prompted to login to SmartThings, go ahead.
    Select you location from the drop down list and the receiver you want to have access to through the REST API
    Click the Authorize button.
    You'll be redirected to a URL that looks like this: http://localhost/?code=<Code>
    
    Copy the Code from the URL for later use.

 22. On the Raspberry Pi (or another Linux box), execute the command (substituting Client Id, Client Secret and the Code from the previous step in):
 
    curl -k "https://graph-xx.api.smartthings.com/oauth/token?grant_type=authorization_code&client_id=<Client Id>&client_secret=<Client Secret>&code=<Code>&scope=app&redirect_uri=https%3A%2F%2Fgraph.api.smartthings.com%2Foauth%2Fcallback"
    
 23. The response to this will contain an ID that will be your OAuth **API Token**, record this
 24. Open the Smarthings app on your mobile device. Select 'Marketplace', 'SmartApps', 'My Apps' and then 'Concord 4 Integration'. Select the alarm device (created in step 10) for 'Which?', and then select the correct device type for each zone. For example, contact sensors use virtual contact devices, fire detectors use virtual smoke etc. and install it
 25. Login to your Pi and install python and the packages via pip (if not already installed). Note that default raspbian comes with it, as does NOOBS
 26. Copy the entire *concordsvr* into a directory you can access, such as *~/*. You can use *git clone* as an easy way to get it from the repository
 27. Edit *concordsvr.conf* with your favourite editor, such as *nano concordsvr.conf*
    * Set *rest_api_auth_password* to the password preference you set in step (12)
    * If you changed port in step (12), then ensure **port** matches
    * Set *callbackurl_base* to your base URL with the correct *graph-xx* URL
    * Set *callbackurl_app_id* to the Client ID from your SmartApp from step (20)
    * Set *callbackurl_access_token* to the token retrieved from step (22-23)
    * Set *callbackurl_concord_device_id* to the device ID noted from the URL in step (13)
 28.  Start the program using **python concordsvr.py**


## API
The proxy accepts the following REST requests to control the alarm system.

* /concord/refresh/
* /concord/arm/stay/[loud]
* /concord/arm/away/[loud]
* /concord/disarm/[loud]
* /concord/keypress/[key]
