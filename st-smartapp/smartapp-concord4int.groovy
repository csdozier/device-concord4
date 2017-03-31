/**
 *  Concord 4 Integration via REST API Callback
 *
 *  Make sure and publish smartapp after pasting in code.
 *  Author: Scott Dozier
 */
definition(
    name: "Concord 4 Integration",
    namespace: "csdozier",
    author: "csdozier",
    description: "Handles the REST callback from concord and set virtual devices",
    category: "Safety & Security",
    iconUrl: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience.png",
    iconX2Url: "https://s3.amazonaws.com/smartapp-icons/Convenience/Cat-Convenience@2x.png")


preferences {
	section("Zones") {
		input "zone1", "capability.contactSensor", title:"Zone 1"
        input "zone2", "capability.contactSensor", title:"Zone 2"
        input "zone3", "capability.contactSensor", title:"Zone 3"
        input "zone4", "capability.contactSensor", title:"Zone 4"
        input "zone5", "capability.contactSensor", title:"Zone 5"
        input "zone6", "capability.contactSensor", title:"Zone 6"
 		input "zone7", "capability.contactSensor", title:"Zone 7"
        input "zone8", "capability.contactSensor", title:"Zone 8"
        input "zone9", "capability.contactSensor", title:"Zone 9"
        input "zone10", "capability.contactSensor", title:"Zone 10"
        input "zone13", "capability.contactSensor", title:"Zone 13"
        input "zone14", "capability.contactSensor", title:"Zone 14"
        input "zone15", "capability.contactSensor", title:"Zone 15"

	}
	section("Which is your Concord4?") {
		input "concord4", "capability.lock"
	}     
}

mappings {
	path("/concord/:id/:item/:state") {
		action: [
			GET: "updateStatus"
		]
	}

}

void updateStatus() {
    log.debug("updateStatus params: ${params}")
	if (params.item == 'armstatus')
    {
    updateConcord4ArmStatus()
    }
    else if (params.item.contains('zone'))
    {
    updateConcord4ZoneStatus()
    }

}
void updateConcord4ArmStatus() {
	def armState = params.state
    def device = concord4.find { it.id == params.id }
    state.concord_id = params.id
	if (!device) {
			httpError(404, "Device not found")
		}
    log.debug("state: ${armState}")
    if(armState == "disarmed")
    {
    device.update("armStatus","Off")
    device.update("lock","unlocked")
	sendLocationEvent(name: "alarmSystemStatus", value: "off")
    }
    else if(armState == "armed_away")
    {
    device.update("armStatus","Away")
    device.update("lock","locked")
	sendLocationEvent(name: "alarmSystemStatus", value: "away")
    }
    else if(armState == "armed_stay")
    {
    device.update("armStatus","Stay")
    device.update("lock","locked")
	sendLocationEvent(name: "alarmSystemStatus", value: "stay")
    }
}

void updateConcord4ZoneStatus() {
    log.debug("zonestatus params: ${params}")
    state.concord_id = params.id
	def zoneState = params.state
	def zone = params.item

    def device = concord4.find { it.id == params.id }
	if (!device) {
			httpError(404, "Device not found")
		}
    else
    {
    device.update("${zone}",zoneState)
    }
}
private void update(devices) {
	log.debug "update, request: params: ${params}, devices: $devices.id"
	//def command = request.JSON?.command
    def param = params.param
    def state = params.state
    //let's create a toggle option here
	if (command)
    {
		def device = concord4.find { it.id == params.id }
		if (!device) {
			httpError(404, "Device not found")
		} else {
        	device.update(param,state)
		}
	}
}

def installed() {
	log.debug "Installed with settings: ${settings}"

	initialize()
}

def updated() {
	log.debug "Updated with settings: ${settings}"

	unsubscribe()
	initialize()
}

def initialize() {
	subscribe(location, "alarmSystemStatus", alarmHandler)

	for(int i=1; i<=25; i++ )
    {
		subscribe( concord4, "zone${i}.open", zoneOpen )
    	subscribe( concord4, "zone${i}.closed", zoneClose )
    }
}

def alarmHandler(evt) {
  log.debug "Alarm Handler evt.value: ${evt.value}"
  def device = concord4.find { it.id == state.concord_id }
    log.debug("alarmHandler device.lock: ${device.currentValue("lock")}")
    if(evt.value == "off")
    {
    if (device.currentValue("lock") != "unlocked")
    {
        device.unlock()
    	device.update("armStatus","Off")

    }
    }
    else if(evt.value == "away")
    {
    if (device.currentValue("lock") != "locked")
    {
        device.armaway()
    	device.update("armStatus","Away")
    }
    }
    else if(evt.value == "stay")
    {
    if (device.currentValue("lock") != "locked")
    {
        device.armstay()
    	device.update("armStatus","Stay")
    }
    }
}
def zoneOpen(evt)
{
	log.debug "Setting Device Open"   
    switch( evt.name )
    {
        case "zone1":
        zone1.open( "Zone 1" )
        break;
        case "zone2":
        zone2.open( "Zone 2" )
        break;
        case "zone3":
        zone3.open( "Zone 3" )
        break;
        case "zone4":
        zone4.open( "Zone 4" )
        break;
        case "zone5":
        zone5.open( "Zone 5" )
        break;
        case "zone6":
        zone6.open( "Zone 6" )
        break;        
        case "zone7":
        zone7.open( "Zone 7" )
        break;
        case "zone8":
        zone8.open( "Zone 8" )
        break;
        case "zone9":
        zone9.open( "Zone 9" )
        break;
        case "zone10":
        zone10.open( "Zone 10" )
        break;
        case "zone13":
        zone13.open( "Zone 13" )
        break;
        case "zone14":
        zone14.open( "Zone 14" )
        break;        
        case "zone15":
        zone15.open( "Zone 15" )
        break;      
    };
}

def zoneClose(evt)
{
	log.debug "Setting Device Closed"
    switch( evt.name )
    {
        case "zone1":
        zone1.closed( "Zone 1" )
        break;
        case "zone2":
        zone2.closed( "Zone 2" )
        break;
        case "zone3":
        zone3.closed( "Zone 3" )
        break;
        case "zone4":
        zone4.closed( "Zone 4" )
        break;
        case "zone5":
        zone5.closed( "Zone 5" )
        break;
        case "zone6":
        zone6.closed( "Zone 6" )
        break;        
        case "zone7":
        zone7.closed( "Zone 7" )
        break;
        case "zone8":
        zone8.closed( "Zone 8" )
        break;
        case "zone9":
        zone9.closed( "Zone 9" )
        break;
        case "zone10":
        zone10.closed( "Zone 10" )
        break;
        case "zone13":
        zone13.closed( "Zone 13" )
        break;
        case "zone14":
        zone14.closed( "Zone 14" )
        break;   
        case "zone15":
        zone15.closed( "Zone 15" )
        break;   
    };
}
