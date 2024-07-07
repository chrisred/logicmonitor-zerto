# Zerto LogicMonitor Modules

"[LogicModules](https://www.logicmonitor.com/support/logicmodules/about-logicmodules/introduction-to-logicmodules)"
for monitoring [Zerto](https://www.zerto.com/) VPGs, VRAs and other resources through the Zerto APIs.

To download the `.xml` files use the "Download raw file" option for an individual file. Or select Code > Download ZIP
to get a zipped copy of the repository.

The `Scripts` folder contains a copy of the Groovy scripts used by each module. Due to how LogicMonitor modules work
currently there are duplicate sections between files.

## Usage

`ZertoAnalytics_Alerts.xml` and `ZertoAppliance_Alerts.xml` are "EventSource" modules, all the rest are "DataSource"
modules. Each module can be imported into a LogicMonitor tenant using the Add > From File
[option](https://www.logicmonitor.com/support/logicmodules/about-logicmodules/importing-exporting-xml-eventsources).

Modules with the `ZertoAnalytics` prefix work with [Zerto Analytics Portal](https://analytics.zerto.com/) API. This
requires an Analytics user account to authenticate to the API.

Modules with the `ZertoAppliance` prefix work with the "Zerto Virtual Manager" and "Zerto Cloud Manager" API. This
requires an account on the ZVM/ZCM with read access to authenticate. The Windows based "ZVM" and Linux based "ZVMA"
have difference authentication methods, the notes in the `ZertoAppliance_Token` module have more details.

The modules have been tested with Zerto v9+.