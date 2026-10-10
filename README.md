# lotu
Primitive and small intrusion detection system with notification on phone, all via local services.

"lotu" stands for "LOcal TUrris".
The intention is to make easier to have your server exposed over internet, having your data only hosted local for you.

## Reduce attack surface
Use established software / hardware and only connect them with a thin layer.

## Last version
Prefer last versions available. Not only for the server[s] but also other software / hardware using or cooperating with your service. (When did you last update your Laptop?)

## Audit
Select and run periodically audit.

## Constantly Observe ("Turris")
Enable the logging on the edge of either hardware and software, to know timely and precisely who is (trying) to (ab)use your service.

# Current setup

## Hardware
Fiber <=> FritzBox <=> Raspberry Pi 5

## Update
Updates are done manually once per week.

| Device   |      Software      |  Update Command|
|----------|-------------|------|
| Fritz Box | Fritz OS | Check from the webpage |
| Raspberry Pi 5 | Debian Trixie | apt update && apt upgrade |
| Raspberry Pi 5 | Next Cloud | php updater/updater.phar | 
| Swift Lite 14 | CachyOS | GUI trigger it every  few days |

# Professional solutions
https://ui.com/
https://www.home-assistant.io/green
https://uptime.kuma.pet/
