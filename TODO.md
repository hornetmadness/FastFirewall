# TODO

## Networking / Boot

- [ ] Investigate replacing `After=network.target` with ifstate-native boot ordering — remove dependency on NetworkManager/networking.service and let ifstate own interface bring-up directly
- [ ] Declare `Before=network-online.target` in `fastfirewall-networking.service` so ifstate fully replaces the distro network manager for interface bring-up
