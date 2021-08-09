# homedns

`homedns` is a DNS server meant to reliably resolve client devices on a LAN. It
publishes local devices under two fake DNS zones:
 * `.mdns` for discovered mDNS devices
 * `.lan` for devices imported from supported router firmware

All other DNS requests are forwarded to an upstream provider (currently
Cloudflare) using DNS over TLS.

Once running, just point your client devices to the DNS server and access them
via `hostname.lan` or `hostname.mdns`.

## Supported router firmware

At this time, the `.lan` zone only supports the Qnap QHora-301W (and possibly
other Qnap routers).

The `.mdns` zone should work on any network, but only discovers devices that
support mDNS.

## Usage

```bash
homedns --dns-listen 0.0.0.0:5053 --web-listen 0.0.0.0:8053
```

Qnap integration requires additional flags: `--qnap-url`, `--qnap-username`,
`--qnap-password`

## Motivation

The short version: local DNS resolution stinks. Most home routers don't do
anything to assist with this other than allowing users to statically assign an
IP to a device. Otherwise, you're stuck with whatever mDNS/WINS/etc gives you
which is unreliable and generally not portable between platforms.

I recently moved from using a Google OnHub (now Google Wifi) to using a Qnap
QHora-301W as my home network's primary router. Google's routers provide a handy
`.lan` zone that publishes all local devices by their hostname which (mostly)
worked great. My new router's built-in DNS server lacks this feature. This
project is an attempt to restore that functionality and hopefully improve on it.

## Qnap Integration Notes

Qnap's firmware unfortunately only allows a single API token to be issued at any
time, which includes human users accessing the router's web interface. Tokens
last 24 hours and don't seem to expire on their own. Users can "force" a login
which invalidates any previously issued tokens and kicks out any sessions using
the web UI.

Because tokens take a full day to expire on their own, we do need to force
logins. To avoid unnecessarily kicking human users out of the web UI, we do the
following:
 * Force the first login.
 * Record the token's expiration time.
 * Continuously check the client list.
 * When an error is received:
   * If the token has expired, immediately attempt a regular login.
   * If the token has not expired, wait 15 minutes to give the (presumably)
     human user time to finish using the web UI, then force a login.

## To-do list

 * Configurable upstream DNS providers
 * Possibly more router firmware querying
 * Status page listing all devices
