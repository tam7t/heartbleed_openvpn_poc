heartbleed_openvpn_poc
======================
Script to encapsulate heartbleed (CVE-2014-0160) POC's against OpenVPN

Built by Tommy Murphy (@tam7t) to investigate vulnerable dd-wrt build

Usage
-----
    python openvpn-proxy.py <openvpn server address>
    python heartbleed-poc.py localhost

Limitations
-----------
   * UDP only (no TCP)
   * implementing `--tls-auth` would block this (that would require HMAC'ing of messages)
   * `time_t` timestamp not implemented (part of packet-id)
   * no reliability layer (ignores acks/doesn't retransmit) 
   * `key id` parameter fixed to 0 (bottom 3 bits of OpenVPN opcode)
