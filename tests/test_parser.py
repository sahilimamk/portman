import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
# import parser helpers without GTK main side effects: module imports gi but that's ok headless? 
# If Gtk unavailable in CI, skip gracefully.
try:
    from portman import parse_ss, split_addr_port, WELL_KNOWN
except Exception as e:
    print(f"SKIP: GTK import unavailable in this env: {e}")
    raise SystemExit(0)

SAMPLE = """Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=801,fd=14))
tcp   LISTEN 0 511 0.0.0.0:3001 0.0.0.0:* users:(("node",pid=4321,fd=20))
tcp   LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=900,fd=4))
udp   UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("avahi-daemon",pid=700,fd=12))
tcp   ESTAB 0 0 192.168.0.106:54322 142.250.77.14:443 users:(("chrome",pid=2222,fd=33))
tcp   LISTEN 0 100 *:8080 *:* 
"""

def test_split():
    assert split_addr_port("127.0.0.53%lo:53") == ("127.0.0.53%lo", "53")
    assert split_addr_port("[::]:22") == ("::", "22")
    assert split_addr_port("0.0.0.0:*") == ("0.0.0.0", "*")
    print("split ok")

def test_parse():
    rows = parse_ss(SAMPLE)
    assert len(rows) == 6, rows
    by_port = {r['local_port']: r for r in rows}
    assert by_port['3001']['process'] == 'node'
    assert by_port['3001']['pid'] == 4321
    assert by_port['3001']['service'] == 'Dev (Node)'
    assert by_port['22']['local_addr'] == '::'
    assert by_port['53']['service'] == 'DNS'
    assert by_port['8080']['pid'] is None
    estab = [r for r in rows if r['state']=='ESTAB'][0]
    assert estab['peer_port'] == '443' and estab['process'] == 'chrome'
    print("parse ok")

if __name__ == '__main__':
    test_split(); test_parse(); print("ALL TESTS PASS")
