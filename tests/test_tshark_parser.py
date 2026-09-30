import json

from app.analysis import tshark


def test_tshark_json_is_aggregated_into_an_email_session(monkeypatch):
    packets = [
        {
            "_source": {
                "layers": {
                    "frame": {"frame.number": "1", "frame.time_epoch": "1700000000.0", "frame.len": "120"},
                    "ip": {"ip.src": "10.0.0.10", "ip.dst": "10.0.0.20"},
                    "tcp": {"tcp.stream": "4", "tcp.srcport": "51000", "tcp.dstport": "587", "tcp.len": "80"},
                    "smtp": {"smtp.req.command": "EHLO", "smtp.req.parameter": "STARTTLS"},
                }
            }
        },
        {
            "_source": {
                "layers": {
                    "frame": {"frame.number": "2", "frame.time_epoch": "1700000001.0", "frame.len": "200"},
                    "ip": {"ip.src": "10.0.0.20", "ip.dst": "10.0.0.10"},
                    "tcp": {"tcp.stream": "4", "tcp.srcport": "587", "tcp.dstport": "51000", "tcp.len": "160"},
                    "smtp": {"smtp.rsp.code": "220", "smtp.rsp.parameter": "Ready for TLS"},
                    "tls": {
                        "tls.handshake.type": "Client Hello",
                        "tls.handshake.version": "0x0303",
                        "tls.handshake.ciphersuite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "tls.handshake.extensions_server_name": "mail.example.test",
                    },
                }
            }
        },
        {
            "_source": {
                "layers": {
                    "frame": {"frame.number": "3", "frame.time_epoch": "1700000001.2", "frame.len": "220"},
                    "ip": {"ip.src": "10.0.0.20", "ip.dst": "10.0.0.10"},
                    "tcp": {"tcp.stream": "4", "tcp.srcport": "587", "tcp.dstport": "51000", "tcp.len": "180"},
                    "tls": {
                        "tls.handshake.type": "Server Hello",
                        "tls.handshake.version": "0x0303",
                        "tls.handshake.ciphersuite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                        "tls.handshake.certificate": "30" + "00" * 120,
                    },
                }
            }
        },
    ]
    monkeypatch.setattr(tshark, "tshark_available", lambda: True)
    # analyze_pcap may take a second pass with decode hints for captures on unusual
    # ports, so the stand-in accepts the optional port map.
    monkeypatch.setattr(tshark, "_run_tshark",
                        lambda path, port_map=None, exclude_ports=None: json.dumps(packets))

    sessions = tshark.analyze_pcap(__import__("pathlib").Path("capture.pcap"))
    assert len(sessions) == 1
    session = sessions[0]
    assert session.protocol == "SMTP"
    assert session.server_port == 587
    assert session.starttls.command_seen is True
    assert session.tls.detected is True
    assert session.tls.tls_version == "TLS 1.2"
    assert session.tls.key_exchange == "ECDHE"
    assert session.tls.forward_secrecy is True
