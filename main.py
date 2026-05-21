import argparse
import logging
import socket

from dnslib import DNSRecord, EDNSOption, RR, QTYPE

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 53530

UPSTREAM_HOST = "193.58.251.251"
UPSTREAM_PORT = 53

EDNS_TOKEN_OPTION_CODE = 65520
EDNS_CATEGORIES_OPTION_CODE = 65000


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SkyDNSProxy] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

logger = logging.getLogger("SkyDNSProxy")


def main():
    parser = argparse.ArgumentParser(description="SkyDNS EDNS0 proxy")

    parser.add_argument(
        "--token",
        type=int,
        required=True,
        help="SkyDNS filtering token",
    )

    args = parser.parse_args()
    token_bytes = args.token.to_bytes(4, "big")

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind((LISTEN_HOST, LISTEN_PORT))

    upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    logger.info(
        f"DNS Proxy with EDNS0 OPT 0xFFF0 running on {LISTEN_HOST}:{LISTEN_PORT}"
    )
    logger.info("Press Ctrl+C to stop...")

    while True:
        try:
            data, client_addr = server_sock.recvfrom(4096)
            request = DNSRecord.parse(data)

            qname = str(request.q.qname)
            qtype = QTYPE.get(request.q.qtype)

            logger.info(
                f"Request from {client_addr[0]}:{client_addr[1]} / {qname} ({qtype})"
            )

            opt_record = None

            for ar in request.ar:
                if ar.rtype == QTYPE.OPT:
                    opt_record = ar
                    break

            if opt_record:
                opts = opt_record.rdata
                if not isinstance(opts, list):
                    opts = []

                # update or insert token option
                for option in opts:
                    if option.code == EDNS_TOKEN_OPTION_CODE:
                        option.data = token_bytes
                        break
                else:
                    opts.append(
                        EDNSOption(EDNS_TOKEN_OPTION_CODE, token_bytes)
                    )

                opt_record.rdata = opts

            else:
                opt_record = RR(
                    rname=".",
                    rtype=QTYPE.OPT,
                    rclass=4096,
                    ttl=0,
                    rdata=[EDNSOption(EDNS_TOKEN_OPTION_CODE, token_bytes)],
                )

            request.add_ar(opt_record)

            modified_packet = request.pack()

            upstream_sock.sendto(
                modified_packet,
                (UPSTREAM_HOST, UPSTREAM_PORT),
            )

            response_data, _ = upstream_sock.recvfrom(4096)
            response = DNSRecord.parse(response_data)

            for ar in response.ar:
                if ar.rtype != QTYPE.OPT:
                    continue

                for option in ar.rdata:
                    if option.code == EDNS_CATEGORIES_OPTION_CODE:
                        logger.info(
                            f"EDNS categories (65000): {list(option.data)!r}"
                        )

            answer_types = [QTYPE.get(rr.rtype) for rr in response.rr]
            answer_types_str = ", ".join(answer_types) or "EMPTY"

            logger.info(
                f"Reply to {client_addr[0]}:{client_addr[1]} "
                f"/ {qname} ({qtype}) "
                f"RRs: {answer_types_str}"
            )

            server_sock.sendto(response_data, client_addr)

        except KeyboardInterrupt:
            logger.info("Stopping DNS proxy...")
            break

        except Exception:
            logger.exception("Unhandled error in DNS loop")


if __name__ == "__main__":
    main()