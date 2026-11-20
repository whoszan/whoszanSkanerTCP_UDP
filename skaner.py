#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
portscan - сканер TCP и UDP портов (Linux, требуются права root / CAP_NET_RAW).

    portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...

TCP: SYN-сканирование. IP- и TCP-заголовки формируются вручную, на каждый
     SYN-ACK отправляется RST, поэтому полуоткрытых соединений не остаётся.
UDP: отправка датаграммы + приём ICMP "port unreachable" через raw-сокет.
     Порт считается открытым, если пришёл ответ либо ICMP-ошибка не пришла.
Параллелизм: неблокирующие сокеты + selectors (epoll/poll/select),
     при -j > 1 порты делятся между потоками, каждый со своим циклом событий.

Запуск:  sudo python3 skaner.py [OPTIONS] IP_ADDRESS tcp/80 udp/50-60,100
"""

import argparse
import errno
import ipaddress
import os
import random
import re
import selectors
import socket
import struct
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor

PROG = "portscan"

TCP_WINDOW = 1024     # максимум одновременно ожидающих ответа TCP-проб
UDP_WINDOW = 256      # то же для UDP
SEND_BATCH = 64       # сколько пакетов отправлять между опросами сокетов
ATTEMPTS = 2          # число отправок пробы в пределах одного таймаута

FLAG_RST = 0x04
FLAG_SYN = 0x02
FLAG_ACK = 0x10


# --------------------------------------------------------------------------
# Разбор аргументов
# --------------------------------------------------------------------------

PORT_RE = re.compile(r"^(\d+)(?:-(\d+))?$")


def parse_ports(text, parser):
    """Разбирает 'PORT|PORT-PORT,...' в множество портов."""
    result = set()
    for part in text.split(","):
        m = PORT_RE.match(part.strip())
        if not m:
            parser.error("некорректное описание портов: '%s'" % part)
        lo = int(m.group(1))
        hi = int(m.group(2)) if m.group(2) is not None else lo
        if lo < 1 or hi > 65535 or lo > hi:
            parser.error("некорректный диапазон портов: '%s'" % part)
        result.update(range(lo, hi + 1))
    return result


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog=PROG,
        usage="%(prog)s [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...",
        description="Сканер TCP (SYN) и UDP портов.",
    )
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="таймаут ожидания ответа, с (по умолчанию 2)")
    parser.add_argument("-j", "--num-threads", dest="threads", type=int, default=1,
                        help="число потоков")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="подробный режим (время ответа)")
    parser.add_argument("-g", "--guess", action="store_true",
                        help="определение протокола прикладного уровня")
    parser.add_argument("ip", metavar="IP_ADDRESS", help="IPv4-адрес цели")
    parser.add_argument("specs", metavar="{tcp|udp}[/PORTS]", nargs="*",
                        help="протокол и порты, например tcp/80 udp/50-60,100")
    args = parser.parse_intermixed_args(argv)

    if args.timeout <= 0 or args.timeout != args.timeout:
        parser.error("--timeout должен быть положительным числом")
    if args.threads < 1:
        parser.error("число потоков должно быть не меньше 1")

    try:
        addr = ipaddress.ip_address(args.ip)
    except ValueError:
        parser.error("некорректный IP-адрес: '%s'" % args.ip)
    if addr.version != 4:
        parser.error("поддерживаются только IPv4-адреса")
    args.ip = str(addr)

    order = []                       # порядок протоколов по первому упоминанию
    ports = {"tcp": set(), "udp": set()}
    for spec in args.specs:
        proto, slash, rest = spec.partition("/")
        proto = proto.lower()
        if proto not in ports:
            parser.error("неизвестный протокол: '%s'" % spec)
        if proto not in order:
            order.append(proto)
        if not slash or rest == "":
            ports[proto].update(range(1, 65536))
        else:
            ports[proto].update(parse_ports(rest, parser))
    args.order = order
    args.ports = {p: sorted(v) for p, v in ports.items()}
    return args


# --------------------------------------------------------------------------
# Ручное формирование пакетов
# --------------------------------------------------------------------------

def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def build_tcp(src, dst, sport, dport, seq, ack, flags, options=b"", window=64240):
    offset = ((20 + len(options)) // 4) << 4
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, offset, flags,
                      window, 0, 0) + options
    pseudo = src + dst + struct.pack("!BBH", 0, socket.IPPROTO_TCP, len(hdr))
    ck = checksum(pseudo + hdr)
    return hdr[:16] + struct.pack("!H", ck) + hdr[18:]


def build_ip(src, dst, payload, proto=socket.IPPROTO_TCP):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                      random.getrandbits(16), 0x4000, 64, proto, 0, src, dst)
    ck = checksum(hdr)
    hdr = hdr[:10] + struct.pack("!H", ck) + hdr[12:]
    return hdr + payload


MSS_OPTION = struct.pack("!BBH", 2, 4, 1460)


def local_ip_for(target):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target, 9))
        return s.getsockname()[0]
    finally:
        s.close()


# --------------------------------------------------------------------------
# TCP SYN-сканирование
# --------------------------------------------------------------------------

def make_tcp_sockets():
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except Exception:
        send_sock.close()
        raise
    try:
        recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    recv_sock.setblocking(False)
    return send_sock, recv_sock


def tcp_worker(target, src_ip, ports, sport, timeout, send_sock, recv_sock, out):
    """Цикл событий одного потока: отправка SYN, приём SYN-ACK/RST."""
    dst = socket.inet_aton(target)
    src = socket.inet_aton(src_ip)
    sel = selectors.DefaultSelector()
    sel.register(recv_sock, selectors.EVENT_READ)
    attempt_wait = timeout / ATTEMPTS

    queue = deque(ports)
    pending = {}   # порт -> [seq, время последней отправки, число отправок]

    def send_segment(dport, seq, ack, flags, options=b""):
        seg = build_tcp(src, dst, sport, dport, seq, ack, flags, options)
        send_sock.sendto(build_ip(src, dst, seg), (target, 0))

    def handle(data):
        if len(data) < 40 or data[9] != socket.IPPROTO_TCP or data[12:16] != dst:
            return
        ihl = (data[0] & 0x0F) * 4
        tcp = data[ihl:ihl + 20]
        if len(tcp) < 20:
            return
        rsport, rdport, _seq, ack, _off, flags = struct.unpack("!HHIIBB", tcp[:14])
        if rdport != sport:
            return
        st = pending.get(rsport)
        if flags & (FLAG_SYN | FLAG_ACK) == (FLAG_SYN | FLAG_ACK):
            # порт открыт: сразу сбрасываем соединение (RST), чтобы не оставлять
            # полуоткрытых подключений на цели
            try:
                send_segment(rsport, ack, 0, FLAG_RST)
            except OSError:
                pass
            if st is not None and ack == (st[0] + 1) & 0xFFFFFFFF:
                out[rsport] = (time.monotonic() - st[1]) * 1000.0
                del pending[rsport]
        elif flags & FLAG_RST:
            if st is not None and flags & FLAG_ACK and ack == (st[0] + 1) & 0xFFFFFFFF:
                del pending[rsport]

    try:
        while queue or pending:
            # --- отправка очередной порции SYN
            sent = 0
            while queue and len(pending) < TCP_WINDOW and sent < SEND_BATCH:
                port = queue.popleft()
                seq = random.getrandbits(32)
                try:
                    send_segment(port, seq, 0, FLAG_SYN, MSS_OPTION)
                except OSError as e:
                    if e.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EINTR):
                        queue.appendleft(port)
                        time.sleep(0.001)
                        break
                    sent += 1
                    continue
                pending[port] = [seq, time.monotonic(), 1]
                sent += 1

            # --- ожидание ответов
            more = bool(queue) and len(pending) < TCP_WINDOW
            if sel.select(0 if more else 0.02):
                for _ in range(4096):
                    try:
                        data = recv_sock.recv(65535)
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break
                    handle(data)

            # --- повторная отправка / истечение таймаута
            now = time.monotonic()
            for port, st in list(pending.items()):
                if now - st[1] >= attempt_wait:
                    if st[2] < ATTEMPTS:
                        try:
                            send_segment(port, st[0], 0, FLAG_SYN, MSS_OPTION)
                        except OSError:
                            pass
                        st[1] = now
                        st[2] += 1
                    else:
                        del pending[port]
    finally:
        sel.close()


def scan_tcp(target, ports, timeout, threads):
    src_ip = local_ip_for(target)
    threads = max(1, min(threads, len(ports)))
    socks = [make_tcp_sockets() for _ in range(threads)]
    base = random.randint(33000, 60000 - threads)
    outs = [dict() for _ in range(threads)]
    workers = []
    try:
        for i in range(threads):
            t = threading.Thread(
                target=tcp_worker,
                args=(target, src_ip, ports[i::threads], base + i, timeout,
                      socks[i][0], socks[i][1], outs[i]),
                daemon=True)
            t.start()
            workers.append(t)
        for t in workers:
            while t.is_alive():
                t.join(0.2)
    finally:
        for s, r in socks:
            s.close()
            r.close()
    result = {}
    for o in outs:
        result.update(o)
    return result    # порт -> время ответа, мс


# --------------------------------------------------------------------------
# UDP-сканирование
# --------------------------------------------------------------------------

def dns_query(qid):
    return (qid + struct.pack("!HHHHH", 0x0100, 1, 0, 0, 0)
            + b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1))


def is_dns_response(data, qid):
    return len(data) >= 12 and data[:2] == qid and bool(data[2] & 0x80)


def make_udp_sockets():
    icmp = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except Exception:
        icmp.close()
        raise
    udp.bind(("", 0))
    udp.setblocking(False)
    icmp.setblocking(False)
    try:
        icmp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    return udp, icmp


def udp_worker(target, ports, payload, timeout, udp, icmp, out):
    dst = socket.inet_aton(target)
    lport = udp.getsockname()[1]
    sel = selectors.DefaultSelector()
    sel.register(udp, selectors.EVENT_READ, "udp")
    sel.register(icmp, selectors.EVENT_READ, "icmp")
    attempt_wait = timeout / ATTEMPTS

    queue = deque(ports)
    pending = {}   # порт -> [время последней отправки, число отправок]

    def send_probe(port):
        udp.sendto(payload, (target, port))

    def handle_icmp(d):
        if len(d) < 28:
            return
        ihl = (d[0] & 0x0F) * 4
        if len(d) < ihl + 8 + 20 or d[ihl] != 3:       # Destination Unreachable
            return
        inner = d[ihl + 8:]
        iihl = (inner[0] & 0x0F) * 4
        if inner[9] != socket.IPPROTO_UDP or inner[16:20] != dst or len(inner) < iihl + 4:
            return
        isport, idport = struct.unpack("!HH", inner[iihl:iihl + 4])
        if isport == lport:
            pending.pop(idport, None)

    try:
        while queue or pending:
            sent = 0
            while queue and len(pending) < UDP_WINDOW and sent < SEND_BATCH:
                port = queue.popleft()
                try:
                    send_probe(port)
                except OSError as e:
                    if e.errno in (errno.ENOBUFS, errno.EAGAIN, errno.EINTR):
                        queue.appendleft(port)
                        time.sleep(0.001)
                        break
                    sent += 1
                    continue
                pending[port] = [time.monotonic(), 1]
                sent += 1

            more = bool(queue) and len(pending) < UDP_WINDOW
            for key, _ in sel.select(0 if more else 0.02):
                for _ in range(4096):
                    try:
                        if key.data == "udp":
                            data, addr = udp.recvfrom(65535)
                            if addr[0] == target and addr[1] in pending:
                                out[addr[1]] = data
                                del pending[addr[1]]
                        else:
                            handle_icmp(icmp.recv(65535))
                    except (BlockingIOError, InterruptedError):
                        break
                    except OSError:
                        break

            now = time.monotonic()
            for port, st in list(pending.items()):
                if now - st[0] >= attempt_wait:
                    if st[1] < ATTEMPTS:
                        try:
                            send_probe(port)
                        except OSError:
                            pass
                        st[0] = now
                        st[1] += 1
                    else:
                        # ни ответа, ни ICMP "unreachable" - open|filtered
                        out.setdefault(port, None)
                        del pending[port]
    finally:
        sel.close()


def scan_udp(target, ports, payload, timeout, threads):
    threads = max(1, min(threads, len(ports)))
    socks = [make_udp_sockets() for _ in range(threads)]
    outs = [dict() for _ in range(threads)]
    workers = []
    try:
        for i in range(threads):
            t = threading.Thread(
                target=udp_worker,
                args=(target, ports[i::threads], payload, timeout,
                      socks[i][0], socks[i][1], outs[i]),
                daemon=True)
            t.start()
            workers.append(t)
        for t in workers:
            while t.is_alive():
                t.join(0.2)
    finally:
        for u, i in socks:
            u.close()
            i.close()
    result = {}
    for o in outs:
        result.update(o)
    return result    # порт -> ответ (bytes) или None


# --------------------------------------------------------------------------
# Определение протокола прикладного уровня
# --------------------------------------------------------------------------

def tcp_exchange(ip, port, data, timeout, min_len=1):
    """Обычное соединение: отправить data и прочитать ответ."""
    s = None
    try:
        s = socket.create_connection((ip, port), timeout)
        s.sendall(data)
        deadline = time.monotonic() + timeout
        buf = b""
        while len(buf) < min_len:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            s.settimeout(left)
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf
    except OSError:
        return b""
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def guess_tcp(ip, port, timeout):
    req = (b"GET / HTTP/1.1\r\nHost: " + ip.encode()
           + b"\r\nUser-Agent: portscan\r\nAccept: */*\r\nConnection: close\r\n\r\n")
    resp = tcp_exchange(ip, port, req, timeout, 5)
    if resp:
        if resp.startswith(b"HTTP/"):
            return "HTTP"
        if resp[:len(req)] == req[:len(resp)]:
            return "ECHO"

    qid = os.urandom(2)
    query = dns_query(qid)
    resp = tcp_exchange(ip, port, struct.pack("!H", len(query)) + query, timeout, 14)
    if len(resp) >= 14 and resp[2:4] == qid and resp[4] & 0x80:
        return "DNS"
    return "-"


def guess_udp(response, qid, payload):
    if not response:
        return "-"
    if response == payload:
        return "ECHO"
    if is_dns_response(response, qid):
        return "DNS"
    if response.startswith(b"HTTP/"):
        return "HTTP"
    return "-"


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    target = args.ip
    rows = []   # (протокол, порт, время или None, протокол приклад. уровня)

    try:
        for proto in args.order:
            ports = args.ports[proto]
            if not ports:
                continue
            if proto == "tcp":
                found = scan_tcp(target, ports, args.timeout, args.threads)
                guesses = {}
                if args.guess and found:
                    with ThreadPoolExecutor(max_workers=max(args.threads, 4)) as ex:
                        futs = {p: ex.submit(guess_tcp, target, p, args.timeout)
                                for p in found}
                        guesses = {p: f.result() for p, f in futs.items()}
                for p in sorted(found):
                    rows.append(("TCP", p, found[p], guesses.get(p, "-")))
            else:
                qid = os.urandom(2)
                payload = dns_query(qid)
                found = scan_udp(target, ports, payload, args.timeout, args.threads)
                for p in sorted(found):
                    g = guess_udp(found[p], qid, payload) if args.guess else "-"
                    rows.append(("UDP", p, None, g))
    except PermissionError:
        sys.stderr.write("%s: для работы с raw-сокетами нужны права root\n" % PROG)
        return 1
    except OSError as e:
        sys.stderr.write("%s: ошибка: %s\n" % (PROG, e))
        return 1
    except KeyboardInterrupt:
        return 130

    out = []
    for proto, port, ms, guess in rows:
        cols = [proto, str(port)]
        if args.verbose:
            cols.append("%d" % round(ms) if ms is not None else "-")
        if args.guess:
            cols.append(guess)
        out.append(" ".join(cols))
    if out:
        sys.stdout.write("\n".join(out) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
