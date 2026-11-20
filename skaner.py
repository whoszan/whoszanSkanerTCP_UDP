#!/usr/bin/env python3
import argparse
from concurrent.futures import ThreadPoolExecutor
import random
import select
import socket
import struct
import sys
import time

# Полезные нагрузки (payloads) для определения протоколов (-g)
ECHO_PAYLOAD = b"PORTSCAN_ECHO_TEST_42\r\n"
DNS_TID = b"\x13\x37"
# Стандартный DNS-запрос (A-запись для example.com)
DNS_QUERY = (
    DNS_TID
    + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    + b"\x07example\x03com\x00\x00\x01\x00\x01"
)


def calculate_checksum(data: bytes) -> int:
    """Вычисление контрольной суммы RFC 1071 (для TCP заголовка)."""
    if len(data) % 2 != 0:
        data += b"\x00"
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return ~checksum & 0xFFFF


def get_local_ip(target_ip: str) -> str:
    """Определяет локальный IP-адрес интерфейса, через который идет маршрут к цели."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect((target_ip, 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"


def build_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack_seq: int,
    flags: int,
) -> bytes:
    """Ручная сборка TCP-заголовка с вычислением контрольной суммы."""
    data_offset = 5 << 4  # 5 слов по 32 бита = 20 байт (без опций)
    window = socket.htons(5840)
    checksum = 0
    urg_ptr = 0

    # Собираем заголовок с нулевой контрольной суммой
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        data_offset,
        flags,
        window,
        checksum,
        urg_ptr,
    )

    # Псевдозаголовок IPv4 для расчета контрольной суммы TCP
    src_ip_bytes = socket.inet_aton(src_ip)
    dst_ip_bytes = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    pseudo_header = struct.pack(
        "!4s4sBBH",
        src_ip_bytes,
        dst_ip_bytes,
        placeholder,
        protocol,
        tcp_length,
    )

    checksum = calculate_checksum(pseudo_header + tcp_header)

    # Пересобираем заголовок с правильной контрольной суммой
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        seq,
        ack_seq,
        data_offset,
        flags,
        window,
        checksum,
        urg_ptr,
    )
    return tcp_header


def scan_tcp_syn(
    local_ip: str, target_ip: str, port: int, timeout: float
) -> tuple[bool, int]:
    """TCP SYN сканирование (полуоткрытое).

    Возвращает (is_open, rtt_ms).
    """
    src_port = random.randint(32768, 60999)
    seq = random.randint(1000, 1000000)

    # Флаг SYN = 0x02
    syn_packet = build_tcp_packet(
        local_ip, target_ip, src_port, port, seq, 0, 0x02
    )

    with socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
    ) as sock:
        start_time = time.perf_counter()
        sock.sendto(syn_packet, (target_ip, port))

        while True:
            elapsed = time.perf_counter() - start_time
            remaining = timeout - elapsed
            if remaining <= 0:
                return False, 0

            ready, _, _ = select.select([sock], [], [], remaining)
            if not ready:
                return False, 0

            packet, addr = sock.recvfrom(1024)
            if addr[0] != target_ip:
                continue

            # Длина IP-заголовка (IHL) находится в младших 4 битах первого байта
            ip_header_len = (packet[0] & 0x0F) * 4
            if len(packet) < ip_header_len + 20:
                continue

            tcp_header = packet[ip_header_len : ip_header_len + 20]
            r_src_port, r_dst_port, r_seq, r_ack, _, r_flags, _, _, _ = (
                struct.unpack("!HHIIBBHHH", tcp_header)
            )

            # Проверяем, что пакет адресован именно нашему потоку и от нужного порта
            if r_src_port == port and r_dst_port == src_port:
                rtt_ms = int(round((time.perf_counter() - start_time) * 1000))

                # Если пришли флаги SYN (0x02) + ACK (0x10) = 0x12 -> Порт ОТКРЫТ
                if (r_flags & 0x12) == 0x12:
                    # Отправляем RST (0x04), чтобы закрыть полуоткрытое соединение!
                    rst_packet = build_tcp_packet(
                        local_ip, target_ip, src_port, port, r_ack, 0, 0x04
                    )
                    sock.sendto(rst_packet, (target_ip, port))
                    return True, rtt_ms

                # Если пришел флаг RST (0x04) -> Порт ЗАКРЫТ
                if (r_flags & 0x04) != 0:
                    return False, 0


def guess_tcp_protocol(target_ip: str, port: int, timeout: float) -> str:
    """Определение протокола прикладного уровня поверх TCP (ECHO, HTTP, DNS)."""
    # 1. Проверка на ECHO
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(ECHO_PAYLOAD)
            resp = s.recv(1024)
            if resp == ECHO_PAYLOAD:
                return "ECHO"
    except Exception:
        pass

    # 2. Проверка на HTTP
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            http_req = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\nConnection: close\r\n\r\n".encode()
            s.sendall(http_req)
            resp = s.recv(1024)
            if resp.startswith(b"HTTP/"):
                return "HTTP"
    except Exception:
        pass

    # 3. Проверка на DNS (поверх TCP перед запросом идет 2 байта длины)
    try:
        with socket.create_connection((target_ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            tcp_dns_req = struct.pack("!H", len(DNS_QUERY)) + DNS_QUERY
            s.sendall(tcp_dns_req)
            resp = s.recv(1024)
            # Проверяем Transaction ID и бит ответа QR (0x80)
            if (
                len(resp) >= 14
                and resp[2:4] == DNS_TID
                and (resp[4] & 0x80) != 0
            ):
                return "DNS"
    except Exception:
        pass

    return "-"


def check_udp_response_protocol(resp: bytes) -> str:
    """Анализирует ответный UDP-пакет на принадлежность к ECHO, DNS или HTTP."""
    if resp == ECHO_PAYLOAD:
        return "ECHO"
    if len(resp) >= 12 and resp[0:2] == DNS_TID and (resp[2] & 0x80) != 0:
        return "DNS"
    if resp.startswith(b"HTTP/"):
        return "HTTP"
    return "-"


def scan_udp(
    target_ip: str, port: int, timeout: float, guess: bool
) -> tuple[bool, str]:
    """UDP сканирование с перехватом ICMP Port Unreachable и угадыванием протокола.

    Возвращает (is_open, protocol).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock, (
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    ) as icmp_sock:

        udp_sock.bind(("", 0))
        src_port = udp_sock.getsockname()[1]

        # Формируем список пакетов для отправки
        http_req = f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n".encode()
        probes = [DNS_QUERY, ECHO_PAYLOAD, http_req] if guess else [DNS_QUERY]

        start_time = time.perf_counter()
        for probe in probes:
            udp_sock.sendto(probe, (target_ip, port))

        while True:
            elapsed = time.perf_counter() - start_time
            remaining = timeout - elapsed
            if remaining <= 0:
                # За время таймаута ICMP-ошибка "Порт недоступен" НЕ пришла -> порт открыт (или отфильтрован)
                return True, "-"

            ready, _, _ = select.select(
                [udp_sock, icmp_sock], [], [], remaining
            )
            if not ready:
                return True, "-"

            # Если пришел прямой UDP-ответ, порт точно ОТКРЫТ
            if udp_sock in ready:
                try:
                    data, addr = udp_sock.recvfrom(2048)
                    if addr[0] == target_ip and addr[1] == port:
                        proto = (
                            check_udp_response_protocol(data) if guess else "-"
                        )
                        return True, proto
                except Exception:
                    return False, "-"

            # Если пришел ICMP-пакет, проверяем не Destination/Port Unreachable ли это
            if icmp_sock in ready:
                packet, addr = icmp_sock.recvfrom(2048)
                if addr[0] != target_ip:
                    continue

                ip_hdr_len = (packet[0] & 0x0F) * 4
                icmp_packet = packet[ip_hdr_len:]
                if len(icmp_packet) < 8:
                    continue

                icmp_type, icmp_code = struct.unpack("!BB", icmp_packet[:2])
                # Type 3 (Destination Unreachable), Code 3 (Port Unreachable)
                if icmp_type == 3 and icmp_code == 3:
                    # Внутри ICMP-пакета лежит IP-заголовок и первые 8 байт нашего исходного UDP-пакета
                    orig_ip_pkt = icmp_packet[8:]
                    if len(orig_ip_pkt) < 20:
                        continue
                    orig_ip_hdr_len = (orig_ip_pkt[0] & 0x0F) * 4
                    orig_udp_hdr = orig_ip_pkt[
                        orig_ip_hdr_len : orig_ip_hdr_len + 8
                    ]
                    if len(orig_udp_hdr) >= 4:
                        orig_src_p, orig_dst_p = struct.unpack(
                            "!HH", orig_udp_hdr[:4]
                        )
                        if orig_src_p == src_port and orig_dst_p == port:
                            return False, "-"


def parse_target_specs(specs: list[str]) -> list[tuple[str, int]]:
    """Парсит аргументы вида: tcp/80, tcp/12000-12500, udp/3000-3100,3200, tcp."""
    tasks = []
    seen = set()

    for spec in specs:
        if "/" in spec:
            proto_part, ports_part = spec.split("/", 1)
        else:
            proto_part, ports_part = spec, "1-65535"

        proto = proto_part.upper()
        if proto not in ("TCP", "UDP"):
            raise ValueError(f"Неизвестный протокол: {proto_part}")

        if not ports_part:
            raise ValueError(f"Пустой список портов в: {spec}")

        for item in ports_part.split(","):
            if "-" in item:
                start_s, end_s = item.split("-", 1)
                start_p, end_p = int(start_s), int(end_s)
                if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535):
                    raise ValueError(f"Порт вне диапазона 1-65535: {item}")
                if start_p > end_p:
                    raise ValueError(f"Неверный диапазон портов: {item}")
                for p in range(start_p, end_p + 1):
                    if (proto, p) not in seen:
                        seen.add((proto, p))
                        tasks.append((proto, p))
            else:
                p = int(item)
                if not (1 <= p <= 65535):
                    raise ValueError(f"Порт вне диапазона 1-65535: {p}")
                if (proto, p) not in seen:
                    seen.add((proto, p))
                    tasks.append((proto, p))

    return tasks


def process_task(
    task: tuple[str, int],
    local_ip: str,
    target_ip: str,
    timeout: float,
    verbose: bool,
    guess: bool,
) -> str | None:
    """Обрабатывает один порт и возвращает отформатированную строку вывода (если открыт)."""
    proto, port = task

    if proto == "TCP":
        is_open, rtt_ms = scan_tcp_syn(local_ip, target_ip, port, timeout)
        if not is_open:
            return None
        app_proto = (
            guess_tcp_protocol(target_ip, port, timeout) if guess else ""
        )

        parts = ["TCP", str(port)]
        if verbose:
            parts.append(str(rtt_ms))
        if guess:
            parts.append(app_proto)
        return " ".join(parts)

    else:  # UDP
        is_open, app_proto = scan_udp(target_ip, port, timeout, guess)
        if not is_open:
            return None

        parts = ["UDP", str(port)]
        # Для UDP время ответа в режиме -v не выводится по условию задачи
        if guess:
            parts.append(app_proto)
        return " ".join(parts)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="Сканер TCP и UDP портов",
        usage=(
            "portscan [OPTIONS] IP_ADDRESS"
            " [{tcp|udp}[/[PORT|PORT-PORT],...]]..."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="таймаут ожидания ответа (по умолчанию 2с)",
    )
    parser.add_argument(
        "-j",
        "--num-threads",
        type=int,
        default=10,
        help="число потоков (по умолчанию 10)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="подробный режим"
    )
    parser.add_argument(
        "-g",
        "--guess",
        action="store_true",
        help="определение протокола прикладного уровня",
    )
    parser.add_argument("ip_address", metavar="IP_ADDRESS", help="целевой IP")
    parser.add_argument(
        "targets", nargs="+", help="список протоколов и диапазонов портов"
    )
    return parser


def main():
    parser = build_arg_parser()
    try:
        args = parser.parse_args()
        if args.timeout <= 0 or args.num_threads <= 0:
            raise ValueError("timeout и num-threads должны быть больше 0")
        target_ip = socket.gethostbyname(args.ip_address)
        tasks = parse_target_specs(args.targets)
    except Exception as e:
        sys.stderr.write(f"Ошибка параметров запуска: {e}\n")
        sys.exit(2)

    local_ip = get_local_ip(target_ip)

    try:
        with ThreadPoolExecutor(max_workers=args.num_threads) as executor:
            futures = [
                executor.submit(
                    process_task,
                    task,
                    local_ip,
                    target_ip,
                    args.timeout,
                    args.verbose,
                    args.guess,
                )
                for task in tasks
            ]
            for future in futures:
                result = future.result()
                if result is not None:
                    print(result)
    except PermissionError:
        sys.stderr.write(
            "Ошибка: Для работы сокетов (RAW SOCKETS) требуются права"
            " суперпользователя (запустите через sudo).\n"
        )
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()