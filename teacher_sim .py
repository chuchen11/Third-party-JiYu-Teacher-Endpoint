#!/usr/bin/env python3
"""极域V6.0教师端 - 逐字节匹配真实抓包，带调试日志。

运行后会弹出两个窗口：
- 主窗口：显示命令提示符 teacher>，用于输入操作命令。
- 日志窗口：PowerShell 实时 tail teacher_sim.log。
"""
import socket, struct, threading, time, random, sys, os, uuid, colorsys, ipaddress
import logging, logging.handlers
from PIL import Image, ImageOps
import io
import subprocess

LOG_DIR = os.path.join(os.path.expanduser('~'), 'Desktop')
LOG_PATH = os.path.join(LOG_DIR, 'teacher_sim.log')

# 默认文件日志级别：INFO 已足够，DEBUG 太占空间。
# 运行中可用 debug on/off 切换。
FILE_LOG_LEVEL = logging.INFO


def get_file_handler():
    """返回当前的文件日志 handler（不存在返回 None）。"""
    for h in logging.getLogger().handlers:
        if isinstance(h, logging.handlers.RotatingFileHandler):
            return h
    return None


def set_file_log_level(level):
    """切换文件日志级别并持久化到全局变量。"""
    global FILE_LOG_LEVEL
    FILE_LOG_LEVEL = level
    fh = get_file_handler()
    if fh:
        fh.setLevel(level)


def clear_old_logs():
    """启动时清理上一次的日志文件，避免累积过大。"""
    for path in [LOG_PATH] + [f'{LOG_PATH}.{i}' for i in range(1, 4)]:
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError as e:
            # 如果删不掉（比如被其他进程占用），至少不要阻止程序启动
            print(f'[警告] 删除旧日志 {path} 失败：{e}', file=sys.stderr)


def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # 允许 DEBUG 通过，由 handler 决定是否写入
    if logger.handlers:
        logger.handlers.clear()

    clear_old_logs()

    fh = logging.handlers.RotatingFileHandler(
        LOG_PATH, maxBytes=10*1024*1024, backupCount=3, encoding='utf-8'
    )
    fh.setLevel(FILE_LOG_LEVEL)
    fmt = logging.Formatter(
        '%(asctime)s.%(msecs)03d [%(levelname)-8s] [%(threadName)-12s] %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    # 日志由独立窗口实时显示，主窗口只保留命令交互，所以不再输出到 stdout。
    # 如需在控制台也看日志，可取消下面注释。
    # ch = logging.StreamHandler(sys.stdout)
    # ch.setLevel(logging.INFO)
    # ch.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    # logger.addHandler(ch)

    logger.info('日志系统初始化完成，级别=%s，log 文件：%s',
                logging.getLevelName(FILE_LOG_LEVEL), LOG_PATH)
    return logger


def spawn_log_window():
    """在独立的命令行窗口中实时跟踪日志文件。"""
    # 确保日志文件已存在，避免 PowerShell Get-Content 报错。
    if not os.path.exists(LOG_PATH):
        open(LOG_PATH, 'a', encoding='utf-8').close()

    # 强制 PowerShell 控制台使用 UTF-8，避免中文日志乱码。
    ps_cmd = (
        f'chcp 65001 | Out-Null; '
        f'[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; '
        f'Get-Content -Path "{LOG_PATH}" -Wait -Tail 50 -Encoding UTF8'
    )
    try:
        subprocess.Popen(
            ['start', 'powershell', '-NoExit', '-Command', ps_cmd],
            shell=True,
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        print('[启动] 已打开实时日志窗口（PowerShell 跟踪 log，UTF-8）')
    except Exception as e:
        print(f'[启动] 打开日志窗口失败：{e}')


logger = setup_logging()

MCAST, PORT = '224.50.50.42', 4705
SESSION_MCAST_PREFIX = '225.2'
SESSION_BASE_PORT = 5000
SESSION_PORT_STRIDE = 0x200
TGUID = uuid.UUID('{F96A6D19-5B29-46B9-AB95-8A143ECDDC26}')

oonc_seq = 0
cmd_seq = 0

MAGIC_NAMES = {
    0x434E4F4F: 'OONC',
    0x434E414E: 'NANC',
    0x434E4143: 'CANC',
    0x41434157: 'WACA',
    0x544E5253: 'SRNT',
    0x434F4D44: 'DMOC',
    0x544E504C: 'LPNT',
    0x4143414B: 'KACA',
    0x434D5254: 'TRMC',
    0x544E5254: 'TRNT',
    0x544E4544: 'DENT',
    0x544E414C: 'LANT',
    0x4F4E4E41: 'ANNO',
    0x49474F4C: 'LOGI',
    0x5353454D: 'MESS',
}

# 日常广播类魔数，不必逐条记录 hexdump
ROUTINE_MAGICS = {0x434E4F4F, 0x434E414E, 0x434E4143, 0x4F4E4E41}

students = {}
previews = {}   # sip -> 当前正在重组的 LANT 帧
completed_preview_frames = {}  # sip -> 最近完整接收的帧序号
preview_policy_versions = {}   # sip -> 最近发送的 LPNT policy version
remote_views = {}  # sip -> RemoteViewSession
remote_controls = {}  # sip -> {'port': int, 'sock': socket.socket}
remote_view_failures = {}  # sip -> 最近失败时间；避免反复触发学生端编码器
remote_state_lock = threading.RLock()
last_status = {}  # (sip, key) -> 最近一条同类消息内容（重复降为 DEBUG，防止刷屏）
running = True
SELECTED_NETWORK = None


def hexdump(data, width=16):
    if data is None:
        return '<None>'
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f'{i:04x}  {hex_part:<{width*3}} {ascii_part}')
    return '\n'.join(lines)


def magic_name(mag):
    return MAGIC_NAMES.get(mag, f'UNKNOWN(0x{mag:08X})')


def is_interesting(d, sip):
    """判断是否值得记录的数据包：非本机、非日常广播、或未知类型。"""
    if sip == ip:
        return False
    if len(d) < 4:
        return True
    mag = struct.unpack('<I', d[:4])[0]
    return mag not in ROUTINE_MAGICS


def get_ip():
    global SELECTED_NETWORK
    SELECTED_NETWORK = None
    override = os.environ.get('TEACHER_IP', '').strip()
    peer_hint = os.environ.get('TEACHER_PEER_IP', '').strip()
    network_hint = os.environ.get('TEACHER_NETWORK', '').strip()
    benchmark_net = ipaddress.ip_network('198.18.0.0/15')

    def usable(value):
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return (addr.version == 4
                and not addr.is_loopback
                and not addr.is_link_local
                and not addr.is_multicast
                and not addr.is_unspecified
                and addr not in benchmark_net)

    peer_address = None
    if peer_hint:
        try:
            peer_address = ipaddress.ip_address(peer_hint)
            if (peer_address.version != 4 or peer_address.is_unspecified
                    or peer_address.is_multicast):
                raise ValueError('必须是普通 IPv4 地址')
        except Exception as e:
            raise ValueError(f'TEACHER_PEER_IP 不是有效 IPv4 地址：{peer_hint}（{e}）') from e

    wanted_network = None
    if network_hint:
        try:
            wanted_network = ipaddress.ip_network(network_hint, strict=False)
            if wanted_network.version != 4:
                raise ValueError('必须是 IPv4 网段')
        except ValueError as e:
            raise ValueError(f'TEACHER_NETWORK 不是有效 IPv4 网段：{network_hint}') from e

    if override:
        if not usable(override):
            raise ValueError(f'TEACHER_IP 不是可用的 IPv4 地址：{override}')
        override_address = ipaddress.ip_address(override)
        if wanted_network and override_address not in wanted_network:
            raise ValueError(
                f'TEACHER_IP={override} 不属于 TEACHER_NETWORK={wanted_network}'
            )
        SELECTED_NETWORK = wanted_network
        logger.info('使用 TEACHER_IP 指定地址：%s', override)
        return override

    # 官方逻辑枚举所有本机 IPv4，并不会按网卡名称排除虚拟接口。这里同样
    # 保留全部可用地址；可通过 TEACHER_NETWORK 选择所需网段。
    if os.name == 'nt':
        ps_script = (
            "$ErrorActionPreference='Stop'; "
            "foreach($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) { "
            "if($nic.OperationalStatus -ne [System.Net.NetworkInformation.OperationalStatus]::Up) { continue }; "
            "$props=$nic.GetIPProperties(); $gateway=$false; "
            "foreach($gw in $props.GatewayAddresses) { "
            "if($gw.Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { "
            "$gateway=$true; break } }; "
            "foreach($addr in $props.UnicastAddresses) { "
            "if($addr.Address.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { continue }; "
            "\"{0}`t{1}`t{2}`t{3}\" -f "
            "$addr.Address.IPAddressToString,$nic.Name,$gateway,$addr.PrefixLength } }"
        )
        try:
            completed = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_script],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=8,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            candidates = []
            for line in completed.stdout.splitlines():
                parts = line.strip().split('\t')
                if len(parts) != 4 or not usable(parts[0]):
                    continue
                candidate, alias, has_gateway, prefix_text = parts
                addr = ipaddress.ip_address(candidate)
                prefix = int(prefix_text)
                candidate_network = ipaddress.ip_network(
                    f'{candidate}/{prefix}', strict=False)
                if wanted_network and addr not in wanted_network:
                    continue
                gateway = has_gateway.lower() == 'true'
                score = 100 if gateway else 0
                score += 20 if addr.is_private else 0
                if peer_address is not None and peer_address in candidate_network:
                    score += 1000
                # 在同分情况下保留 PowerShell 的枚举顺序，避免地址字符串排序
                # 意外改变选择结果。
                candidates.append((score, candidate, alias, candidate_network, gateway))
            if candidates:
                logger.info('可用 IPv4 候选：%s', '; '.join(
                    f'{candidate}/{network.prefixlen}（{alias}，默认网关={gateway}）'
                    for score, candidate, alias, network, gateway in candidates))
                selected_item = max(enumerate(candidates),
                                    key=lambda item: (item[1][0], -item[0]))[1]
                _, selected, alias, selected_network, _ = selected_item
                SELECTED_NETWORK = selected_network
                if peer_address and peer_address in selected_network:
                    logger.info('按 TEACHER_PEER_IP=%s 的直连网段选择地址：%s（%s，网段=%s）',
                                peer_hint, selected, alias, selected_network)
                else:
                    logger.info('自动选择局域网地址：%s（%s，网段=%s）',
                                selected, alias, selected_network)
                    if peer_address:
                        logger.warning(
                            'TEACHER_PEER_IP=%s 不在所选直连网段 %s；组播发现通常不会跨越路由器',
                            peer_hint, selected_network)
                return selected
            if wanted_network:
                raise RuntimeError(f'没有找到属于 TEACHER_NETWORK={wanted_network} 的本机地址')
        except Exception as e:
            if wanted_network:
                raise
            logger.warning('枚举 Windows 网卡失败，将使用路由探测：%s', e)

    # UDP connect 只查询本机路由，不会真正向目标发送数据。优先探测
    # 指定同端，其次探测本程序使用的组播路由；外网地址只作最后尝试。
    # 这样在只有局域网、没有默认网关时也能正常启动。
    route_targets = []
    if peer_hint:
        route_targets.append((peer_hint, PORT, 'TEACHER_PEER_IP'))
    route_targets.extend([
        (MCAST, PORT, '组播'),
        ('8.8.8.8', 80, '默认路由'),
    ])
    route_errors = []
    for route_target, route_port, route_name in route_targets:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((route_target, route_port))
            selected = s.getsockname()[0]
            if not usable(selected):
                raise RuntimeError(f'得到不可用地址 {selected}')
            if wanted_network and ipaddress.ip_address(selected) not in wanted_network:
                raise RuntimeError(
                    f'地址 {selected} 不属于 TEACHER_NETWORK={wanted_network}'
                )
            SELECTED_NETWORK = wanted_network
            logger.info('通过%s路由选择地址：%s', route_name, selected)
            return selected
        except OSError as e:
            route_errors.append(f'{route_name} {route_target}: {e}')
            logger.warning('%s路由探测失败：%s', route_name, e)
        except RuntimeError as e:
            route_errors.append(f'{route_name} {route_target}: {e}')
            logger.warning('%s路由探测忽略：%s', route_name, e)
        finally:
            s.close()

    # 极端情况下 Windows 网卡枚举和路由查询都可能失败，再从
    # 主机名解析结果中选一个可用局域网地址。
    hostname_candidates = []
    try:
        for info in socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET, socket.SOCK_DGRAM):
            candidate = info[4][0]
            if candidate not in hostname_candidates and usable(candidate):
                hostname_candidates.append(candidate)
    except OSError as e:
        logger.warning('主机名 IPv4 解析失败：%s', e)

    if wanted_network:
        hostname_candidates = [
            candidate for candidate in hostname_candidates
            if ipaddress.ip_address(candidate) in wanted_network
        ]
    if hostname_candidates:
        selected = hostname_candidates[0]
        SELECTED_NETWORK = wanted_network
        logger.info('通过主机名解析选择局域网地址：%s（候选=%s）',
                    selected, ', '.join(hostname_candidates))
        return selected

    detail = '; '.join(route_errors) or '未找到可用 IPv4 地址'
    raise RuntimeError(
        f'无法自动选择本机局域网 IP（{detail}）。'
        '请设置 TEACHER_IP，例如：'
        'set TEACHER_IP=192.168.52.132'
    )


ip = get_ip()


def get_channel_id():
    raw = os.environ.get('TEACHER_CHANNEL', '1').strip()
    try:
        channel = int(raw, 0)
    except ValueError as e:
        raise ValueError(f'TEACHER_CHANNEL 不是有效整数：{raw}') from e
    if not 1 <= channel <= 32:
        raise ValueError('TEACHER_CHANNEL 必须在 1 到 32 之间')
    return channel


CHANNEL_ID = get_channel_id()


def get_env_int(name, default, minimum=0, maximum=0xFFFF):
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw, 0)
    except ValueError as e:
        raise ValueError(f'{name} 不是有效整数：{raw}') from e
    if not minimum <= value <= maximum:
        raise ValueError(f'{name} 必须在 {minimum} 到 {maximum} 之间')
    return value


# V6 的连续桌面观看走 TCP/UMSP；4806 是原版默认通信端口。
TCP_COMM_MODE = get_env_int('TEACHER_TCP_MODE', 1, 0, 1)
TCP_COMM_PORT = get_env_int('TEACHER_TCP_PORT', 4806, 1, 0xFFFF)
# 远控接收端口位于学生机上。0 表示每次从动态端口段随机选择，避免和
# 学生端自身服务或上一次异常退出残留的接收线程争用固定端口。
CONTROL_PORT = get_env_int('TEACHER_CONTROL_PORT', 0, 0, 0xFFFF)
# 官方协议：0=Share（双方可操作），1=Monitor，2=Control Student（额外锁定学生输入）。
# 官方 control 分支会先初始化输入 Hook；默认使用 mode=2，确保键盘模拟路径已初始化。
# 如需保留学生端本地输入，可显式设置 TEACHER_CONTROL_MODE=0。
CONTROL_MODE = get_env_int('TEACHER_CONTROL_MODE', 2, 0, 2)
REMOTE_CONTROL_ENABLED = os.environ.get('TEACHER_ENABLE_REMOTE_CONTROL', '1').strip() != '0'
VIEW_START_DELAY = get_env_int('TEACHER_VIEW_START_DELAY_MS', 0, 0, 10000) / 1000.0
VIEW_FAILURE_COOLDOWN = get_env_int('TEACHER_VIEW_COOLDOWN', 60, 5, 3600)
REMOTE_VIEW_DIR = os.path.join(LOG_DIR, 'teacher_remote_view')


def get_session_endpoint(channel):
    """按教师端公式计算频道对应的会话组播地址和 UDP 端口。"""
    return (f'{SESSION_MCAST_PREFIX}.{channel + 1}.1',
            SESSION_BASE_PORT + channel * SESSION_PORT_STRIDE)


SMCAST, SPORT = get_session_endpoint(CHANNEL_ID)
VIEW_LOCAL_PORT = get_env_int('TEACHER_VIEW_LOCAL_PORT', SPORT, 1, 0xFFFF)
VIEW_PEER_PORT = get_env_int('TEACHER_VIEW_PEER_PORT', SPORT, 1, 0xFFFF)
DIRECT_PEER_IP = os.environ.get('TEACHER_PEER_IP', '').strip() or None

def build_announce_targets(group, port):
    """同时生成组播、本网段广播和可选定向发现目标。"""
    targets = []

    def add(host):
        host_text = str(host)
        target = (host_text, port)
        if host_text != ip and target not in targets:
            targets.append(target)

    add(group)

    # VMware NAT 和仅主机网络都是独立二层网段。组播被虚拟交换
    # 机过滤时，子网广播仍能到达同一 VMnet 的宿主机或其他虚拟机。
    if (SELECTED_NETWORK is not None
            and SELECTED_NETWORK.prefixlen <= 30
            and ipaddress.ip_address(ip).is_private):
        add(SELECTED_NETWORK.broadcast_address)

        # VMware 默认把 VMnet 宿主虚拟网卡放在网段第一个可用
        # 地址。单播补发可覆盖宿主端防火墙放行单播但限制组播/广播的情况。
        host_candidate = SELECTED_NETWORK.network_address + 1
        add(host_candidate)

    if DIRECT_PEER_IP:
        add(DIRECT_PEER_IP)
    return targets


MAIN_ANNOUNCE_TARGETS = build_announce_targets(MCAST, PORT)
SESSION_ANNOUNCE_TARGETS = build_announce_targets(SMCAST, SPORT)

sock = socket.socket(2, 2)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock.bind(('', PORT))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                struct.pack('4s4s', socket.inet_aton(MCAST), socket.inet_aton(ip)))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
logger.info('主 socket 就绪：%s:%d', MCAST, PORT)

sock2 = socket.socket(2, 2)
sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock2.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
sock2.bind(('', SPORT))
sock2.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                 struct.pack('4s4s', socket.inet_aton(SMCAST), socket.inet_aton(ip)))
sock2.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
sock2.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
logger.info('会话 socket 就绪：%s:%d', SMCAST, SPORT)

logger.info('Teacher %s channel=%d started on %s:%d + %s:%d',
            ip, CHANNEL_ID, MCAST, PORT, SMCAST, SPORT)
logger.info('发现宣告已启用：NANC（普通频道）+ CANC（自动连接）')
logger.info('主发现目标：%s', ', '.join(
    f'{host}:{port}' for host, port in MAIN_ANNOUNCE_TARGETS))
logger.info('会话发现目标：%s', ', '.join(
    f'{host}:{port}' for host, port in SESSION_ANNOUNCE_TARGETS))
if SELECTED_NETWORK is None:
    logger.warning('未获取到所选网卡的子网掩码，未启用自动子网广播；'
                   '可设置 TEACHER_NETWORK，例如 192.168.52.0/24')


def send_to_targets(out_sock, packet, targets, label):
    """向一组宣告目标发送同一数据包，单个目标失败不影响其他目标。"""
    failures = []
    sent = 0
    for target in targets:
        try:
            out_sock.sendto(packet, target)
            sent += 1
        except OSError as e:
            failures.append(f'{target[0]}:{target[1]}（{e}）')
    if failures:
        logger.warning('[%s] 部分目标发送失败：%s', label, '; '.join(failures))
    if not sent:
        raise OSError(f'{label} 的全部发送目标均失败')
    return sent


def oonc():
    global oonc_seq
    pkt = (struct.pack('<II', 0x434E4F4F, 0x10000)
           + struct.pack('<I', 16)
           + TGUID.bytes_le
           + socket.inet_aton(ip)
           + struct.pack('<III', 1, 1, oonc_seq))
    oonc_seq += 1
    return pkt


def get_teacher_name_field():
    name = os.environ.get('TEACHER_NAME', '1')[:31] or '1'
    nw = (name + '\x00').encode('utf-16-le')
    name_chars = len(nw) // 2 - 1
    return nw, name_chars


def nanc():
    """构造普通频道选择模式使用的教师宣告。"""
    nw, name_chars = get_teacher_name_field()
    af = (name_chars << 17) | CHANNEL_ID
    body = struct.pack('<I', af) + socket.inet_aton(ip) + nw
    declared_length = 11 + name_chars * 2
    body += b'\x00' * (declared_length - len(body))
    return (struct.pack('<III', 0x434E414E, 0x10000, len(body))
            + TGUID.bytes_le
            + body)


def canc():
    """构造自动连接模式使用的教师宣告。"""
    nw, name_chars = get_teacher_name_field()
    af = (name_chars << 17) | CHANNEL_ID
    channel_mask = 1 << (CHANNEL_ID - 1)
    body = (struct.pack('<I', af)
            + socket.inet_aton(ip)
            + struct.pack('<II', channel_mask, 1)
            + nw)
    if len(body) > 84:
        raise ValueError('TEACHER_NAME 编码后超过 CANC 负载上限')
    body += b'\x00' * (84 - len(body))
    return (struct.pack('<III', 0x434E4143, 0x10000, len(body))
            + TGUID.bytes_le
            + body)


def waca(sip):
    return (struct.pack('<III', 0x41434157, 0x10000, 8)
            + TGUID.bytes_le
            + socket.inet_aton(ip)
            + struct.pack('<I', CHANNEL_ID))


def request_preview(sip):
    """通过一次 LPNT 关/开切换，立即请求新的预览帧。"""
    version = preview_policy_versions.get(sip, 3)
    stop_version = version + 1
    start_version = version + 2
    preview_policy_versions[sip] = start_version
    try:
        sock.sendto(build_lpnt(stop_version, False), (sip, PORT))
        time.sleep(0.05)
        sock.sendto(build_lpnt(start_version, True), (sip, PORT))
        logger.info('[Preview] LPNT restart -> %s, versions=%d/%d',
                    sip, stop_version, start_version)
    except Exception as e:
        logger.error('[Preview] LPNT restart 发送给 %s 失败：%s', sip, e, exc_info=True)


def build_mess_packet(sip, payload):
    """构造单接收者 MESS；recipient IP 使用协议中的原始网络序字节。"""
    socket.inet_aton(sip)
    return (struct.pack('<III', 0x5353454D, 1, 1)
            + socket.inet_aton(sip)
            + payload)


def build_command_transaction(payload):
    """构造 CCommandTransaction 使用的 COMD 外层。"""
    if len(payload) > 0x800:
        raise ValueError('CCommandTransaction payload 不能超过 2048 字节')
    packet = (struct.pack('<III', 0x434F4D44, 0x10000,
                          len(payload) + 13)
              + uuid.uuid4().bytes_le
              + struct.pack('<I', 20000)
              + socket.inet_aton(ip)
              + struct.pack('<I', len(payload))
              + payload
              + b'\x00')
    if len(packet) != len(payload) + 41:
        raise AssertionError('COMD 命令事务长度错误')
    return packet


def build_remote_view_payload(sip):
    """构造远程观看 feature 8 的 617 字节内部负载。"""
    params = bytearray(604)
    struct.pack_into('<I', params, 0, 0)  # RemoteWithVoice
    params[4:8] = socket.inet_aton(ip)
    # 这里是教师会话/桌面监控端点，不是学生端的 TCP 服务端口 4806。
    struct.pack_into('<H', params, 8, VIEW_LOCAL_PORT)
    params[10:14] = socket.inet_aton(ip)
    struct.pack_into('<H', params, 14, VIEW_PEER_PORT)
    struct.pack_into('<IIIIIIII', params, 36,
                     1,      # NetworkType
                     1,      # ShowMonitorControlMessage
                     20480,  # MaxSendSpeed
                     1,      # RepairMode
                     1440,   # MaxPacketSize
                     25,     # FrameLimit
                     75,     # CaptureQuality
                     1)      # TcpCommMode
    params[68:72] = socket.inet_aton(sip)
    struct.pack_into('<III', params, 72, 5, 12, 16)
    payload = struct.pack('<III', 617, 8, 0x80000000) + params + b'\x00'
    if len(payload) != 617:
        raise AssertionError(f'feature 8 长度错误：{len(payload)}')
    return payload


def build_remote_view_stop_payload():
    return struct.pack('<III', 13, 0, 0) + b'\x00'


def send_remote_view_feature(sip, enabled=True):
    payload = (build_remote_view_payload(sip) if enabled
               else build_remote_view_stop_payload())
    packet = build_mess_packet(sip, payload)
    sock2.sendto(packet, (sip, SPORT))
    logger.info('[RemoteView] feature %s -> %s:%d, payload=%d, mess=%d',
                'start' if enabled else 'stop', sip, SPORT,
                len(payload), len(packet))


class RemoteViewSession:
    """V6 TCP/UMSP channel 10 接收器及 libTDDesk2 桌面帧重组器。"""

    UMSP_VERSION = 0x10000
    UMSP_SELECT_MAGIC = 0x4F434853  # wire: SHCO
    UMSP_DATA_MAGIC = 0x43504B54    # wire: TKPC (代码常量名 TCPK)
    DESK_CHANNEL = 10
    MAX_FRAME_SIZE = 0x241800

    def __init__(self, sip, port):
        self.sip = sip
        self.port = port
        self.stop_event = threading.Event()
        self.connected_event = threading.Event()
        self.conn = None
        self.thread = None
        self.fragments = {}
        self.frame_count = 0
        self.control_record_count = 0
        self.remote_cursor = None
        self.remote_cursor_version = 0
        self.local_cursor = None
        self.local_cursor_version = 0
        self.last_local_cursor_at = 0.0
        self.last_cursor_log = 0.0
        self.player = None
        self.player_format = None
        self.player_kind = None
        self.player_size = None
        self.viewer_thread = None
        self.player_unavailable = False
        self.interactive_requested = False
        self.dump_stream = os.environ.get('TEACHER_VIEW_DUMP', '0').strip() == '1'
        self.base_name = sip.replace('.', '_')
        self.session_tag = time.strftime('%Y%m%d-%H%M%S')

    def start(self):
        self.thread = threading.Thread(
            target=self.run, name=f'view-{self.base_name}', daemon=True
        )
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        conn = self.conn
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass
        self._stop_player()

    def enable_interactive_player(self):
        """立即退出纯播放窗口，下一帧改用带输入绑定的内嵌窗口。"""
        self.interactive_requested = True
        if self.player_kind in ('ffplay', 'opencv-h264'):
            self._stop_player()

    def _connect(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(2.5)
        try:
            conn.bind((ip, 0))
            conn.connect((self.sip, self.port))
            hello = struct.pack('<IIIII', self.UMSP_VERSION,
                                self.UMSP_SELECT_MAGIC, 8, 1,
                                self.DESK_CHANNEL)
            conn.sendall(hello)
            conn.settimeout(1.0)
            self.conn = conn
            self.connected_event.set()
            with remote_state_lock:
                remote_view_failures.pop(self.sip, None)
            logger.info('[RemoteView] TCP 已连接 %s:%d，SHCO channel=%d',
                        self.sip, self.port, self.DESK_CHANNEL)
            return conn
        except OSError:
            conn.close()
            raise

    def run(self):
        try:
            # 立即订阅 channel 10，避免错过编码器最初的 SPS/PPS/IDR。
            if self.stop_event.wait(VIEW_START_DELAY):
                return
            conn = self._connect()
            stream = bytearray()
            while running and not self.stop_event.is_set():
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    continue
                if not chunk:
                    raise ConnectionError('学生端关闭 TCP 连接')
                stream.extend(chunk)
                while len(stream) >= 12:
                    version, magic, payload_len = struct.unpack_from('<III', stream)
                    if payload_len > self.MAX_FRAME_SIZE + 0x10000:
                        raise ValueError(f'UMSP payload 过大：{payload_len}')
                    packet_len = 12 + payload_len
                    if len(stream) < packet_len:
                        break
                    payload = bytes(stream[12:packet_len])
                    del stream[:packet_len]
                    if version != self.UMSP_VERSION:
                        logger.warning('[RemoteView] UMSP version=%#x（预期 %#x）',
                                       version, self.UMSP_VERSION)
                    if magic != self.UMSP_DATA_MAGIC:
                        logger.debug('[RemoteView] 忽略 UMSP magic=%#x len=%d',
                                     magic, payload_len)
                        continue
                    if len(payload) < 4:
                        logger.warning('[RemoteView] TCPK payload 过短：%d', len(payload))
                        continue
                    channel = struct.unpack_from('<I', payload)[0]
                    if channel == self.DESK_CHANNEL:
                        self._handle_fragment(payload[4:])
                    else:
                        logger.debug('[RemoteView] 忽略 channel=%d len=%d',
                                     channel, len(payload) - 4)
        except Exception as e:
            if not self.stop_event.is_set():
                with remote_state_lock:
                    remote_view_failures[self.sip] = time.monotonic()
                logger.error('[RemoteView] %s 接收结束：%s', self.sip, e,
                             exc_info=True)
                print(f'[观看] {self.sip} 接收失败：{e}')
                print(f'[观看] 已停止请求；{VIEW_FAILURE_COOLDOWN} 秒内不会再次启动，避免学生端反复闪退')
                try:
                    send_remote_view_feature(self.sip, False)
                except OSError as stop_error:
                    logger.warning('[RemoteView] 向 %s 发送失败清理包失败：%s',
                                   self.sip, stop_error)
        finally:
            self.stop()
            with remote_state_lock:
                if remote_views.get(self.sip) is self:
                    remote_views.pop(self.sip, None)
            logger.info('[RemoteView] %s 会话退出，共完成 %d 帧',
                        self.sip, self.frame_count)

    def _handle_fragment(self, data):
        if len(data) < 12:
            logger.warning('[RemoteView] 桌面分片过短：%d', len(data))
            return
        frame_seq, offset, total = struct.unpack_from('<III', data)
        fragment = data[12:]
        if not 1 <= total <= self.MAX_FRAME_SIZE:
            logger.warning('[RemoteView] 非法桌面帧大小：seq=%d total=%d',
                           frame_seq, total)
            return
        if offset > total or len(fragment) > total - offset:
            logger.warning('[RemoteView] 非法分片：seq=%d off=%d len=%d total=%d',
                           frame_seq, offset, len(fragment), total)
            return
        state = self.fragments.get(frame_seq)
        if state is None or state['total'] != total:
            state = {
                'total': total,
                'data': bytearray(total),
                'seen': bytearray(total),
                'received': 0,
            }
            self.fragments[frame_seq] = state
            if len(self.fragments) > 4:
                oldest = next(iter(self.fragments))
                if oldest != frame_seq:
                    self.fragments.pop(oldest, None)
        end = offset + len(fragment)
        new_bytes = len(fragment) - sum(state['seen'][offset:end])
        state['data'][offset:end] = fragment
        state['seen'][offset:end] = b'\x01' * len(fragment)
        state['received'] += new_bytes
        if state['received'] == total:
            record = bytes(state['data'])
            self.fragments.pop(frame_seq, None)
            self._handle_record(frame_seq, record)

    def _handle_record(self, frame_seq, record):
        if len(record) < 64:
            self.control_record_count += 1
            if len(record) >= 16 and record[:4] == b'SPUC':
                record_size, timestamp, packed_position = struct.unpack_from(
                    '<III', record, 4
                )
                cursor = (packed_position & 0xFFFF,
                          (packed_position >> 16) & 0xFFFF)
                if record_size == 16 and cursor != self.remote_cursor:
                    self.remote_cursor = cursor
                    self.remote_cursor_version += 1
                    with remote_state_lock:
                        control_active = self.sip in remote_controls
                    now = time.monotonic()
                    if control_active and now - self.last_cursor_log >= 0.1:
                        self.last_cursor_log = now
                        logger.info('[RemoteControl] 学生端光标 -> %s (%d,%d) ts=%d',
                                    self.sip, cursor[0], cursor[1], timestamp)
            if self.control_record_count == 1 or self.control_record_count % 100 == 0:
                logger.info('[RemoteView] 控制记录 count=%d seq=%d len=%d data=%s',
                            self.control_record_count, frame_seq, len(record),
                            record.hex(' '))
            return
        magic, declared_size, timestamp = struct.unpack_from('<III', record)
        encoded_rect = struct.unpack_from('<iiii', record, 12)
        visible_rect = struct.unpack_from('<iiii', record, 28)
        frame_type = struct.unpack_from('<I', record, 44)[0]
        payload = record[64:]
        width = abs(encoded_rect[2] - encoded_rect[0])
        height = abs(encoded_rect[3] - encoded_rect[1])
        visible_width = abs(visible_rect[2] - visible_rect[0])
        visible_height = abs(visible_rect[3] - visible_rect[1])
        if not width or not height:
            width = visible_width
            height = visible_height
        if not 0 < visible_width <= width:
            visible_width = width
        if not 0 < visible_height <= height:
            visible_height = height
        self.frame_count += 1
        os.makedirs(REMOTE_VIEW_DIR, exist_ok=True)

        if magic == 0x46524848:  # wire HHRF, H.264 Annex-B
            self._write_player('h264', payload, width, height,
                               visible_width, visible_height)
            if self.dump_stream or self.player_unavailable:
                path = os.path.join(REMOTE_VIEW_DIR,
                                    f'remote_{self.base_name}_{self.session_tag}.h264')
                with open(path, 'ab') as f:
                    f.write(payload)
            codec = 'H264'
        elif magic == 0x46524A48:  # wire HJRF, JPEG
            soi = payload.find(b'\xff\xd8')
            jpeg = payload[soi:] if soi >= 0 else payload
            path = os.path.join(REMOTE_VIEW_DIR,
                                f'remote_{self.base_name}_latest.jpg')
            with open(path, 'wb') as f:
                f.write(jpeg)
            self._write_player('mjpeg', jpeg, width, height,
                               visible_width, visible_height)
            codec = 'JPEG'
        elif magic == 0x46524D48:  # wire HMRF, legacy
            path = os.path.join(REMOTE_VIEW_DIR,
                                f'remote_{self.base_name}_latest.hmrf')
            with open(path, 'wb') as f:
                f.write(record)
            codec = 'HMRF'
        else:
            logger.warning('[RemoteView] 未知桌面记录 magic=%#x seq=%d len=%d',
                           magic, frame_seq, len(record))
            return

        if self.frame_count == 1 or self.frame_count % 100 == 0:
            logger.info('[RemoteView] %s %s frame=%d seq=%d type=%d '
                        'record=%d declared=%d ts=%d encoded=%s visible=%s',
                        self.sip, codec, self.frame_count, frame_seq, frame_type,
                        len(record), declared_size, timestamp,
                        encoded_rect, visible_rect)

    def _write_player(self, fmt, data, width, height,
                      visible_width=None, visible_height=None):
        if not data or self.player_unavailable:
            return
        output_width = visible_width or width
        output_height = visible_height or height
        wanted_size = (output_width, output_height)
        video_filter = ('shuffleplanes=0:2:1:3,'
                        f'crop={output_width}:{output_height}:0:0')
        if (self.player is None or self.player_format != fmt
                or (self.player_kind == 'opencv-h264'
                    and self.player_size != wanted_size)
                or (self.player_kind == 'pillow-h264'
                    and self.player_size != wanted_size)):
            self._stop_player()
            # H.264 从首帧开始固定使用内嵌窗口。观看切换到控制时复用同一个
            # 解码器，避免在码流中途重启而错过 SPS/PPS/IDR 后永久黑屏。
            if not self._start_opencv_player(
                    fmt, width, height, output_width, output_height,
                    interactive=(fmt == 'h264')):
                self.player_unavailable = True
                logger.warning('[RemoteView] 实时播放器不可用；帧保存在 %s',
                               REMOTE_VIEW_DIR)
                return
        if self.player_kind == 'opencv-jpeg':
            try:
                import cv2
                import numpy as np
                frame = cv2.imdecode(np.frombuffer(data, dtype=np.uint8),
                                     cv2.IMREAD_COLOR)
                if frame is not None:
                    cv2.imshow(f'学生屏幕 {self.sip}', frame)
                    cv2.waitKey(1)
            except Exception as e:
                logger.warning('[RemoteView] OpenCV JPEG 显示失败：%s', e)
                self.player_unavailable = True
            return
        try:
            self.player.stdin.write(data)
            self.player.stdin.flush()
        except (BrokenPipeError, OSError, AttributeError):
            logger.warning('[RemoteView] 视频解码器管道已关闭，停止播放器重启')
            self.player_unavailable = True
            self._stop_player()

    def _start_opencv_player(self, fmt, width, height,
                             output_width=None, output_height=None,
                             interactive=False):
        try:
            output_width = output_width or width
            output_height = output_height or height
            if fmt == 'mjpeg':
                import cv2  # noqa: F401
                self.player = 'opencv-jpeg'
                self.player_format = fmt
                self.player_kind = 'opencv-jpeg'
                self.player_size = (output_width, output_height)
                logger.info('[RemoteView] 使用 OpenCV 显示 JPEG：%s', self.sip)
                return True
            if width <= 0 or height <= 0:
                raise ValueError(f'无效画面尺寸 {width}x{height}')
            import imageio_ffmpeg
            ffmpeg = imageio_ffmpeg.get_ffmpeg_exe()
            try:
                if interactive:
                    raise ImportError('远控模式使用内嵌窗口')
                import cv2  # noqa: F401
                pixel_format = 'bgr24'
                player_kind = 'opencv-h264'
                reader = self._opencv_h264_reader
                display_name = 'OpenCV'
            except ImportError:
                import tkinter  # noqa: F401
                from PIL import ImageTk  # noqa: F401
                pixel_format = 'rgb24'
                player_kind = 'pillow-h264'
                reader = self._pillow_h264_reader
                display_name = 'Pillow/Tkinter'
            self.player = subprocess.Popen(
                [ffmpeg, '-loglevel', 'error', '-flags', 'low_delay',
                 '-threads', '1',
                 '-probesize', '32', '-analyzeduration', '0',
                 '-f', 'h264', '-i', 'pipe:0',
                 '-an', '-vf',
                 f'shuffleplanes=0:2:1:3,'
                 f'crop={output_width}:{output_height}:0:0',
                 '-f', 'rawvideo', '-pix_fmt', pixel_format, 'pipe:1'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            self.player_format = fmt
            self.player_kind = player_kind
            self.player_size = (output_width, output_height)
            player = self.player
            self.viewer_thread = threading.Thread(
                target=reader,
                args=(player, output_width, output_height),
                name=f'view-ui-{self.base_name}', daemon=True,
            )
            self.viewer_thread.start()
            threading.Thread(
                target=self._ffmpeg_stderr_reader,
                args=(player,), name=f'view-ffmpeg-{self.base_name}', daemon=True,
            ).start()
            logger.info('[RemoteView] 使用 bundled FFmpeg + %s 显示 H264：%s '
                        'encoded=%dx%d visible=%dx%d', display_name, self.sip,
                        width, height, output_width, output_height)
            return True
        except Exception as e:
            logger.warning('[RemoteView] OpenCV/FFmpeg 播放器启动失败：%s', e,
                           exc_info=True)
            self.player = None
            self.player_kind = None
            return False

    def _ffmpeg_stderr_reader(self, player):
        count = 0
        try:
            while player is self.player and player.stderr:
                raw = player.stderr.readline()
                if not raw:
                    return
                count += 1
                if count <= 20 or count % 100 == 0:
                    message = raw.decode('utf-8', errors='replace').strip()
                    if message:
                        logger.warning('[RemoteView] FFmpeg：%s', message)
        except (OSError, AttributeError):
            pass

    def _pillow_h264_reader(self, player, width, height):
        frame_size = width * height * 3
        root = None
        closed = threading.Event()
        try:
            import queue
            import tkinter as tk
            from PIL import ImageDraw, ImageTk
            frames = queue.Queue(maxsize=1)
            reader_done = threading.Event()

            def read_decoded_frames():
                try:
                    while not self.stop_event.is_set() and player is self.player:
                        chunks = bytearray()
                        while len(chunks) < frame_size:
                            chunk = player.stdout.read(frame_size - len(chunks))
                            if not chunk:
                                return
                            chunks.extend(chunk)
                        try:
                            frames.get_nowait()
                        except queue.Empty:
                            pass
                        try:
                            frames.put_nowait(bytes(chunks))
                        except queue.Full:
                            pass
                finally:
                    reader_done.set()

            root = tk.Tk()
            label = tk.Label(root, text='正在等待视频画面...', width=60,
                             height=20, borderwidth=0, highlightthickness=0,
                             padx=0, pady=0, takefocus=True,
                             bg='black', fg='white', cursor='none')
            label.pack()
            root.protocol('WM_DELETE_WINDOW', closed.set)
            last_move_time = [0.0]
            last_control_state = [None]
            displayed_image_size = [None]
            blocked_gui_keys = {0x12, 0x5B, 0x5C}  # Alt、左/右 Windows 键

            def control_active():
                with remote_state_lock:
                    return self.sip in remote_controls

            def normalized_mouse(event):
                image_size = displayed_image_size[0]
                if image_size is None:
                    image_size = (label.winfo_width(), label.winfo_height())
                image_width = max(1, image_size[0] - 1)
                image_height = max(1, image_size[1] - 1)
                x = min(max(event.x, 0), image_width)
                y = min(max(event.y, 0), image_height)
                normalized_x = round(x * 65535 / image_width)
                normalized_y = round(y * 65535 / image_height)
                source_x = round(normalized_x * max(0, width - 1) / 65535)
                source_y = round(normalized_y * max(0, height - 1) / 65535)
                return normalized_x, normalized_y, source_x, source_y

            def focus_control_window():
                try:
                    root.lift()
                    root.focus_force()
                    label.focus_set()
                except tk.TclError:
                    pass

            def mouse_event(action, event, data=0):
                if not control_active():
                    return None
                try:
                    x, y, source_x, source_y = normalized_mouse(event)
                    self.local_cursor = (source_x, source_y)
                    self.local_cursor_version += 1
                    self.last_local_cursor_at = time.monotonic()
                    send_remote_mouse(self.sip, action, x, y, data)
                    if action.endswith('down'):
                        focus_control_window()
                except Exception as e:
                    logger.warning('[RemoteControl] 窗口鼠标事件失败：%s', e)
                return 'break'

            def mouse_move(event):
                if not control_active():
                    return None
                now = time.monotonic()
                if now - last_move_time[0] < 1 / 120:
                    return 'break'
                last_move_time[0] = now
                return mouse_event('move', event)

            def mouse_wheel(event):
                return mouse_event('wheel', event, int(event.delta or 0))

            extended_keys = {
                'Left', 'Right', 'Up', 'Down', 'Home', 'End', 'Prior',
                'Next', 'Insert', 'Delete', 'Control_R', 'Alt_R',
                'KP_Enter', 'Num_Lock', 'Print', 'Cancel',
            }

            def key_event(event, key_up):
                if not control_active():
                    return None
                try:
                    virtual_key = int(event.keycode) & 0xFFFF
                    if virtual_key in blocked_gui_keys:
                        logger.info('[RemoteControl] 已拦截系统修饰键 vk=%#x',
                                    virtual_key)
                        return 'break'
                    logger.info('[RemoteControl] 窗口按键 %s keysym=%s '
                                'keycode=%#x',
                                'up' if key_up else 'down', event.keysym,
                                virtual_key)
                    send_remote_key(self.sip, virtual_key, key_up=key_up,
                                    extended=event.keysym in extended_keys)
                except Exception as e:
                    logger.warning('[RemoteControl] 窗口键盘事件失败：%s', e)
                return 'break'

            # Tk 会被 Windows 输入法吞掉部分字母键（尤其是中文输入法状态下）。
            # 远控时安装低级键盘钩子，直接使用系统提供的 VK/扫描码/按键状态。
            keyboard_hook_handle = [None]
            keyboard_hook_callback = [None]

            def install_keyboard_hook():
                if os.name != 'nt' or keyboard_hook_handle[0] is not None:
                    return
                try:
                    import ctypes
                    from ctypes import wintypes
                    user32 = ctypes.windll.user32
                    kernel32 = ctypes.windll.kernel32
                    WH_KEYBOARD_LL = 13
                    WM_KEYDOWN = 0x0100
                    WM_KEYUP = 0x0101
                    WM_SYSKEYDOWN = 0x0104
                    WM_SYSKEYUP = 0x0105
                    LLKHF_EXTENDED = 0x01
                    LLKHF_INJECTED = 0x10

                    class KBDLLHOOKSTRUCT(ctypes.Structure):
                        _fields_ = [
                            ('vkCode', wintypes.DWORD),
                            ('scanCode', wintypes.DWORD),
                            ('flags', wintypes.DWORD),
                            ('time', wintypes.DWORD),
                            ('dwExtraInfo', ctypes.c_void_p),
                        ]

                    callback_type = ctypes.WINFUNCTYPE(
                        ctypes.c_ssize_t, ctypes.c_int, wintypes.WPARAM,
                        wintypes.LPARAM)

                    def keyboard_hook_proc(code, message, lparam):
                        try:
                            if code >= 0 and control_active():
                                info = ctypes.cast(
                                    lparam, ctypes.POINTER(KBDLLHOOKSTRUCT)
                                ).contents
                                if not (info.flags & LLKHF_INJECTED):
                                    vk = int(info.vkCode) & 0xFFFF
                                    key_up = message in (WM_KEYUP, WM_SYSKEYUP)
                                    if vk in blocked_gui_keys:
                                        logger.info(
                                            '[RemoteControl] 全局钩子拦截系统键 vk=%#x',
                                            vk)
                                        return 1
                                    scan = int(info.scanCode) & 0xFFFF
                                    extended = bool(info.flags & LLKHF_EXTENDED)
                                    logger.info(
                                        '[RemoteControl] 全局按键 %s vk=%#x scan=%#x flags=%#x',
                                        'up' if key_up else 'down', vk, scan,
                                        int(info.flags))
                                    send_remote_key(
                                        self.sip, vk, key_up=key_up,
                                        scan_code=(scan or None), extended=extended)
                                    return 1
                        except Exception as e:
                            logger.warning('[RemoteControl] 全局键盘钩子失败：%s', e)
                        return user32.CallNextHookEx(
                            keyboard_hook_handle[0], code, message, lparam)

                    callback = callback_type(keyboard_hook_proc)
                    handle = user32.SetWindowsHookExW(
                        WH_KEYBOARD_LL, callback,
                        kernel32.GetModuleHandleW(None), 0)
                    if not handle:
                        raise ctypes.WinError()
                    keyboard_hook_callback[0] = callback
                    keyboard_hook_handle[0] = handle
                    logger.info('[RemoteControl] Windows 全局键盘钩子已启用')
                except Exception as e:
                    logger.warning('[RemoteControl] Windows 全局键盘钩子不可用：%s', e)

            def uninstall_keyboard_hook():
                handle = keyboard_hook_handle[0]
                if handle is None:
                    return
                try:
                    import ctypes
                    ctypes.windll.user32.UnhookWindowsHookEx(handle)
                except Exception as e:
                    logger.debug('[RemoteControl] 卸载全局键盘钩子失败：%s', e)
                finally:
                    keyboard_hook_handle[0] = None
                    keyboard_hook_callback[0] = None

            label.bind('<Motion>', mouse_move)
            label.bind('<ButtonPress-1>',
                       lambda e: mouse_event('leftdown', e))
            label.bind('<ButtonRelease-1>',
                       lambda e: mouse_event('leftup', e))
            label.bind('<ButtonPress-2>',
                       lambda e: mouse_event('middledown', e))
            label.bind('<ButtonRelease-2>',
                       lambda e: mouse_event('middleup', e))
            label.bind('<ButtonPress-3>',
                       lambda e: mouse_event('rightdown', e))
            label.bind('<ButtonRelease-3>',
                       lambda e: mouse_event('rightup', e))
            label.bind('<MouseWheel>', mouse_wheel)
            root.bind_all('<KeyPress>', lambda e: key_event(e, False))
            root.bind_all('<KeyRelease>', lambda e: key_event(e, True))
            root.update_idletasks()
            root.update()
            threading.Thread(
                target=read_decoded_frames,
                name=f'view-decode-{self.base_name}', daemon=True,
            ).start()
            waiting_since = time.monotonic()
            warned = False
            base_frame = None
            displayed_cursor_version = -1
            while (not self.stop_event.is_set() and not closed.is_set()
                   and player is self.player):
                try:
                    raw_frame = frames.get_nowait()
                except queue.Empty:
                    raw_frame = None
                if raw_frame is not None:
                    base_frame = Image.frombytes('RGB', (width, height), raw_frame)
                    waiting_since = time.monotonic()
                current_control_state = control_active()
                predicted_cursor_active = (
                    current_control_state and self.local_cursor is not None
                    and time.monotonic() - self.last_local_cursor_at < 0.18
                )
                cursor_version = (self.remote_cursor_version,
                                  self.local_cursor_version,
                                  predicted_cursor_active)
                if (base_frame is not None
                        and (raw_frame is not None
                             or cursor_version != displayed_cursor_version)):
                    frame = base_frame.copy()
                    cursor = (self.local_cursor if predicted_cursor_active
                              else self.remote_cursor)
                    if cursor is not None:
                        cursor_x = min(max(cursor[0], 0), width - 1)
                        cursor_y = min(max(cursor[1], 0), height - 1)
                        arm = max(8, min(width, height) // 60)
                        draw = ImageDraw.Draw(frame)
                        lines = [
                            (cursor_x - arm, cursor_y, cursor_x + arm, cursor_y),
                            (cursor_x, cursor_y - arm, cursor_x, cursor_y + arm),
                        ]
                        for line in lines:
                            draw.line(line, fill='black', width=5)
                            draw.line(line, fill='white', width=2)
                    screen_w = max(320, root.winfo_screenwidth() - 80)
                    screen_h = max(240, root.winfo_screenheight() - 120)
                    resampling = getattr(Image, 'Resampling', Image)
                    frame.thumbnail((screen_w, screen_h), resampling.LANCZOS)
                    displayed_image_size[0] = frame.size
                    photo = ImageTk.PhotoImage(frame)
                    label.configure(image=photo, text='', width=0, height=0)
                    label.image = photo
                    displayed_cursor_version = cursor_version
                elif (not warned and time.monotonic() - waiting_since >= 5):
                    warned = True
                    logger.warning('[RemoteView] FFmpeg 5 秒内未输出画面，窗口将继续等待；请查看随后 FFmpeg 日志')
                if current_control_state != last_control_state[0]:
                    title = ('远程控制' if current_control_state else '学生屏幕')
                    root.title(f'{title} {self.sip}')
                    if current_control_state:
                        install_keyboard_hook()
                        root.after_idle(focus_control_window)
                    else:
                        uninstall_keyboard_hook()
                    last_control_state[0] = current_control_state
                root.update_idletasks()
                root.update()
                if reader_done.is_set() and frames.empty():
                    label.configure(text='视频解码器已停止，请查看日志', image='',
                                    width=60, height=20)
                time.sleep(0.015)
        except Exception as e:
            if not self.stop_event.is_set():
                logger.warning('[RemoteView] Pillow/Tkinter 显示线程退出：%s', e)
        finally:
            try:
                uninstall_keyboard_hook()
            except UnboundLocalError:
                pass
            if closed.is_set():
                self.player_unavailable = True
                with remote_state_lock:
                    control_was_active = self.sip in remote_controls
                if control_was_active:
                    try:
                        stop_remote_control(self.sip)
                    except OSError as e:
                        logger.warning('[RemoteControl] 关闭窗口时停止远控失败：%s', e)
            if player is self.player:
                try:
                    player.terminate()
                except OSError:
                    pass
            if root is not None:
                try:
                    root.destroy()
                except Exception:
                    pass

    def _opencv_h264_reader(self, player, width, height):
        frame_size = width * height * 3
        window_name = f'学生屏幕 {self.sip}'
        try:
            import cv2
            import numpy as np
            while not self.stop_event.is_set() and player is self.player:
                chunks = bytearray()
                while len(chunks) < frame_size:
                    chunk = player.stdout.read(frame_size - len(chunks))
                    if not chunk:
                        return
                    chunks.extend(chunk)
                frame = np.frombuffer(chunks, dtype=np.uint8).reshape(
                    (height, width, 3)
                )
                cv2.imshow(window_name, frame)
                cv2.waitKey(1)
        except Exception as e:
            if not self.stop_event.is_set():
                logger.warning('[RemoteView] H264 显示线程退出：%s', e)
        finally:
            try:
                cv2.destroyWindow(window_name)
            except Exception:
                pass

    def _stop_player(self):
        player, self.player = self.player, None
        self.player_format = None
        kind, self.player_kind = self.player_kind, None
        self.player_size = None
        if player is None:
            return
        if kind == 'opencv-jpeg':
            try:
                import cv2
                cv2.destroyWindow(f'学生屏幕 {self.sip}')
            except Exception:
                pass
            return
        try:
            if player.stdin:
                player.stdin.close()
        except OSError:
            pass
        try:
            player.terminate()
        except OSError:
            pass


def probe_remote_view(sip, port=TCP_COMM_PORT, timeout=1.5):
    """仅探测学生端 TCP 服务是否监听；不发送 feature 8 或 SHCO。"""
    socket.inet_aton(sip)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(timeout)
    try:
        probe.bind((ip, 0))
        error = probe.connect_ex((sip, port))
        if error == 0:
            return True, None
        return False, f'TCP connect_ex={error}'
    except OSError as e:
        return False, str(e)
    finally:
        probe.close()


def start_remote_view(sip, port=TCP_COMM_PORT):
    if not _check_student(sip, 'view <学生IP> [TCP端口]'):
        return False
    with remote_state_lock:
        failure_time = remote_view_failures.get(sip)
        if failure_time is not None:
            remaining = VIEW_FAILURE_COOLDOWN - (time.monotonic() - failure_time)
            if remaining > 0:
                print(f'[观看] {sip} 仍在失败冷却中，请等待 {int(remaining) + 1} 秒；不要连续执行 view')
                return False
            remote_view_failures.pop(sip, None)
        if remote_views.get(sip):
            print(f'[观看] {sip} 已有观看会话；如需重启请先执行 view_stop {sip}')
            return False
    reachable, detail = probe_remote_view(sip, port)
    if not reachable:
        print(f'[观看] 未启动：{sip}:{port} 未监听（{detail}）。请先确认学生端已重新登录，再执行 view_probe')
        return False
    with remote_state_lock:
        session = RemoteViewSession(sip, port)
        remote_views[sip] = session
    try:
        send_remote_view_feature(sip, True)
    except Exception:
        with remote_state_lock:
            if remote_views.get(sip) is session:
                remote_views.pop(sip, None)
            remote_view_failures[sip] = time.monotonic()
        session.stop()
        raise
    session.start()
    return True


def stop_remote_view(sip, notify=True):
    with remote_state_lock:
        session = remote_views.pop(sip, None)
    if session:
        session.stop()
    if notify:
        send_remote_view_feature(sip, False)
    logger.info('[RemoteView] stop -> %s（本地会话=%s）', sip, bool(session))


def build_remote_control_payload(sip, mode, port):
    """构造 MCMD；mode 0/2 开始远控，mode 1 停止。"""
    payload = bytearray(53)
    struct.pack_into('<III', payload, 0, 53, 8, 0)
    payload[12:16] = b'MCMD'
    struct.pack_into('<I', payload, 16, mode)
    payload[20:24] = socket.inet_aton(sip)
    struct.pack_into('<H', payload, 24, port)
    return bytes(payload)


def choose_remote_control_port():
    """选择学生端模拟输入线程的 UDP 监听端口。"""
    if CONTROL_PORT:
        return CONTROL_PORT
    return random.SystemRandom().randint(49152, 65535)


def start_remote_control(sip, port=None):
    if not REMOTE_CONTROL_ENABLED:
        print('[远控] 已禁用；删除 TEACHER_ENABLE_REMOTE_CONTROL=0 后重启脚本即可启用')
        return False
    if not _check_student(sip, 'control <学生IP> [UDP端口]'):
        return False
    with remote_state_lock:
        session = remote_views.get(sip)
    if session is None or not session.connected_event.is_set():
        print('[远控] 未发送 MCMD：屏幕 TCP 通道尚未连接')
        return False
    if port is None:
        port = choose_remote_control_port()
    if not 1 <= port <= 0xFFFF:
        raise ValueError('远控 UDP 端口必须在 1..65535')
    # mode 0 和 2 都会在学生端调用 BeginSimulate；mode 2 还会先执行
    # 官方 control 分支的输入 Hook 初始化和本地输入锁定。
    mode = CONTROL_MODE
    if mode == 1:
        raise ValueError('TEACHER_CONTROL_MODE=1 是仅观看模式，不能用于 control')
    packet = build_command_transaction(
        build_remote_control_payload(sip, mode, port))
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.bind((ip, 0))
    with remote_state_lock:
        old = remote_controls.pop(sip, None)
        if old:
            old['sock'].close()
        remote_controls[sip] = {
            'port': port,
            'sock': sender,
            'input_count': 0,
            'ready_at': time.monotonic() + 0.35,
        }
    sock.sendto(packet, (sip, PORT))
    mode_name = 'Share' if mode == 0 else 'Control Student'
    logger.info('[RemoteControl] COMD/MCMD mode=%d (%s) -> %s:%d，输入端点=%s:%d',
                mode, mode_name, sip, PORT, sip, port)
    return port


def stop_remote_control(sip, notify=True):
    with remote_state_lock:
        state = remote_controls.pop(sip, None)
    port = state['port'] if state else (CONTROL_PORT or 0)
    if state:
        state['sock'].close()
    if notify:
        packet = build_command_transaction(
            build_remote_control_payload(sip, 1, port))
        sock.sendto(packet, (sip, PORT))
    logger.info('[RemoteControl] stop -> %s:%d', sip, port)


def send_remote_input(sip, kind, payload):
    if len(payload) != 20:
        raise ValueError('远控输入 payload 必须是 20 字节')
    with remote_state_lock:
        state = remote_controls.get(sip)
    if not state:
        print(f'[远控] {sip} 尚未 control，请先执行 control {sip}')
        return False
    startup_delay = state['ready_at'] - time.monotonic()
    if startup_delay > 0:
        time.sleep(startup_delay)
    packet = struct.pack('<II', 0x2321347C, kind) + payload
    state['sock'].sendto(packet, (sip, state['port']))
    with remote_state_lock:
        state['input_count'] += 1
        input_count = state['input_count']
    if kind == 16 or input_count <= 8 or input_count % 100 == 0:
        logger.info('[RemoteControl] input #%d kind=%d -> %s:%d data=%s',
                    input_count, kind, sip, state['port'], packet.hex(' '))
    else:
        logger.debug('[RemoteControl] input #%d kind=%d -> %s:%d\n%s',
                     input_count, kind, sip, state['port'], hexdump(packet))
    return True


MOUSE_MESSAGES = {
    'move': 0x0200,
    'leftdown': 0x0201,
    'leftup': 0x0202,
    'rightdown': 0x0204,
    'rightup': 0x0205,
    'middledown': 0x0207,
    'middleup': 0x0208,
    'wheel': 0x020A,
}


def send_remote_mouse(sip, action, x, y, data=0, swapped=0):
    action = action.lower()
    if action not in MOUSE_MESSAGES:
        raise ValueError('鼠标动作应为 ' + '/'.join(MOUSE_MESSAGES))
    if not 0 <= x <= 65535 or not 0 <= y <= 65535:
        raise ValueError('鼠标坐标必须在 0..65535')
    payload = struct.pack('<IIIII', MOUSE_MESSAGES[action], x, y,
                          data & 0xFFFFFFFF, swapped & 0xFFFFFFFF)
    sent = send_remote_input(sip, 1, payload)
    if sent and action != 'move':
        logger.info('[RemoteControl] mouse %s -> %s (%d,%d) data=%d',
                    action, sip, x, y, data)
    return sent


def send_remote_key(sip, virtual_key, key_up=False, scan_code=None,
                    extended=False):
    if not 0 <= virtual_key <= 0xFFFF:
        raise ValueError('虚拟键码必须在 0..0xFFFF')
    if scan_code is None:
        try:
            import ctypes
            scan_code = ctypes.windll.user32.MapVirtualKeyW(virtual_key, 0)
        except Exception:
            scan_code = virtual_key
    flags = (1 if extended else 0) | (0x80 if key_up else 0)
    payload = struct.pack('<HHI', scan_code & 0xFFFF,
                          virtual_key & 0xFFFF, flags) + b'\x00' * 12
    return send_remote_input(sip, 16, payload)


def send_chat(sip, text):
    """向已登录学生发送聊天消息（MESS，payload type=0x800）。"""
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    try:
        text_utf16 = text.encode('utf-16-le') + b'\x00\x00'
        # [12..15] 经测试应设为 UTF-16 码元数（含结尾空字符），否则学生端可能只显示第一个字。
        wchar_count = len(text_utf16) // 2
        payload = (struct.pack('<I', 16 + len(text_utf16))
                   + struct.pack('<I', 0x800)
                   + struct.pack('<I', 0)
                   + struct.pack('<I', wchar_count)
                   + text_utf16)
        mess = (struct.pack('<II', 0x5353454D, 1)
                + struct.pack('<I', 1)
                + socket.inet_aton(sip)
                + payload)
        sock2.sendto(mess, (sip, SPORT))
        logger.info('[命令] 发送聊天消息 -> %s: %s', sip, text)
        print(f'[命令] 聊天消息已发送给 {sip}')
    except Exception as e:
        logger.error('[命令] 发送聊天消息失败：%s', e, exc_info=True)
        print(f'[命令] 发送失败：{e}')


def request_info(sip, rtype=0):
    """请求学生上报信息（MESS，payload type=0x100000）。

    rtype（学生端 sub_445670 的分支条件）：
           0=全部（type 5 系统信息 + type 6 窗口列表 + type 7 进程列表）
           1=type 6 窗口/应用程序列表（hwnd+标题，分片）
           2=type 7 进程列表（pid+exe名，分片）
    学生端入口: sub_44CA70 [payload+4]==0x100000 → sub_445670。
    """
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    try:
        payload = (struct.pack('<I', 16)
                   + struct.pack('<I', 0x100000)
                   + struct.pack('<I', 0)
                   + struct.pack('<I', rtype))
        mess = (struct.pack('<II', 0x5353454D, 1)
                + struct.pack('<I', 1)
                + socket.inet_aton(sip)
                + payload)
        sock2.sendto(mess, (sip, SPORT))
        logger.info('[Info] 信息请求 rtype=%d -> %s:%d', rtype, sip, SPORT)
    except Exception as e:
        logger.error('[Info] 发送信息请求失败：%s', e, exc_info=True)
        print(f'[命令] 发送失败：{e}')


def send_kill(sip, pid=None, hwnd=None, force=1):
    """结束进程 / 结束应用程序（MESS，0x100000 通道，学生端 sub_445670 type 4/3）。

    pid  → type 4（按进程结束）；hwnd → type 3（按窗口结束应用程序）。
    force=1: TerminateProcess 强杀；force=0: 先给主窗口发 WM_CLOSE（温和结束）。
    学生端 fire-and-forget 无确认包；杀完重新 info 刷新列表验证结果。
    """
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    if pid is None and hwnd is None:
        print('[命令] 需要 pid 或 hwnd')
        return
    rtype = 4 if pid is not None else 3
    payload = (struct.pack('<I', 24) + struct.pack('<I', 0x100000)
               + struct.pack('<I', 0) + struct.pack('<I', rtype)
               + struct.pack('<I', hwnd or 0) + struct.pack('<I', pid or 0)
               + struct.pack('<I', force))
    mess = (struct.pack('<II', 0x5353454D, 1) + struct.pack('<I', 1)
            + socket.inet_aton(sip) + payload)
    kind = f'进程 pid={pid}' if rtype == 4 else f'应用窗口 hwnd=0x{hwnd:08X}'
    try:
        sock2.sendto(mess, (sip, SPORT))
        logger.info('[命令] 结束%s -> %s, force=%d', kind, sip, force)
        print(f'[命令] 已向 {sip} 发送结束{kind}(force={force})')
    except Exception as e:
        logger.error('[命令] 发送结束命令失败：%s', e, exc_info=True)
        print(f'[命令] 发送失败：{e}')


def send_open_url(sip, url):
    """打开网页/文件（COMD 应用命令，cmdId 0x18，sub_44A490 case 0x18）。

    学生端执行 ShellExecuteW(0, "open", url, ...)：网址走默认浏览器；
    也可以传学生机上的文件路径，按扩展名关联程序打开（.txt/.jpg 等）。
    """
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    payload = (struct.pack('<I', 0x200) + struct.pack('<I', 0)
               + struct.pack('<I', 0x18) + struct.pack('<I', 0)
               + url.encode('utf-16-le') + b'\x00\x00'
               + b'\x00' * 4)
    pkt = build_comd_command_ex(0x80000010, payload,
                                'f96a6d195b2946b9ab958a143ecddc26')
    try:
        sock.sendto(pkt, (sip, PORT))
        logger.info('[命令] 打开网页/文件 -> %s: %s', sip, url)
        print(f'[命令] 已向 {sip} 发送打开命令：{url}')
    except Exception as e:
        logger.error('[命令] 发送打开命令失败：%s', e, exc_info=True)
        print(f'[命令] 发送失败：{e}')


def send_run_program(sip, path, args='', show=0, fallback=1):
    """远程运行程序（COMD 应用命令，cmdId 0x0F，case 0x0F → sub_432CB0）。

    学生端执行 CreateProcessW("\"path\" args")（服务态用 CreateProcessAsUser）。
    path 必须是学生机上的绝对路径；show: 0=正常 1=最小化 2=最大化；
    fallback=1 时启动失败会在系统目录查找同名程序重试一次。
    """
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    body = struct.pack('<I', 0x0F) + struct.pack('<I', fallback)
    body += path.encode('utf-16-le')[:510].ljust(512, b'\x00')   # a2+8  路径 256 wchar
    body += args.encode('utf-16-le')[:318].ljust(320, b'\x00')   # a2+520 参数 160 wchar
    body += struct.pack('<I', show)                                 # a2+840 窗口模式
    payload = (struct.pack('<I', 0x200) + struct.pack('<I', 0)
               + body + b'\x00' * 4)
    pkt = build_comd_command_ex(0x80000010, payload,
                                'f96a6d195b2946b9ab958a143ecddc26')
    try:
        sock.sendto(pkt, (sip, PORT))
        logger.info('[命令] 远程运行 -> %s: "%s" %s (show=%d)', sip, path, args, show)
        print(f'[命令] 已向 {sip} 发送运行命令："{path}" {args}')
    except Exception as e:
        logger.error('[命令] 发送运行命令失败：%s', e, exc_info=True)
        print(f'[命令] 发送失败：{e}')


def _parse_id_name_pairs(buf):
    """解析 {u32 id, wchar name\0} 序列（type 6 窗口列表 / type 7 进程列表的条目）。

    学生端条目格式（sub_445670）：id(4) + name(UTF-16LE) + \\x00\\x00，
    每条 6 + 2*len(name) 字节。返回 [(id, name), ...]，容错截断。
    """
    entries = []
    pos, end = 0, len(buf)
    while pos + 6 <= end:
        rid = struct.unpack('<I', buf[pos:pos + 4])[0]
        chars = bytearray()
        p = pos + 4
        while p + 2 <= end and buf[p:p + 2] != b'\x00\x00':
            chars += buf[p:p + 2]
            p += 2
        name = bytes(chars).decode('utf-16-le', errors='ignore')
        entries.append((rid, name))
        pos = p + 2
    return entries


def _parse_student_info(payload, sip):
    """解析 type 5 学生信息结构体（自 payload 起，含 12 字节消息头）。

    布局（学生端 sub_445670 填充，均为 UTF-16LE 定长字段）：
      +0x0C  DWORD 5            +0x10  计算机名[32]   +0x50  学生ID u32
      +0x54  MAC[6]             +0x5A  登录用户[32]   +0x9A  OS名称[32]
      +0xDA  OS版本[64]         +0x21A CPU厂商[32]   +0x25A CPU型号[64]
      +0x2DA 内存 "xxxx MB"[16]
    """
    def wstr(off, maxlen):
        raw = payload[off:off + maxlen * 2]
        return raw.decode('utf-16-le', errors='ignore').split('\x00')[0]

    info = {
        'name': wstr(0x10, 32),
        'stu_id': struct.unpack('<I', payload[0x50:0x54])[0],
        'mac': '-'.join(f'{b:02X}' for b in payload[0x54:0x5A]),
        'user': wstr(0x5A, 32),
        'os': wstr(0x9A, 32),
        'osver': wstr(0xDA, 64),
        'cpu_vendor': wstr(0x21A, 32),
        'cpu_model': wstr(0x25A, 64),
        'mem': wstr(0x2DA, 16),
    }
    if sip in students:
        students[sip]['info'] = info
    return info


def build_comd_command(cmd_code, payload):
    """构造 COMD 命令包（Magic=0x434F4D44，即代码中的 DMOC）。"""
    global cmd_seq
    cmd_id = cmd_seq
    cmd_seq += 1
    inner = (struct.pack('<I', cmd_code)
             + struct.pack('<I', cmd_id)
             + struct.pack('<I', len(payload))
             + struct.pack('<I', 0)      # reserved
             + payload)
    return (struct.pack('<II', 0x434F4D44, 0x10000)
            + struct.pack('<I', len(inner))
            + bytes.fromhex('ce90fd383df5844c857fa35183c051f3')
            + inner)


def build_comd_command_ex(cmd_code, payload, guid_hex, extra_header=b''):
    """构造 COMD 命令包，可自定义 GUID 与 GUID 后的额外头。"""
    global cmd_seq
    cmd_id = cmd_seq
    cmd_seq += 1
    inner = (struct.pack('<I', cmd_code)
             + struct.pack('<I', cmd_id)
             + struct.pack('<I', len(payload))
             + struct.pack('<I', 0)
             + payload)
    return (struct.pack('<II', 0x434F4D44, 0x10000)
            + struct.pack('<I', len(extra_header) + len(inner))
            + bytes.fromhex(guid_hex)
            + extra_header
            + inner)


def build_blackscreen_mess_payload(lock_input=True, timeout=10, text=None, text_color=0x0000FFFF):
    """构造黑屏安静命令的 MESS payload。

    逐字节匹配真实抓包（教师端 sub_54C4E0，MESS type=0x20）。

    抓包验证结构（教师到当前频道对应的会话组播端点）：
      [0..3]  = 总长度 (基础 39 字节 + 可选文本)
      [4..7]  = 0x20 (黑屏)
      [8..11] = 0x80000000 (启动标志)
      [12..15]= lock_input (1=锁定键鼠)
      [16..19]= 0x01 (禁用学生端本地定时器，由教师端负责超时解锁)
      [20..23]= timeout (超时秒数, 0=永久；供协议字段保持一致)
      [24..27]= has_text (0/1)
      [28..31]= text_color (Windows COLORREF: 0x00BBGGRR)
      [32..35]= 0x00000000 (field_5)
      [36..38]= 0xA00520 (padding, 仅 has_text=0 时)
      [36..]  = UTF-16LE 文本 (has_text=1 时)

    text_color 默认值 0x0000FFFF = 黄色 (R=255,G=255,B=0)，匹配真实教师端。
    要白色用 0x00FFFFFF，红色用 0x000000FF。
    """
    has_text = 1 if text else 0
    text_utf16 = b''
    if has_text:
        text_utf16 = (text.encode('utf-16-le') + b'\x00\x00') if text else b''

    total_len = 39 + len(text_utf16)  # 基础 39 字节

    payload = struct.pack('<I', total_len)               # [0] 总长
    payload += struct.pack('<I', 0x20)                    # [4] 黑屏
    payload += struct.pack('<I', 0x80000000)              # [8] 启动标志
    payload += struct.pack('<I', 1 if lock_input else 0)  # [12] 锁定输入
    payload += struct.pack('<I', 1)                       # [16] 不启用学生端本地定时器
    payload += struct.pack('<I', timeout)                 # [20] 超时
    payload += struct.pack('<I', has_text)                # [24] 有自定义文字
    payload += struct.pack('<I', text_color)              # [28] 文字颜色 (0x00BBGGRR)
    payload += struct.pack('<I', 0)                       # [32] field_5
    if has_text:
        payload += text_utf16                             # [36+] UTF-16LE 文本
    else:
        payload += b'\xa0\x05\x20'                        # [36..38] padding (来自真实抓包)
    return payload


# 跟踪各学生的自动解锁定时器，方便手动解锁时取消
blackscreen_timers = {}   # sip -> threading.Timer


def _send_comd_blackscreen_lock(sip, timeout=10):
    """补发 COMD case 6 黑屏锁定命令，兼容只处理该路径的学生端。

    学生端反编译确认：case 6 的 lock_input=0 仅表示“不新加锁”，并
    不是解锁命令。这里因此只发送 lock_input=1。timer_flag=1 禁用
    学生端本地定时器，统一由 blackscreen_timers 负责超时解锁，避免
    永久黑屏被 COMD 中固定的 10 秒定时器提前解除。
    """
    payload = struct.pack('<I', 0x200)        # subcmd
    payload += struct.pack('<I', 0)            # flags
    payload += struct.pack('<I', 6)            # case 6 = 黑屏/锁键鼠
    payload += struct.pack('<I', 1)            # lock_input=1
    payload += struct.pack('<I', 1)            # 禁用学生端本地定时器
    payload += struct.pack('<I', timeout)       # 与 MESS timeout 保持一致
    payload += struct.pack('<I', 0)            # has_text
    payload += b'\x00' * 8                    # padding
    pkt = build_comd_command_ex(0x80000010, payload, 'f96a6d195b2946b9ab958a143ecddc26')
    sock.sendto(pkt, (sip, PORT))
    logger.info('[锁键鼠] COMD case6 lock=1 timer_flag=1 timeout=%d -> %s:%d',
                timeout, sip, PORT)


def send_blackscreen(sip, lock_input=True, timeout=10, text=None):
    """向已登录学生发送黑屏安静命令。

    MESS 协议 → 当前频道对应的会话组播端点（黑屏窗口、bit 0x20 状态，
                  lock_input 非零时也会直接锁定键鼠）
    COMD 协议 → 学生单播 :4705（锁定兼容补包，sub_44A490 case 6）

    超时由教师端主动发解锁包实现——先发 flags=0x80000000（锁），
    时间到再发 flags=0x90000000（解）。
    """
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    try:
        # 1) MESS 黑屏包 → 组播（创建窗口、设置 bit 0x20，并按 lock_input 锁键鼠）
        payload = build_blackscreen_mess_payload(lock_input, timeout, text)
        mess = (struct.pack('<II', 0x5353454D, 1)
                + struct.pack('<I', 1)
                + socket.inet_aton(sip)
                + payload)
        sock2.sendto(mess, (SMCAST, SPORT))

        # 2) COMD case 6 → 单播兼容补包；不启用学生端本地定时器
        if lock_input:
            _send_comd_blackscreen_lock(sip, timeout=timeout)

        # 取消之前的定时器
        if sip in blackscreen_timers:
            blackscreen_timers[sip].cancel()
            del blackscreen_timers[sip]

        if timeout > 0:
            timeout_str = f'{timeout}秒后自动解锁'
            t = threading.Timer(timeout, _auto_unlock, args=(sip,))
            t.daemon = True
            t.start()
            blackscreen_timers[sip] = t
        else:
            timeout_str = '永久（需手动 unlock）'

        logger.info('[命令] 黑屏安静 -> %s, lock=%s, timeout=%s, text=%s',
                    sip, lock_input, timeout_str, text)
        print(f'[命令] 已向 {sip} 发送黑屏安静（{timeout_str}）')
    except Exception as e:
        logger.error('[命令] 发送黑屏安静失败：%s', e, exc_info=True)
        print(f'[命令] 发送失败：{e}')


def _auto_unlock(sip):
    """定时器回调：到了超时时间自动解锁。"""
    if sip in blackscreen_timers:
        del blackscreen_timers[sip]
    if sip in students:
        logger.info('[AutoUnlock] 超时自动解锁 %s', sip)
        print(f'[自动] {sip} 黑屏超时，正在解锁...')
        _do_unlock(sip)
    else:
        logger.info('[AutoUnlock] %s 已下线，跳过', sip)


def _do_unlock(sip):
    """通过 MESS 停止标志关闭黑屏并解除键鼠锁。"""
    try:
        # MESS 解锁 → 组播（flags=0x90000000，清除 bit 0x20）
        payload = (struct.pack('<I', 0x0D)
                   + struct.pack('<I', 0x20)
                   + struct.pack('<I', 0x90000000)
                   + b'\x01')
        mess = (struct.pack('<II', 0x5353454D, 1)
                + struct.pack('<I', 1)
                + socket.inet_aton(sip)
                + payload)
        sock2.sendto(mess, (SMCAST, SPORT))
        logger.info('[解锁] MESS -> %s:%d 目标=%s', SMCAST, SPORT, sip)
    except Exception as e:
        logger.error('[解锁] 发送失败：%s', e, exc_info=True)


def send_unlock(sip):
    """向已登录学生发送 MESS 黑屏停止/解锁命令。"""
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    # 取消自动解锁定时器
    if sip in blackscreen_timers:
        blackscreen_timers[sip].cancel()
        del blackscreen_timers[sip]
    _do_unlock(sip)
    print(f'[命令] 已向 {sip} 发送解锁')


def send_shutdown(sip, reboot=False, delay=0, force=True, text=None):
    """关机/重启学生机（COMD 0x80000010，category=0x200 → sub_44A490）。

    cmdId: 0x14=关机，0x13=重启，|0x10000000=强制（跳过学生端倒计时气泡）。
    delay>0 且非 force 时，学生端弹倒计时气泡（(delay+1)*1000ms，文本取 text）。
    执行端为学生端目录下 Shutdown.exe：关机=-nb，重启=-b，force=-f/-nf，
    执行后学生端进程自杀退出。

    注意：payload 末尾必须多补 4 字节——学生端按包内 len 从 body+0xC 复制，
    会从 reserved 字段开始算，吃掉 payload 尾部 4 字节。
    """
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    cmd = (0x13 if reboot else 0x14) | (0x10000000 if force else 0)
    payload = struct.pack('<I', 0x200)                # category: 应用命令
    payload += struct.pack('<I', 0)                   # flags
    payload += struct.pack('<I', cmd)                 # cmdId
    payload += struct.pack('<I', delay)               # 延迟秒数
    payload += b'\x00' * 8                            # reserved
    if text:
        payload += text.encode('utf-16-le') + b'\x00\x00'
    payload += b'\x00' * 4                            # 吸收接收端 len 截断
    pkt = build_comd_command_ex(0x80000010, payload,
                                'f96a6d195b2946b9ab958a143ecddc26')
    action = '重启' if reboot else '关机'
    try:
        sock.sendto(pkt, (sip, PORT))
        mode = '强制立即' if force else (f'倒计时{delay}秒' if delay > 0 else '立即')
        logger.info('[命令] %s -> %s, cmd=0x%08X, delay=%d, text=%s',
                    action, sip, cmd, delay, text)
        print(f'[命令] 已向 {sip} 发送{mode}{action}')
    except Exception as e:
        logger.error('[命令] 发送%s失败：%s', action, e, exc_info=True)
        print(f'[命令] 发送失败：{e}')




def build_dmoc():
    """构造 DMOC 包（教师端控制信息）。"""
    cg = bytes.fromhex('ce90fd383df5844c857fa35183c051f3')
    dd = b'\x20\x4e\x00\x00' + socket.inet_aton(ip) + b'\x35\x00\x00\x00\x35\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x80'
    dd += bytes.fromhex('e10202331e16e102023421160000a046000020419a99993fa0052000')
    dd += b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3d\x00'
    return struct.pack('<II', 0x434F4D44, 0x10000) + struct.pack('<I', len(dd)) + cg + dd


def build_lpnt(policy_version=3, enabled=True, width=80, height=60, refresh_seconds=5):
    """构造缩略图策略包：版本、启用标志、宽、高、刷新秒数。"""
    lg = bytes.fromhex('aa3a8dbe2b906645908ea29526218540')
    policy = struct.pack('<IIIII', policy_version, int(enabled),
                         width, height, refresh_seconds)
    return struct.pack('<III', 0x544E504C, 0x10000, len(policy)) + lg + policy


def build_srnt(frame_seq, complete=True, missing_parts=()):
    """构造学生端实际接收的 SRNT 帧确认/重传请求。"""
    lg = bytes.fromhex('aa3a8dbe2b906645908ea29526218540')
    if missing_parts is None:
        payload = struct.pack('<III', frame_seq, 0, 0xFFFFFFFF)
    else:
        missing_parts = tuple(missing_parts)
        payload = struct.pack('<III', frame_seq, int(complete), len(missing_parts))
        if missing_parts:
            payload += struct.pack(f'<{len(missing_parts)}H', *missing_parts)
    # DLL 要求 payload 至少 14 字节；最后两个字节不参与解析。
    payload += b'\x00\x00'
    return struct.pack('<III', 0x544E5253, 0x10000, len(payload)) + lg + payload


def keep_alive_preview(sip):
    """学生登录后周期性发送启用的 LPNT + DMOC，直到开始收到预览。"""
    lp = build_lpnt(3, True)
    dm = build_dmoc()
    logger.info('[KeepAlive] 启动 %s', sip)
    while running and sip in students:
        if sip in previews:
            logger.info('[KeepAlive] %s previews 已存在，停止', sip)
            break
        try:
            sock.sendto(lp, (sip, PORT))
            logger.debug('[KeepAlive] LPNT -> %s', sip)
        except Exception as e:
            logger.error('[KeepAlive] LPNT -> %s 失败：%s', sip, e, exc_info=True)
        time.sleep(0.05)
        try:
            sock.sendto(dm, (sip, PORT))
            logger.debug('[KeepAlive] DMOC -> %s', sip)
        except Exception as e:
            logger.error('[KeepAlive] DMOC -> %s 失败：%s', sip, e, exc_info=True)
        time.sleep(0.5)
    logger.info('[KeepAlive] %s 退出', sip)


def handle_tnal(d, sip):
    """接收 LANT 预览缩略图片段并拼成 JPEG。"""
    logger.debug('[LANT] RECV from %s, len=%d\n%s', sip, len(d), hexdump(d[:256]))

    if len(d) < 48:
        logger.warning('[TNAL] 包太短：%d 字节 from %s', len(d), sip)
        return

    try:
        frame_seq = struct.unpack('<I', d[32:36])[0]
        total = struct.unpack('<I', d[36:40])[0]
        offset = struct.unpack('<I', d[40:44])[0]
        frag_len = struct.unpack('<I', d[44:48])[0]
    except struct.error as e:
        logger.error('[TNAL] 解包失败 from %s：%s', sip, e, exc_info=True)
        return

    frag = d[48:48+frag_len]
    logger.debug('[LANT] %s frame=%d total=%d offset=%d frag_len=%d',
                 sip, frame_seq, total, offset, frag_len)

    if not frag or total == 0 or offset >= total:
        logger.warning('[LANT] 非法片段 frame=%d total=%d offset=%d from %s',
                       frame_seq, total, offset, sip)
        return

    state = previews.get(sip)
    if state is None or state['frame_seq'] != frame_seq or state['total'] != total:
        logger.info('[LANT] %s 新建帧 frame=%d total=%d', sip, frame_seq, total)
        state = {
            'frame_seq': frame_seq,
            'total': total,
            'buf': bytearray(total),
            'got': 0,
            'received': {},
        }
        previews[sip] = state

    end = min(offset + len(frag), total)
    written = end - offset
    if written <= 0:
        logger.warning('[LANT] 非法写入 offset=%d end=%d from %s', offset, end, sip)
        return

    state['buf'][offset:end] = frag[:written]
    previous = state['received'].get(offset, 0)
    state['received'][offset] = max(previous, written)
    state['got'] += max(0, written - previous)
    logger.debug('[LANT] %s frame=%d 进度 %d/%d (+%d)',
                 sip, frame_seq, state['got'], total, max(0, written - previous))

    if state['got'] >= total:
        idx = 0
        while True:
            fn = os.path.join(LOG_DIR, f'preview_{sip.replace(".", "_")}_{idx}.jpg')
            if not os.path.exists(fn):
                break
            idx += 1
        try:
            with open(fn, 'wb') as f:
                f.write(state['buf'])
            logger.info('[Preview] 已保存原图 %s (%d bytes)', fn, total)
        except Exception as e:
            logger.error('[Preview] 保存原图 %s 失败：%s', fn, e, exc_info=True)
            return

        # 极域学生端 JPEG 是 bottom-up DIB + 仅色度反相（Cb/Cr 反相，Y 不变）。
        try:
            fixed_fn = fn.replace('.jpg', '_fixed.jpg')
            img = Image.open(io.BytesIO(state['buf']))
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img = img.transpose(Image.FLIP_TOP_BOTTOM)
            ycbcr = img.convert('YCbCr')
            y, cb, cr = ycbcr.split()
            cb = ImageOps.invert(cb)
            cr = ImageOps.invert(cr)
            img = Image.merge('YCbCr', (y, cb, cr)).convert('RGB')
            img.save(fixed_fn, 'JPEG', quality=95)
            logger.info('[Preview] 已保存修复图 %s', fixed_fn)
        except Exception as e:
            logger.error('[Preview] 修复图保存失败：%s', e, exc_info=True)

        logger.info('[Preview] %s 接收完成', sip)
        completed_preview_frames[sip] = frame_seq
        del previews[sip]


def handle_mess(d, sip, sp, via='unknown'):
    """解析学生端发来的 MESS 消息包（聊天/提示类）。"""
    if len(d) < 12:
        logger.warning('[MESS] 包过短（%d 字节）from %s:%d via %s', len(d), sip, sp, via)
        return

    try:
        magic, sender_id, rcpt_count = struct.unpack('<III', d[:12])
        header_len = 12 + 4 * rcpt_count
        if len(d) < header_len:
            logger.warning('[MESS] 头长度不足 from %s:%d (rcpt_count=%d)', sip, sp, rcpt_count)
            return
        payload = d[header_len:]
    except struct.error as e:
        logger.error('[MESS] 解包失败 from %s:%d：%s', sip, sp, e)
        return

    logger.info('[MESS] RECV from %s:%d via %s, sender_id=0x%08X, rcpt_count=%d, payload_len=%d',
                sip, sp, via, sender_id, rcpt_count, len(payload))
    logger.debug('[MESS] payload hex\n%s', hexdump(payload[:256]))

    text = None
    msg_kind = 'unknown'
    # 去重键：区分消息类别/子类型，避免交替消息绕过相邻去重
    dedupe_key = None
    msg_type = struct.unpack('<I', payload[4:8])[0] if len(payload) >= 8 else 0
    category = struct.unpack('<I', payload[8:12])[0] if len(payload) >= 12 else 0
    subtype = struct.unpack('<I', payload[12:16])[0] if len(payload) >= 16 else 0

    # IDA 中聊天消息负载结构：
    # [0..3]=总长, [4..7]=0x800, [8..11]=0, [12..15]=1, [16..]=UTF-16-LE 字符串
    if len(payload) >= 16 and msg_type == 0x800:
        dedupe_key = 'chat'
        try:
            raw = payload[16:].rstrip(b'\x00')
            if len(raw) % 2:
                raw = raw[:-1]
            text = raw.decode('utf-16-le')
            msg_kind = 'chat'
        except Exception as e:
            logger.debug('[MESS] 聊天消息 UTF-16-LE 解码失败：%s', e)

    elif len(payload) >= 24 and msg_type == 0:
        dedupe_key = f'{category:#010x}/{subtype}'
        extra = struct.unpack('<I', payload[20:24])[0]
        if category == 0x800000:
            # 信息上报（request_info 0x100000 的回复）：
            # [12..15]: 5=系统信息 6=窗口列表(分片) 7=进程列表(分片)
            if subtype == 5:
                if len(payload) >= 0x2E0:
                    try:
                        info = _parse_student_info(payload, sip)
                        text = (f"[学生信息] 计算机名={info['name']} 用户={info['user']} "
                                f"MAC={info['mac']} OS={info['os']} {info['osver']} "
                                f"CPU={info['cpu_vendor']}/{info['cpu_model']} 内存={info['mem']}")
                        msg_kind = 'status'
                    except Exception as e:
                        logger.debug('[MESS] 学生信息解析失败：%s', e)
                else:
                    logger.debug('[MESS] type 5 学生信息长度不足: %d', len(payload))
            elif subtype in (6, 7):
                # [16..19]=分片标志(1=首片), [20..]={u32 id, wchar name\0} 序列
                # type 6=窗口/应用程序列表(hwnd+标题), type 7=进程列表(pid+exe名)
                chunk_flag = struct.unpack('<I', payload[16:20])[0]
                entries = _parse_id_name_pairs(payload[20:])
                store_key = 'windows' if subtype == 6 else 'processes'
                if sip in students:
                    if chunk_flag == 1 or store_key not in students[sip]:
                        students[sip][store_key] = []
                    # 按 (id, name) 去重，防止首片丢失导致的重复累积
                    existing = students[sip][store_key]
                    seen = set(existing)
                    for e in entries:
                        if e not in seen:
                            seen.add(e)
                            existing.append(e)
                total = len(students[sip][store_key]) if sip in students and store_key in students[sip] else len(entries)
                kind = '窗口' if subtype == 6 else '进程'
                names = '，'.join(n for _, n in entries[:6])
                text = (f'[{kind}列表{"首片" if chunk_flag == 1 else "续片"}] '
                        f'本片 {len(entries)} 个，累计 {total} 个：{names}'
                        + ('…' if len(entries) > 6 else ''))
                msg_kind = 'status'
                logger.debug('[MESS] %s列表完整分片: %s', kind,
                             '，'.join(f'{p}:{n}' for p, n in entries))
            else:
                logger.debug('[MESS] 未知信息上报子类型 %d', subtype)
        else:
            # 状态消息（category=3 等）：
            # [12..15]=子类型, [16..19]=字符串最大长度, [20..23]=PID/计数/额外数据, [24..]=UTF-16-LE 字符串
            if subtype == 6:
                try:
                    raw = payload[24:].rstrip(b'\x00')
                    if len(raw) % 2:
                        raw = raw[:-1]
                    title = raw.decode('utf-16-le')
                    text = f'[窗口标题] {title}'
                    msg_kind = 'status'
                except Exception as e:
                    logger.debug('[MESS] 窗口标题解码失败：%s', e)
            elif subtype == 7:
                # sub_43B080：调用 Wlanapi 获取可用 WiFi 网络数量，-1 表示检测失败
                count = extra if extra != 0xFFFFFFFF else -1
                text = f'[WiFi可用网络数量] {count}'
                msg_kind = 'status'
            elif subtype == 1:
                text = f'[IE/浏览器URL信息] extra=0x{extra:08X}'
                msg_kind = 'status'
            elif subtype == 0:
                text = f'[窗口标题清空/PID=0x{extra:08X}]'
                msg_kind = 'status'
            elif subtype == 3:
                text = '[系统性能/进程信息]'
                msg_kind = 'status'
            else:
                logger.debug('[MESS] 未知状态子类型 %d (category=%#x)', subtype, category)

    if text:
        if msg_kind == 'chat':
            logger.info('[MESS] 来自 %s:%d 的聊天消息：%s', sip, sp, text)
        elif last_status.get((sip, dedupe_key)) == text:
            # 内容无变化的同类消息（周期性窗口标题/WiFi/列表分片）只记 DEBUG
            logger.debug('[MESS] 来自 %s:%d 的状态消息(重复)：%s', sip, sp, text)
        else:
            last_status[(sip, dedupe_key)] = text
            logger.info('[MESS] 来自 %s:%d 的状态消息：%s', sip, sp, text)
    else:
        key = f'<未解析 type=0x{msg_type:08X} len={len(payload)}>'
        if last_status.get((sip, key)) == payload[:64]:
            logger.debug('[MESS] 来自 %s:%d 的消息无法解析文本(重复)', sip, sp)
        else:
            last_status[(sip, key)] = payload[:64]
            logger.info('[MESS] 来自 %s:%d 的消息无法解析文本，payload_len=%d, msg_type=0x%08X',
                        sip, sp, len(payload), msg_type)


def broadcast():
    logger.info('[Broadcast] 启动')
    first_cycle = True
    while running:
        try:
            oonc_packet = oonc()
            count = send_to_targets(sock, oonc_packet,
                                    MAIN_ANNOUNCE_TARGETS, 'OONC')
            logger.debug('[Broadcast] OONC 已发送到 %d 个目标', count)
        except Exception as e:
            logger.error('[Broadcast] OONC 失败：%s', e, exc_info=True)
            oonc_packet = b''
            count = 0
        time.sleep(0.5)

        try:
            normal_packet = nanc()
            auto_packet = canc()
            normal_count = send_to_targets(sock, normal_packet, MAIN_ANNOUNCE_TARGETS,
                                           'NANC')
            auto_count = send_to_targets(sock, auto_packet, MAIN_ANNOUNCE_TARGETS,
                                         'CANC')
            logger.debug('[Broadcast] NANC/CANC 已发送到 %d/%d 个目标',
                         normal_count, auto_count)
            if first_cycle:
                targets = ', '.join(f'{host}:{port}'
                                    for host, port in MAIN_ANNOUNCE_TARGETS)
                logger.info(
                    '[Broadcast] 首轮发送完成：OONC len=%d sent=%d；'
                    'NANC len=%d sent=%d；CANC len=%d mask=0x%08X sent=%d；'
                    'targets=%s',
                    len(oonc_packet), count, len(normal_packet), normal_count,
                    len(auto_packet), 1 << (CHANNEL_ID - 1), auto_count, targets)
                first_cycle = False
        except Exception as e:
            logger.error('[Broadcast] NANC/CANC 失败：%s', e, exc_info=True)
        time.sleep(0.5)
    logger.info('[Broadcast] 退出')


def session_anno():
    logger.info('[Session] 广播线程启动')
    first_cycle = True
    while running:
        try:
            pkt1 = struct.pack('<II', 0x4F4E4E41, 1)
            type1_count = send_to_targets(sock2, pkt1, SESSION_ANNOUNCE_TARGETS,
                                          'ANNO(type1)')
            logger.debug('[Session] ANNO(type1) 已发送到 %d 个目标', type1_count)
            time.sleep(0.3)

            pkt2 = (struct.pack('<III', 0x4F4E4E41, 1, 1)
                    + b'\x00'*8
                    + socket.inet_aton(ip)
                    + struct.pack('<I', 0x0D5AD030)
                    + b'\x00'*4
                    + struct.pack('<I', 0x0D5AD030)
                    + struct.pack('<I', 1)
                    + b'\x00'*32)
            type2_count = send_to_targets(sock2, pkt2, SESSION_ANNOUNCE_TARGETS,
                                          'ANNO(type2)')
            logger.debug('[Session] ANNO(type2) 已发送到 %d 个目标', type2_count)
            if first_cycle:
                targets = ', '.join(f'{host}:{port}'
                                    for host, port in SESSION_ANNOUNCE_TARGETS)
                logger.info(
                    '[Session] 首轮发送完成：ANNO(type1) len=%d sent=%d；'
                    'ANNO(type2) len=%d sent=%d；targets=%s',
                    len(pkt1), type1_count, len(pkt2), type2_count, targets)
                first_cycle = False
            time.sleep(0.7)
        except Exception as e:
            logger.error('[Session] 广播异常：%s', e, exc_info=True)
            break
    logger.info('[Session] 广播线程退出')


def build_session_reply(recipient_ip, msg_type):
    """构造教师端会话回复，目标地址同时写入 MESS 接收者字段。"""
    if msg_type == 0x1000:
        payload = struct.pack('<III', 0x0D, 0x1000, 0)
        payload += b'\x00'
    elif msg_type == 0x8000:
        # 连续桌面观看需要 TCPMode=1；均可通过环境变量覆盖。
        # 尾部状态值来自已验证样本；总长度严格保持 0x1B。
        payload = struct.pack('<III', 0x1B, 0x8000, 0)
        payload += struct.pack('<IH', TCP_COMM_MODE, TCP_COMM_PORT)
        payload += b'\x00' * 4
        payload += struct.pack('<I', 0x270034B0)
        payload += b'\x00'
    else:
        raise ValueError(f'不支持的会话回复类型：0x{msg_type:08X}')

    if len(payload) != struct.unpack_from('<I', payload)[0]:
        raise AssertionError('会话回复的声明长度与实际长度不一致')
    return (struct.pack('<III', 0x5353454D, 1, 1)
            + socket.inet_aton(recipient_ip)
            + payload)


def session_recv():
    logger.info('[SessionRecv] 启动')
    sock2.settimeout(1)
    while running:
        try:
            d, a = sock2.recvfrom(4096)
            sip, sp = a

            # 忽略本机发出的 ANNO 回包
            if sip == ip:
                continue

            if len(d) < 4:
                logger.warning('[SessionRecv] 包过短（%d 字节）from %s:%d', len(d), sip, sp)
                continue

            mag = struct.unpack('<I', d[:4])[0]

            if mag == 0x49474F4C:  # LOGI
                already_logged_in = sip in students
                # 已登录学生会周期性重发 LOGI（相当于心跳），属常态——
                # 回复包照发，但日志降为 DEBUG，避免每次心跳刷 4 条 INFO。
                log = logger.debug if already_logged_in else logger.info
                log('[SessionRecv] LOGI from %s:%d%s', sip, sp,
                    '（周期重复）' if already_logged_in else '')

                # 1) 真实教师端第一条回复：msg_type=0x1000，总长 0x0d
                mess1 = build_session_reply(sip, 0x1000)
                sock2.sendto(mess1, (sip, SPORT))
                log('[MESS] type 0x1000 -> %s:%d, len=%d', sip, SPORT, len(mess1))
                time.sleep(0.05)

                # 2) 真实教师端第二条回复：msg_type=0x8000，总长 0x1b
                mess2 = build_session_reply(sip, 0x8000)
                sock2.sendto(mess2, (sip, SPORT))
                log('[MESS] type 0x8000 -> %s:%d, len=%d', sip, SPORT, len(mess2))
                time.sleep(0.05)

                if already_logged_in:
                    continue

                lg = bytes.fromhex('aa3a8dbe2b906645908ea29526218540')
                lp = struct.pack('<II', 0x544E504C, 0x10000) + struct.pack('<I', 20) + lg + b'\x02\x00\x00\x00\x00\x00\x00\x00\x50\x00\x00\x00\x3c\x00\x00\x00\x05\x00\x00\x00'
                sock.sendto(lp, (sip, PORT))
                logger.info('[LPNT] subtype=2 -> %s:%d', sip, PORT)

                lp2 = bytes(lp)
                lp2 = lp2[:28] + b'\x03\x00\x00\x00\x01\x00\x00\x00' + lp2[36:]
                sock.sendto(lp2, (sip, PORT))
                logger.info('[LPNT] subtype=3 -> %s:%d', sip, PORT)

                dm = build_dmoc()
                sock.sendto(dm, (sip, PORT))
                logger.info('[DMOC] -> %s:%d, len=%d', sip, PORT, len(dm))

                students[sip] = {'logged_in': True}
                logger.info('[Login] %s 登录成功，students=%s', sip, list(students.keys()))

                # 登录后自动请求学生信息（计算机名/MAC/用户/OS/CPU/内存）
                time.sleep(0.2)
                request_info(sip)

                threading.Thread(target=keep_alive_preview, args=(sip,), daemon=True).start()

            elif mag == 0x5353454D:  # MESS 学生端发来的消息
                handle_mess(d, sip, sp, 'SessionRecv')

            elif mag not in ROUTINE_MAGICS:
                # 非日常广播包才记录，减少噪音
                logger.warning(
                    '[SessionRecv] 未认证/非登录包 %s from %s:%d, len=%d\n%s',
                    magic_name(mag), sip, sp, len(d), hexdump(d[:256])
                )

        except socket.timeout:
            continue
        except Exception as e:
            if running:
                logger.error('[SessionRecv] 异常：%s', e, exc_info=True)
    logger.info('[SessionRecv] 退出')


def main_recv():
    global running
    logger.info('[MainRecv] 启动')
    while running:
        try:
            d, a = sock.recvfrom(4096)
            sip, sp = a

            # 过滤本机广播
            if sip == ip:
                continue

            if len(d) < 4:
                logger.warning('[MainRecv] 包过短（%d 字节）from %s:%d', len(d), sip, sp)
                continue

            mag = struct.unpack('<I', d[:4])[0]

            # 日常广播（OONC/NANC/CANC）直接跳过，不记录
            if mag in ROUTINE_MAGICS:
                continue

            if sip not in students:
                logger.warning(
                    '[MainRecv] 未登录学生 %s:%d 发送 %s',
                    sip, sp, magic_name(mag)
                )

            # TRMC/TRNT 是心跳/预览就绪包，数量很大，默认用 DEBUG
            if mag in (0x434D5254, 0x544E5254):
                logger.debug('[MainRecv] %s from %s:%d, len=%d',
                             magic_name(mag), sip, sp, len(d))
            else:
                logger.info('[MainRecv] %s from %s:%d, len=%d',
                            magic_name(mag), sip, sp, len(d))

            if mag == 0x4143414B:  # KACA
                logger.info('[MainRecv] KACA %s -> WACA', sip)
                sock.sendto(waca(sip), (sip, PORT))

            elif mag == 0x434D5254:  # TRMC
                logger.debug('[MainRecv] TRMC %s -> LPNT+DMOC', sip)
                lp = build_lpnt(3, True)
                dm = build_dmoc()
                sock.sendto(lp, (sip, PORT))
                time.sleep(0.05)
                sock.sendto(dm, (sip, PORT))

            elif mag == 0x544E5254:  # TRNT
                logger.debug('[MainRecv] TRNT %s 学生准备好预览', sip)

            elif mag == 0x544E4544:  # DENT
                if len(d) < 40:
                    logger.warning('[MainRecv] DENT 包过短：%d from %s', len(d), sip)
                    continue
                frame_seq = struct.unpack('<I', d[36:40])[0]
                state = previews.get(sip)
                if state and state['frame_seq'] == frame_seq:
                    part_count = (state['total'] + 1023) // 1024
                    missing = [index for index in range(part_count)
                               if index * 1024 not in state['received']]
                    pkt = build_srnt(frame_seq, complete=not missing,
                                     missing_parts=missing)
                    action = 'complete' if not missing else f'retry {len(missing)} parts'
                elif completed_preview_frames.get(sip) == frame_seq:
                    pkt = build_srnt(frame_seq, complete=True)
                    action = 'complete'
                else:
                    pkt = build_srnt(frame_seq, complete=False, missing_parts=None)
                    action = 'retry all'
                logger.info('[MainRecv] DENT %s frame=%d -> SRNT %s',
                            sip, frame_seq, action)
                sock.sendto(pkt, (sip, PORT))

            elif mag == 0x544E414C:  # LANT
                handle_tnal(d, sip)

            elif mag == 0x5353454D:  # MESS 学生端发来的消息
                handle_mess(d, sip, sp, 'MainRecv')

            else:
                logger.warning('[MainRecv] 未知包 %s from %s:%d, len=%d\n%s',
                               hex(mag), sip, sp, len(d), hexdump(d[:256]))

        except Exception as e:
            if running:
                logger.error('[MainRecv] 异常：%s', e, exc_info=True)
    logger.info('[MainRecv] 退出')


# -------------------- 命令行交互 --------------------

def _parse_lock_text(rest):
    """从 bs/bsperm/bsall 的原始剩余字符串解析 lock 标志和 text。

    rest 为 ip 之后的整段字符串（command_loop 以 maxsplit=2 切分）：
      '' / '0' / '1'       → 仅 lock 标志
      '0 消息' / '1 消息'  → lock + text
      '消息'               → lock=True + text
    """
    lock, text = True, None
    if rest:
        rest = rest.strip()
        if rest in ('0', '1'):
            lock = (rest == '1')
        elif rest[:2] in ('0 ', '1 '):
            lock = (rest[0] == '1')
            text = rest[2:].strip() or None
        else:
            text = rest
    return lock, text


def _parse_delay_text(rest):
    """解析 shutdown/reboot 的 '[倒计时秒数] [提示文字]'。

      ''          → (0, None)
      '30'        → (30, None)
      '30 请保存'  → (30, '请保存')
      '请保存'     → (0, '请保存')
    """
    delay, text = 0, None
    if rest:
        parts = rest.strip().split(maxsplit=1)
        if parts[0].isdigit():
            delay = int(parts[0])
            text = parts[1] if len(parts) > 1 else None
        else:
            text = rest.strip()
    return delay, text


def cmd_help():
    print('''可用命令：
  help / ?              显示帮助
  list / ls             列出已登录学生
  preview <ip>          请求指定学生的屏幕预览
  view_probe <ip> [port]  仅探测学生 TCP 观看端口，不发送观看请求
  view <ip> [port]      连续观看学生屏幕（V6 TCP/UMSP，默认 4806）
  view_stop <ip>        停止连续观看
  control <ip> [port]   打开交互式远程控制窗口（默认随机高位 UDP 端口）
  control_stop <ip>     停止远程控制
  mouse <ip> <动作> <x> <y> [data]  发送鼠标事件，坐标范围 0..65535
  key <ip> <vk> [press|down|up] [scan] [extended]  发送键盘事件
  all                   请求所有学生的屏幕预览
  msg <ip> <text>       向指定学生发送聊天消息
  info <ip> [0|1|2]     请求学生上报信息（0=全部 1=窗口列表 2=进程列表，登录后自动请求一次）
  ps <ip>               显示学生进程列表（先 info 请求过）
  wins <ip>             显示学生窗口列表（先 info 请求过）
  kill <ip> <pid|进程名> [f]   结束学生进程（f=1 强杀；f=0 先试 WM_CLOSE）
  closeapp <ip> <hwnd|标题关键字> [f]  结束学生应用程序（按窗口句柄或标题）
  openurl <ip> <网址|路径>   在学生机打开网页/文件（ShellExecute）
  run <ip> <路径> [参数] [show]  远程运行程序（show: 0=正常 1=最小化 2=最大化，路径含空格用引号）
  blackscreen / bs <ip> [lock=1|0] [text]   向指定学生发送黑屏安静（默认锁键鼠，10秒自动解锁）
  bsperm / bsp <ip> [lock=1|0] [text]       向指定学生发送永久黑屏安静（需手动 unlock）
  unlock <ip>           解锁指定学生的黑屏/键盘鼠标锁
  bsall [lock=1|0] [text]  对所有已登录学生发送黑屏安静
  unlock_all            对所有已登录学生发送解锁
  shutdown / sd <ip> [秒] [text]   关闭指定学生机（不带秒数=立即强制；带秒数=倒计时提示）
  reboot / rb <ip> [秒] [text]     重启指定学生机（参数同 shutdown）
  debug on / off        切换文件日志级别（默认 INFO，on=DEBUG 会详细记录并占空间）
  exit / quit / q       退出程序

  例：
    bs 192.168.2.139              黑屏 + 锁键鼠，10秒自动解
    bs 192.168.2.139 0            只黑屏不锁键鼠
    bs 192.168.2.139 1 请认真听课  黑屏锁键鼠 + 自定义文字
    view_probe 192.168.2.139     先确认学生观看端口已监听
    view 192.168.2.139           打开连续屏幕观看窗口
    control 192.168.2.139        打开窗口并开始鼠标/键盘远控
    mouse 192.168.2.139 move 32768 32768
    key 192.168.2.139 0x41 press  按一次 A 键
    shutdown 192.168.2.139        立即强制关机
    reboot 192.168.2.139 30 请保存作业  倒计时30秒重启并显示提示文字''')


def cmd_list():
    if not students:
        print('[命令] 当前无学生登录')
        return
    print('[命令] 已登录学生：')
    for i, (sip, st) in enumerate(students.items(), 1):
        info = st.get('info')
        if info:
            print(f"  {i}. {sip}  {info['name']}  用户:{info['user']}  MAC:{info['mac']}")
            print(f"      OS:{info['os']} {info['osver']}  CPU:{info['cpu_model']}  内存:{info['mem']}")
        else:
            print(f'  {i}. {sip}  (信息未获取，用 info {sip} 请求)')


def cmd_info(args):
    if not args:
        print('[命令] 用法：info <学生IP> [0|1|2]  (0=全部 1=窗口列表 2=进程列表)')
        return
    sip = args[0]
    if sip not in students:
        print(f'[命令] 学生 {sip} 未登录')
        return
    rtype = 0
    if len(args) > 1 and args[1] in ('0', '1', '2'):
        rtype = int(args[1])
    request_info(sip, rtype)
    print(f'[命令] 已向 {sip} 请求信息(rtype={rtype})，结果见日志窗口')


def _check_student(sip, usage):
    """校验学生已登录;第一个参数不像 IP 时提示可能漏填了 IP。"""
    if sip in students:
        return True
    if '.' not in sip:
        print(f'[命令] "{sip}" 不是有效的学生 IP——是不是漏填了 IP?用法:{usage}')
    else:
        print(f'[命令] 学生 {sip} 未登录')
    return False


def _parse_run_args(rest):
    """解析 run 的 '<路径> [参数...] [show]'。路径含空格时用双引号包住。

    show 取末尾独立的 0/1/2（0=正常 1=最小化 2=最大化），其余原样作为程序参数。
    """
    rest = (rest or '').strip()
    if not rest:
        return '', '', 0
    if rest.startswith('"'):
        end = rest.find('"', 1)
        if end > 0:
            path, rest = rest[1:end], rest[end + 1:].strip()
        else:
            path, rest = rest[1:], ''
    else:
        parts = rest.split(maxsplit=1)
        path = parts[0]
        rest = parts[1] if len(parts) > 1 else ''
    show = 0
    if rest in ('0', '1', '2'):
        show, rest = int(rest), ''
    elif rest.endswith((' 0', ' 1', ' 2')):
        show, rest = int(rest[-1]), rest[:-2].rstrip()
    return path, rest, show


def _parse_target_force(rest):
    """'<target> [force]' → (target, force)。force 默认 1，仅识别末尾独立的 0/1。"""
    force = 1
    rest = (rest or '').strip()
    if rest.endswith(' 0'):
        force, rest = 0, rest[:-2].strip()
    elif rest.endswith(' 1'):
        force, rest = 1, rest[:-2].strip()
    return rest, force


def cmd_kill(args):
    """kill <ip> <pid|进程名> [force=1|0]——按 pid 或已建档进程名结束进程。"""
    if len(args) < 2:
        print('[命令] 用法：kill <学生IP> <pid|进程名> [force=1|0]')
        return
    sip = args[0]
    if not _check_student(sip, 'kill <学生IP> <pid|进程名> [force=1|0]'):
        return
    target, force = _parse_target_force(args[1])
    if not target:
        print('[命令] 用法：kill <学生IP> <pid|进程名> [force=1|0]')
        return
    if target.isdigit():
        send_kill(sip, pid=int(target), force=force)
        return
    # 按进程名：查已建档进程列表（info <ip> 2）
    procs = students[sip].get('processes')
    if not procs:
        print(f'[命令] 无 {sip} 的进程列表，先 info {sip} 2 请求')
        return
    matches = [(p, n) for p, n in procs if n.lower() == target.lower()]
    if not matches:  # 精确匹配不到再试包含匹配
        matches = [(p, n) for p, n in procs if target.lower() in n.lower()]
    if not matches:
        print(f'[命令] 进程列表中找不到 "{target}"，可先 info {sip} 2 刷新')
        return
    for pid, name in matches:
        send_kill(sip, pid=pid, force=force)
        time.sleep(0.03)
    print(f'[命令] 已对 {len(matches)} 个匹配进程发送结束命令（可用 info {sip} 2 验证）')


def cmd_closeapp(args):
    """closeapp <ip> <hwnd|标题关键字> [force=1|0]——按窗口结束应用程序。"""
    if len(args) < 2:
        print('[命令] 用法：closeapp <学生IP> <hwnd|窗口标题关键字> [force=1|0]')
        return
    sip = args[0]
    if not _check_student(sip, 'closeapp <学生IP> <hwnd|窗口标题关键字> [force=1|0]'):
        return
    target, force = _parse_target_force(args[1])
    if not target:
        print('[命令] 用法：closeapp <学生IP> <hwnd|窗口标题关键字> [force=1|0]')
        return
    try:
        hwnd = int(target, 0)  # 支持 0x 前缀或十进制
        send_kill(sip, hwnd=hwnd, force=force)
        return
    except ValueError:
        pass
    # 按标题关键字：查已建档窗口列表（info <ip> 1）
    wins = students[sip].get('windows')
    if not wins:
        print(f'[命令] 无 {sip} 的窗口列表，先 info {sip} 1 请求')
        return
    matches = [(h, t) for h, t in wins if target.lower() in t.lower()]
    if not matches:
        print(f'[命令] 窗口列表中找不到 "{target}"，可先 info {sip} 1 刷新')
        return
    if len(matches) > 1:
        print(f'[命令] 匹配到 {len(matches)} 个窗口，取第一个：')
        for h, t in matches[:5]:
            print(f'    0x{h:08X}  {t}')
    hwnd, title = matches[0]
    print(f'[命令] 匹配窗口：0x{hwnd:08X} {title}')
    send_kill(sip, hwnd=hwnd, force=force)


def cmd_ps(args):
    """显示已收集的进程列表（type 7，pid+exe名）。"""
    if not args:
        print('[命令] 用法：ps <学生IP>')
        return
    sip = args[0]
    procs = students.get(sip, {}).get('processes')
    if not procs:
        print(f'[命令] 无 {sip} 的进程列表（先 info {sip} 2 请求）')
        return
    print(f'[命令] {sip} 进程列表（{len(procs)} 个）：')
    for pid, name in procs:
        print(f'  {pid:>6}  {name}')


def cmd_wins(args):
    """显示已收集的窗口列表（type 6，hwnd+标题）。"""
    if not args:
        print('[命令] 用法：wins <学生IP>')
        return
    sip = args[0]
    wins = students.get(sip, {}).get('windows')
    if not wins:
        print(f'[命令] 无 {sip} 的窗口列表（先 info {sip} 1 请求）')
        return
    print(f'[命令] {sip} 窗口列表（{len(wins)} 个）：')
    for hwnd, title in wins:
        print(f'  0x{hwnd:08X}  {title}')


def cmd_preview(args):
    if not args:
        print('[命令] 用法：preview <学生IP>')
        return
    sip = args[0]
    request_preview(sip)
    print(f'[命令] 已向 {sip} 请求预览')


def cmd_view(args):
    if not args:
        print('[命令] 用法：view <学生IP> [TCP端口]')
        return
    sip = args[0]
    try:
        port = int(args[1].strip(), 0) if len(args) > 1 else TCP_COMM_PORT
        if not 1 <= port <= 0xFFFF:
            raise ValueError('端口必须在 1..65535')
        if start_remote_view(sip, port):
            print(f'[观看] 已启动 {sip}:{port}，正在连接；画面由 ffplay 显示')
    except ValueError as e:
        print(f'[观看] 参数错误：{e}')
    except OSError as e:
        print(f'[观看] 启动失败：{e}')


def cmd_view_probe(args):
    if not args:
        print('[命令] 用法：view_probe <学生IP> [TCP端口]')
        return
    sip = args[0]
    try:
        port = int(args[1].strip(), 0) if len(args) > 1 else TCP_COMM_PORT
        if not 1 <= port <= 0xFFFF:
            raise ValueError('端口必须在 1..65535')
        if not _check_student(sip, 'view_probe <学生IP> [TCP端口]'):
            return
        reachable, detail = probe_remote_view(sip, port)
        if reachable:
            print(f'[观看] 探测成功：{sip}:{port} 正在监听，可以执行 view {sip}')
        else:
            print(f'[观看] 探测失败：{sip}:{port} 未监听（{detail}）；未发送观看请求')
    except (ValueError, OSError) as e:
        print(f'[观看] 探测参数错误：{e}')


def cmd_control(args):
    if not args:
        print('[命令] 用法：control <学生IP> [UDP端口]')
        return
    sip = args[0]
    try:
        port = int(args[1].strip(), 0) if len(args) > 1 else None
        if port is not None and not 1 <= port <= 0xFFFF:
            raise ValueError('端口必须在 1..65535')
        if not _check_student(sip, 'control <学生IP> [UDP端口]'):
            return
        with remote_state_lock:
            session = remote_views.get(sip)
        if session is None:
            if not start_remote_view(sip):
                print('[远控] 未发送 MCMD：观看通道尚未建立，避免学生端进入不完整的远控状态')
                return
            with remote_state_lock:
                session = remote_views.get(sip)
        if session is not None:
            session.enable_interactive_player()
        if session is None or not session.connected_event.wait(6.0):
            print('[远控] 未发送 MCMD：等待屏幕 TCP 通道超时，请先执行 view_probe 后重试')
            return
        selected_port = start_remote_control(sip, port)
        if selected_port:
            print(f'[远控] {sip}:{selected_port} 已启动；在远程控制窗口内可直接操作鼠标和键盘')
    except (ValueError, OSError) as e:
        print(f'[远控] 启动失败：{e}')


def cmd_mouse(args):
    if len(args) < 2:
        print('[命令] 用法：mouse <学生IP> <动作> <x> <y> [data]')
        return
    sip = args[0]
    parts = args[1].split()
    if len(parts) < 3:
        print('[命令] 用法：mouse <学生IP> <动作> <x> <y> [data]')
        return
    try:
        action = parts[0]
        x, y = int(parts[1], 0), int(parts[2], 0)
        data = int(parts[3], 0) if len(parts) > 3 else 0
        if send_remote_mouse(sip, action, x, y, data):
            print(f'[远控] mouse {action} -> {sip} ({x},{y})')
    except (ValueError, OSError) as e:
        print(f'[远控] 鼠标事件失败：{e}')


def cmd_key(args):
    if len(args) < 2:
        print('[命令] 用法：key <学生IP> <vk> [press|down|up] [scan] [extended=0|1]')
        return
    sip = args[0]
    parts = args[1].split()
    try:
        virtual_key = int(parts[0], 0)
        action = parts[1].lower() if len(parts) > 1 else 'press'
        if action not in ('press', 'down', 'up'):
            raise ValueError('动作必须是 press/down/up')
        scan_code = int(parts[2], 0) if len(parts) > 2 else None
        extended = bool(int(parts[3], 0)) if len(parts) > 3 else False
        if action in ('press', 'down'):
            if not send_remote_key(sip, virtual_key, False, scan_code, extended):
                return
        if action == 'press':
            time.sleep(0.03)
        if action in ('press', 'up'):
            if not send_remote_key(sip, virtual_key, True, scan_code, extended):
                return
        print(f'[远控] key vk=0x{virtual_key:02X} {action} -> {sip}')
    except (ValueError, OSError) as e:
        print(f'[远控] 键盘事件失败：{e}')


def cmd_all():
    if not students:
        print('[命令] 当前无学生登录')
        return
    for sip in list(students.keys()):
        request_preview(sip)
        time.sleep(0.05)
    print(f'[命令] 已向 {len(students)} 个学生请求预览')


def cmd_debug(args):
    if not args or args[0].lower() not in ('on', 'off'):
        print(f'[命令] 用法：debug on/off（当前文件日志级别：{logging.getLevelName(FILE_LOG_LEVEL)}）')
        return
    if args[0].lower() == 'on':
        set_file_log_level(logging.DEBUG)
        print('[命令] 已开启 DEBUG 日志（文件会变大）')
    else:
        set_file_log_level(logging.INFO)
        print('[命令] 已关闭 DEBUG 日志，仅保留 INFO 及以上')



def command_loop():
    global running
    print('教师端已启动，输入 help 查看命令')
    while running:
        try:
            line = input('teacher> ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        parts = line.split(maxsplit=2)
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ('help', '?', 'h'):
            cmd_help()
        elif cmd in ('list', 'ls', 'students'):
            cmd_list()
        elif cmd == 'preview':
            cmd_preview(args)
        elif cmd == 'view_probe':
            cmd_view_probe(args)
        elif cmd in ('view', 'watch'):
            cmd_view(args)
        elif cmd in ('view_stop', 'unview'):
            if not args:
                print('[命令] 用法：view_stop <学生IP>')
            else:
                stop_remote_view(args[0])
                print(f'[观看] 已停止 {args[0]}')
        elif cmd in ('control', 'ctrl'):
            cmd_control(args)
        elif cmd in ('control_stop', 'ctrl_stop'):
            if not args:
                print('[命令] 用法：control_stop <学生IP>')
            else:
                stop_remote_control(args[0])
                print(f'[远控] 已停止 {args[0]}')
        elif cmd == 'mouse':
            cmd_mouse(args)
        elif cmd == 'key':
            cmd_key(args)
        elif cmd == 'all':
            cmd_all()
        elif cmd == 'debug':
            cmd_debug(args)
        elif cmd == 'msg':
            if len(args) < 2:
                print('[命令] 用法：msg <学生IP> <消息内容>')
            else:
                send_chat(args[0], args[1])
        elif cmd == 'info':
            cmd_info(args)
        elif cmd == 'ps':
            cmd_ps(args)
        elif cmd == 'wins':
            cmd_wins(args)
        elif cmd == 'kill':
            cmd_kill(args)
        elif cmd == 'closeapp':
            cmd_closeapp(args)
        elif cmd in ('openurl', 'open'):
            if len(args) < 2:
                print('[命令] 用法：openurl <学生IP> <网址|文件路径>')
            elif _check_student(args[0], 'openurl <学生IP> <网址|文件路径>'):
                send_open_url(args[0], args[1])
        elif cmd == 'run':
            if len(args) < 2:
                print('[命令] 用法：run <学生IP> <程序路径> [参数...] [show=0|1|2]（路径含空格用双引号）')
            elif _check_student(args[0], 'run <学生IP> <程序路径> [参数] [show]'):
                path, pargs, show = _parse_run_args(args[1])
                if not path:
                    print('[命令] 用法：run <学生IP> <程序路径> [参数...] [show=0|1|2]')
                else:
                    send_run_program(args[0], path, pargs, show)
        elif cmd in ('blackscreen', 'bs'):
            if len(args) < 1:
                print('[命令] 用法：blackscreen <学生IP> [lock=1|0] [提示文字]')
            else:
                lock, text = _parse_lock_text(args[1] if len(args) > 1 else '')
                send_blackscreen(args[0], lock_input=lock, timeout=10, text=text)
        elif cmd in ('bsperm', 'bsp'):
            if len(args) < 1:
                print('[命令] 用法：bsperm <学生IP> [lock=1|0] [提示文字]')
            else:
                lock, text = _parse_lock_text(args[1] if len(args) > 1 else '')
                send_blackscreen(args[0], lock_input=lock, timeout=0, text=text)
        elif cmd == 'unlock':
            if len(args) < 1:
                print('[命令] 用法：unlock <学生IP>')
            else:
                send_unlock(args[0])
        elif cmd == 'bsall':
            if not students:
                print('[命令] 当前无学生登录')
            else:
                lock, text = _parse_lock_text(args[0] if args else '')
                for sip in list(students.keys()):
                    send_blackscreen(sip, lock_input=lock, timeout=10, text=text)
                    time.sleep(0.05)
        elif cmd == 'unlock_all':
            if not students:
                print('[命令] 当前无学生登录')
            else:
                for sip in list(students.keys()):
                    send_unlock(sip)
                    time.sleep(0.05)
        elif cmd in ('shutdown', 'sd'):
            if len(args) < 1:
                print('[命令] 用法：shutdown <学生IP> [倒计时秒数] [提示文字]')
            else:
                delay, text = _parse_delay_text(args[1] if len(args) > 1 else '')
                send_shutdown(args[0], reboot=False, delay=delay,
                              force=(delay == 0), text=text)
        elif cmd in ('reboot', 'rb'):
            if len(args) < 1:
                print('[命令] 用法：reboot <学生IP> [倒计时秒数] [提示文字]')
            else:
                delay, text = _parse_delay_text(args[1] if len(args) > 1 else '')
                send_shutdown(args[0], reboot=True, delay=delay,
                              force=(delay == 0), text=text)
        elif cmd in ('exit', 'quit', 'q'):
            break
        else:
            print(f'[命令] 未知命令：{cmd}，输入 help 查看帮助')


# -------------------- 启动 --------------------

spawn_log_window()
logger.info('启动 4 个后台线程')
threading.Thread(target=broadcast, name='broadcast', daemon=True).start()
threading.Thread(target=session_anno, name='session_anno', daemon=True).start()
threading.Thread(target=session_recv, name='session_recv', daemon=True).start()
threading.Thread(target=main_recv, name='main_recv', daemon=True).start()

command_loop()

running = False
for sip in list(remote_views):
    stop_remote_view(sip, notify=False)
for sip in list(remote_controls):
    stop_remote_control(sip, notify=False)
logger.info('程序退出。students=%s, previews=%s', list(students.keys()), list(previews.keys()))
