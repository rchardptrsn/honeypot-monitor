sudo kill -9 `sudo lsof -t -i:1025`
echo "Process killed on port 1025"
nohup python3 honeypotMonitor.py </dev/null >honeypot.log 2>&1 &
echo "Honeypot started"
