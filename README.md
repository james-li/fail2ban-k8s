# fail2ban-k8s
run fail2ban on k8s

## build&deploy
```bash
#docker build -t fail2ban:1.0.0 .
#kubectl -n vpn apply -f fail2ban-deploy.yml 
```
change namespace to any other name if you like. Don't forget modify deploy yaml file.

