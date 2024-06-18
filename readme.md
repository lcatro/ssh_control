
## SSH Control

SSH群控工具,用来批量管理服务器/跑节点

## Install

```

    pip install -r ./requirement

```

## Run

单IP操作

```

python .\ssh_cli.py run -v --show_timeout_ip --ip=  --username=ubuntu --password= --thread=500 "curl -o apphub-linux-amd64.tar.gz https://assets.coreservice.io/public/package/60/app-market-gaga-pro/1.0.4/app-market-gaga-pro-1_0_4.tar.gz && tar -zxf apphub-linux-amd64.tar.gz && rm -f apphub-linux-amd64.tar.gz && cd ./apphub-linux-amd64 && sudo ./apphub service remove && sudo ./apphub service install && sudo ./apphub service start && sudo ./apps/gaganode/gaganode config set --token=5e763 && sudo ./apphub restart"

```

批量IP操作

```

python .\ssh_cli.py run -v --show_timeout_ip --ip=.\avail_ip_all.txt  --username=ubuntu --password= --thread=500 "cd ./apphub-linux-amd64 && ./apphub status" 

```
