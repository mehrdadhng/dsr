sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client" -h "client" --ip="10.89.0.2" --mac-address="00:00:00:00:00:02"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client2" -h "client2" --ip="10.89.0.7" --mac-address="00:00:00:00:00:07"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client3" -h "client3" --ip="10.89.0.8" --mac-address="00:00:00:00:00:08"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client4" -h "client4" --ip="10.89.0.9" --mac-address="00:00:00:00:00:09"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client5" -h "client5" --ip="10.89.0.10" --mac-address="00:00:00:00:00:0a"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client6" -h "client6" --ip="10.89.0.11" --mac-address="00:00:00:00:00:0b"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client7" -h "client7" --ip="10.89.0.12" --mac-address="00:00:00:00:00:0c"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client8" -h "client8" --ip="10.89.0.13" --mac-address="00:00:00:00:00:0d"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client9" -h "client9" --ip="10.89.0.14" --mac-address="00:00:00:00:00:0e"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client10" -h "client10" --ip="10.89.0.15" --mac-address="00:00:00:00:00:0f"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client11" -h "client11" --ip="10.89.0.16" --mac-address="00:00:00:00:00:10"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client12" -h "client12" --ip="10.89.0.17" --mac-address="00:00:00:00:00:11"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client13" -h "client13" --ip="10.89.0.18" --mac-address="00:00:00:00:00:12"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client14" -h "client14" --ip="10.89.0.19" --mac-address="00:00:00:00:00:13"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client15" -h "client15" --ip="10.89.0.20" --mac-address="00:00:00:00:00:14"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client16" -h "client16" --ip="10.89.0.21" --mac-address="00:00:00:00:00:15"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client17" -h "client17" --ip="10.89.0.22" --mac-address="00:00:00:00:00:16"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client18" -h "client18" --ip="10.89.0.23" --mac-address="00:00:00:00:00:17"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client19" -h "client19" --ip="10.89.0.24" --mac-address="00:00:00:00:00:18"  --env TERM=xterm-color ubuntu:ebpf
sudo docker run -dit --privileged -v /lib/modules/:/lib/modules:ro --network=lb_ebpf --name "client20" -h "client20" --ip="10.89.0.25" --mac-address="00:00:00:00:00:19"  --env TERM=xterm-color ubuntu:ebpf


docker exec -d client python3 /xdp/udpClient.py
docker exec -d client2 python3 /xdp/udpClient.py
docker exec -d client3 python3 /xdp/udpClient.py
docker exec -d client4 python3 /xdp/udpClient.py
docker exec -d client5 python3 /xdp/udpClient.py
docker exec -d client6 python3 /xdp/udpClient.py
docker exec -d client7 python3 /xdp/udpClient.py
docker exec -d client8 python3 /xdp/udpClient.py
docker exec -d client9 python3 /xdp/udpClient.py
docker exec -d client10 python3 /xdp/udpClient.py
docker exec -d client11 python3 /xdp/udpClient.py
docker exec -d client12 python3 /xdp/udpClient.py
docker exec -d client13 python3 /xdp/udpClient.py
docker exec -d client14 python3 /xdp/udpClient.py
docker exec -d client15 python3 /xdp/udpClient.py
docker exec -d client16 python3 /xdp/udpClient.py
docker exec -d client17 python3 /xdp/udpClient.py
docker exec -d client18 python3 /xdp/udpClient.py
docker exec -d client19 python3 /xdp/udpClient.py
docker exec -d client20 python3 /xdp/udpClient.py