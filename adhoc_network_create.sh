sudo ip link set wlp0s20f3 down
sudo iwconfig wlp0s20f3 mode ad-hoc
sudo iwconfig wlp0s20f3 channel 1
sudo iwconfig wlp0s20f3 essid 'MyNetwork'
sudo iwconfig wlp0s20f3 key 1234567890
sudo rfkill unblock all
sudo ip link set wlp0s20f3 up
sudo ip address add 169.254.96.15/16 dev wlp0s20f3