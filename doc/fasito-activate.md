## Prepare your system so faircoind can access the Fasito
 
```
sudo bash -l

cat >/etc/udev/rules.d/50-fasito.rules <<EOF
ATTRS{idVendor}=="16c0", ATTRS{idProduct}=="04[789]?", ENV{ID_MM_DEVICE_IGNORE}="1"
ATTRS{idVendor}=="16c0", ATTRS{idProduct}=="04[789]?", ENV{MTP_NO_PROBE}="1"
EOF

udevadm control --reload-rules

exit
```
 
Now plug in Fasito 
Check if device is there: `ls -l /dev/ttyACM*` 
(please post the output) 
 
Now we check if your user is in the dialout group: 
`groups | grep dialout --color` 
(please post the output) 
 
If there is no output we need to add your user to the group. 
 
`sudo usermod -a -G dialout UserName` 
 
replace **UserName** with your real Linux user name 
 
In case of problems: `minicom -D /dev/ttyACM0` 
 
`alias cli='/path/to/executable/faircoin-cli'` 
`cli getinfo` 
Now let's check if the wallet can access Fasito: 
`cli fasitocmd INFO` 
 
Check serial number:  
Protection status:  
 
## Initialise Fasito at the CVN-opertaors site
(Choose a uniqe hex CVN id which is used to identify the CVN in the network. In the next command replace the ID 0x12345678 with the chosen ID.)

In the next command replace the word `PIN` with the actual PIN I sent you.  
Also: **Do not post the result of the following command**  
 
`cli fasitoinitkey PIN 0 0x12345678` 
 
The result of the previous command is the recovery information. Keep it secret and in a safe place. It is used to restore your CVN in case it got stolen or damaged. 
 
`cli fasitologin fasito PIN` 
 
Please email me the output of the following command:  
`cli fasitocmd "KYPROOF 0"`  

Finally logout from Fasito:  
`cli fasitologout`  
